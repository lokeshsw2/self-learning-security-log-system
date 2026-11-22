"""The learning service: consume the unparsed topic, group lines by format, and let the agents learn
new formats in bounded, budgeted cycles. Code runs the loop; agents are called per work item.

  read a batch  ->  engine.process (detect, group, queue new work; state written in one transaction)
                ->  commit the Kafka offsets (only after the state is saved: at-least-once)
  every interval, if new work is queued and learning is on:
                ->  harness.learn (agents + self-audit + fix round) within the cycle and day budgets
                ->  if the rules changed: on_rules_changed (phase 2 compiles and deploys Logstash pipelines)

The service itself writes no parsed events: in production the deployed Logstash pipelines parse the
topic. It only learns, and keeps what it learned in its store (SQLite here, MySQL in production).
"""
from __future__ import annotations

import json
import signal
import threading
import time
import types

from ..reader import Record, decode, looks_binary
from .config import ServiceConfig


class KafkaConsumer:
    """Thin wrapper over confluent_kafka.Consumer: batches of (topic, partition, offset, bytes, headers)."""

    def __init__(self, cfg: ServiceConfig):
        from confluent_kafka import Consumer
        c = cfg.kafka
        conf = {"bootstrap.servers": c.bootstrap, "group.id": c.group_id, "enable.auto.commit": False,
                "auto.offset.reset": "earliest", **c.extra}
        self.consumer = Consumer(conf)
        self.consumer.subscribe([c.unparsed_topic])
        self.timeout = c.poll_timeout_s
        self._last: list = []

    def poll(self, max_messages: int) -> list:
        msgs = self.consumer.consume(num_messages=max_messages, timeout=self.timeout)
        self._last = [m for m in msgs if m.error() is None]
        return [(m.topic(), m.partition(), m.offset(), m.value() or b"", dict(m.headers() or []))
                for m in self._last]

    def commit(self) -> None:
        if self._last:
            self.consumer.commit(asynchronous=False)

    def lag(self) -> dict:
        out = {}
        for tp in self.consumer.assignment():
            lo, hi = self.consumer.get_watermark_offsets(tp, timeout=2.0)
            pos = self.consumer.position([tp])[0].offset
            out[f"{tp.topic}:{tp.partition}"] = max(0, hi - (pos if pos >= 0 else lo))
        return out

    def close(self) -> None:
        self.consumer.close()


def ensure_topics(cfg: ServiceConfig) -> list:
    """Create the topics for local testing (never in production: create_topics is off there)."""
    from confluent_kafka.admin import AdminClient, NewTopic
    c = cfg.kafka
    admin = AdminClient({"bootstrap.servers": c.bootstrap, **c.extra})
    have = set(admin.list_topics(timeout=10).topics)
    new = [NewTopic(t, num_partitions=c.partitions, replication_factor=1)
           for t in (c.unparsed_topic, c.parsed_topic) if t not in have]
    for t, f in (admin.create_topics(new).items() if new else []):
        f.result()
    return [t.topic for t in new]


def load_builtin(eng) -> tuple:
    """Load the built-in rules into the store on every start: idempotent (only changed bodies are saved),
    so a new database gets them and an upgraded service brings its updated ones."""
    import os
    from .. import registry
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                        "registry", "builtin.json")
    res = registry.import_rules(eng.store, path)
    eng.reload()
    return res


class LearnerService:
    def __init__(self, cfg: ServiceConfig, consumer=None, model_client=None, clock=time.time):
        from ..cli import open_engine
        self.cfg = cfg
        self.eng = open_engine(types.SimpleNamespace(db=cfg.sqlite_path(), settings=cfg.engine_settings))
        self.builtin = load_builtin(self.eng)   # the fixed harness rules (detection, masks, base mappings)
        self.consumer = consumer
        self.model_client = model_client       # tests pass a fake; None = the Anthropic client
        self.clock = clock
        self.stop = threading.Event()
        self.lock = threading.RLock()
        self.on_rules_changed = None           # phase 2: compile and deploy Logstash pipelines
        self.stats = {"batches": 0, "records": 0, "parsed": 0, "pending": 0, "binary": 0, "quarantined": 0,
                      "dlq": 0, "learn_cycles": 0, "started": clock()}

    # ---------------------------------------------------------------- intake
    def step(self) -> dict:
        """Read one batch, process it, then commit the offsets. Returns the batch stats."""
        msgs = self.consumer.poll(self.cfg.kafka.batch_max)
        if not msgs:
            return {"records": 0}
        recs, offsets = [], {}
        for topic, part, off, value, headers in msgs:
            stream = f"kafka:{topic}:{part}"
            label = headers.get("source")
            label = label.decode("utf-8", "replace") if isinstance(label, bytes) else label
            if looks_binary(value):
                recs.append(Record(stream, off, blob=value, label=label))
            else:
                text, flags = decode(value)
                recs.append(Record(stream, off, text=text.rstrip("\r\n"), flags=flags, label=label))
            offsets[f"offset:{stream}"] = off + 1
        with self.lock:
            st = self.eng.process(recs, offsets)     # offsets saved in the same transaction as the batch
        self.consumer.commit()                        # then acknowledged to Kafka
        self.stats["batches"] += 1
        for k in ("records", "parsed", "pending", "binary", "quarantined", "dlq"):
            self.stats[k] += st.get(k, 0)
        return st

    # ---------------------------------------------------------------- learning
    def _spent_today(self) -> float:
        return float(self.eng.store.get_state(f"learn_spend:{time.strftime('%Y-%m-%d', time.gmtime(self.clock()))}", 0.0))

    def _add_spend(self, usd: float) -> None:
        key = f"learn_spend:{time.strftime('%Y-%m-%d', time.gmtime(self.clock()))}"
        self.eng.store.set_state(key, round(self._spent_today() + usd, 6))

    def open_work(self) -> dict:
        from ..harness import ORDER, QUEUES
        rows = self.eng.store.q("SELECT name, COUNT(*) n FROM queue WHERE status='open' GROUP BY name")
        n = {r["name"]: r["n"] for r in rows}
        return {role: n.get(QUEUES[role], 0) for role in ORDER} | {"longtail": n.get("longtail", 0)}

    def learning_due(self) -> str | None:
        """Why a learning cycle may not run now, or None if it may."""
        lc = self.cfg.learning
        if not lc.enabled:
            return "learning is off"
        last = float(self.eng.store.get_state("learn_last", 0.0))
        if self.clock() - last < lc.interval_s:
            return "interval not reached"
        waiting = any(self.open_work().values()) or self.eng.store.q(
            "SELECT 1 FROM groups WHERE status='new' AND merged_into IS NULL AND count > 0 LIMIT 1")
        if not waiting:                          # queued work, or lines of groups no rule reads yet
            return "nothing waiting"
        left = lc.budget_usd_per_day - self._spent_today()
        if left <= 0.01:
            return "daily budget used"
        return None

    def learn_cycle(self) -> dict:
        """One bounded learning cycle: agents, self-audit, fix round, within the cycle and day budgets."""
        from ..harness import ORDER, Harness, learn
        lc = self.cfg.learning
        budget = min(lc.budget_usd_per_cycle, lc.budget_usd_per_day - self._spent_today())
        gen_before = int(self.eng.store.get_state("registry_generation", 0))
        roles = ORDER + ["longtail"] if lc.roles == "all" else list(lc.roles)
        with self.lock:
            self.eng.finalize()                       # groups below the parser threshold enter the long tail
        h = Harness(self.eng, client=self.model_client, model=lc.model, budget_usd=budget, lock=self.lock)
        t0 = self.clock()
        report = learn(h, roles, lc.limit, lc.model, fix_rounds=lc.fix_rounds)
        self._add_spend(h.spent_usd)
        self.eng.store.set_state("learn_last", self.clock())
        gen_after = int(self.eng.store.get_state("registry_generation", 0))
        entry = {"at": t0, "seconds": round(self.clock() - t0, 1), "spent_usd": round(h.spent_usd, 4),
                 "budget_usd": round(budget, 4), "rules_changed": gen_after != gen_before,
                 "summary": json.loads(json.dumps(report, default=str))}
        hist = (self.eng.store.get_state("learn_history", []) or [])[-49:] + [entry]
        self.eng.store.set_state("learn_history", hist)
        self.stats["learn_cycles"] += 1
        if gen_after != gen_before and self.on_rules_changed:
            self.on_rules_changed(gen_after)
        return entry

    # ---------------------------------------------------------------- loop
    def run(self, max_batches: int | None = None, idle_exit_s: float | None = None) -> dict:
        """Consume until stopped (or `max_batches`, or `idle_exit_s` seconds with no messages: for tests)."""
        idle_since = None
        n = 0
        while not self.stop.is_set():
            st = self.step()
            n += 1 if st.get("records") else 0
            if st.get("records"):
                idle_since = None
            else:
                idle_since = idle_since or self.clock()
                if idle_exit_s is not None and self.clock() - idle_since >= idle_exit_s:
                    break
            if self.learning_due() is None:
                self.learn_cycle()
            if max_batches is not None and n >= max_batches:
                break
        return self.status()

    def status(self) -> dict:
        lag = {}
        if self.consumer is not None and hasattr(self.consumer, "lag"):
            try:
                lag = self.consumer.lag()
            except Exception as exc:          # status must never fail the service
                lag = {"error": str(exc)[:200]}
        return {**self.stats, "lag": lag, "open_work": self.open_work(),
                "spent_today_usd": self._spent_today(), "learning": self.learning_due() or "due",
                "rules_generation": int(self.eng.store.get_state("registry_generation", 0)),
                "last_learn": (self.eng.store.get_state("learn_history", []) or [None])[-1]}

    def install_signal_handlers(self) -> None:
        for s in (signal.SIGINT, signal.SIGTERM):
            signal.signal(s, lambda *_: self.stop.set())
