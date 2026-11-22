"""The learning service: consume the unparsed topic, group lines by format, and let the agents learn
new formats in bounded, budgeted cycles. Code runs the loop; agents are called per work item.

  read a batch  ->  drop messages already processed (redelivery after a crash or rebalance)
                ->  engine.process (detect, group, queue new work; offsets saved in the same transaction)
                ->  commit exactly those offsets to Kafka (at-least-once; a failed commit is harmless)
  when the topic has been idle for `idle_flush_s`: small groups still without a rule go to the long tail
  every interval, if work is queued and learning is on: a learning cycle in a background thread, so the
  consumer keeps polling (Kafka evicts a consumer that stops polling for max.poll.interval.ms)
                ->  harness.learn (agents + self-audit + fix round) within the cycle and day budgets
                ->  spend and time recorded even when the cycle fails; failures back off
                ->  if the rules changed: on_rules_changed (phase 2 compiles and deploys Logstash pipelines)

The service itself writes no parsed events: in production the deployed Logstash pipelines parse the
topic. It only learns, and keeps what it learned in its store (SQLite here, MySQL in production).
"""
from __future__ import annotations

import json
import logging
import signal
import threading
import time
import traceback
import types

from ..reader import Record, decode, looks_binary
from .config import ServiceConfig

log = logging.getLogger("logparser.service")


class KafkaConsumer:
    """Thin wrapper over confluent_kafka.Consumer: batches of (topic, partition, offset, bytes, headers)."""

    def __init__(self, cfg: ServiceConfig, on_revoke=None):
        from confluent_kafka import Consumer
        c = cfg.kafka
        conf = {"bootstrap.servers": c.bootstrap, "group.id": c.group_id, "enable.auto.commit": False,
                "auto.offset.reset": "earliest", **c.client_extra()}
        self.consumer = Consumer(conf)
        self._on_revoke = on_revoke
        self.consumer.subscribe([c.unparsed_topic], on_revoke=self._revoked)
        self.timeout = c.poll_timeout_s

    def _revoked(self, consumer, partitions) -> None:
        if self._on_revoke:
            self._on_revoke(partitions)

    def poll(self, max_messages: int) -> list:
        from confluent_kafka import KafkaError, KafkaException
        out = []
        for m in self.consumer.consume(num_messages=max_messages, timeout=self.timeout):
            err = m.error()
            if err is None:
                out.append((m.topic(), m.partition(), m.offset(), m.value() or b"", dict(m.headers() or [])))
            elif err.code() == KafkaError._PARTITION_EOF:
                continue
            elif err.fatal():
                raise KafkaException(err)
            else:
                log.warning("kafka: %s", err)
        return out

    def commit(self, offsets: dict) -> None:
        """Commit exactly the next offsets of what was processed: {(topic, partition): next_offset}."""
        from confluent_kafka import TopicPartition
        if offsets:
            self.consumer.commit(offsets=[TopicPartition(t, p, o) for (t, p), o in offsets.items()],
                                 asynchronous=False)

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
    admin = AdminClient({"bootstrap.servers": c.bootstrap, **c.client_extra()})
    have = set(admin.list_topics(timeout=10).topics)
    new = [NewTopic(t, num_partitions=c.partitions, replication_factor=1)
           for t in (c.unparsed_topic, c.parsed_topic, c.replay_topic, c.failed_topic) if t and t not in have]
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
        self.cfg = cfg
        self.eng = self._open_engine()
        self.builtin = load_builtin(self.eng)   # the fixed harness rules (detection, masks, base mappings)
        self.consumer = consumer
        self.model_client = model_client       # tests pass a fake; None = the Anthropic client
        self.clock = clock
        self.stop = threading.Event()
        self.lock = threading.RLock()          # the engine and its store are shared with the learning thread
        self.on_rules_changed = None           # phase 2: compile and deploy Logstash pipelines
        self.learner: threading.Thread | None = None
        self.idle_since: float | None = None
        self.flushed_idle = False
        self.stats = {"batches": 0, "records": 0, "parsed": 0, "pending": 0, "binary": 0, "quarantined": 0,
                      "dlq": 0, "duplicates_skipped": 0, "empty_skipped": 0, "truncated": 0,
                      "commit_errors": 0, "learn_cycles": 0, "learn_errors": 0, "started": clock()}

    def _open_engine(self):
        from ..cli import open_engine
        return open_engine(types.SimpleNamespace(db=self.cfg.sqlite_path(), settings=self.cfg.engine_settings))

    # ---------------------------------------------------------------- intake
    def _done_offset(self, stream: str) -> int:
        """Next offset not yet processed for a partition, from the store (survives crashes and rebalances)."""
        with self.lock:
            return int(self.eng.store.get_state(f"offset:{stream}", -1))

    def step(self) -> dict:
        """Read one batch, skip what was already processed, process the rest, then commit its offsets."""
        msgs = self.consumer.poll(self.cfg.kafka.batch_max)
        if not msgs:
            return {"records": 0}
        maxlen = self.eng.settings.max_line_len
        recs, offsets, commit = [], {}, {}
        done: dict = {}
        for topic, part, off, value, headers in msgs:
            stream = f"kafka:{topic}:{part}"
            if stream not in done:
                done[stream] = self._done_offset(stream)
            commit[(topic, part)] = max(commit.get((topic, part), 0), off + 1)
            if off < done[stream]:
                self.stats["duplicates_skipped"] += 1     # redelivered: processed before the last commit
                continue
            offsets[f"offset:{stream}"] = off + 1
            if not value.strip():
                self.stats["empty_skipped"] += 1
                continue
            label = headers.get("source")
            label = label.decode("utf-8", "replace") if isinstance(label, bytes) else label
            if looks_binary(value):
                recs.append(Record(stream, off, blob=value, label=label))
                continue
            text, flags = decode(value)
            text = text.rstrip("\r\n")
            if len(text) > maxlen:
                text, flags = text[:maxlen], flags + ["truncated"]
                self.stats["truncated"] += 1
            recs.append(Record(stream, off, text=text, flags=flags, label=label))
        st = {"records": 0}
        if offsets:
            with self.lock:
                try:
                    st = self.eng.process(recs, offsets)  # offsets saved in the same transaction as the batch
                except Exception:
                    self.eng = self._open_engine()        # in-memory state may be half updated: reload it
                    raise
        try:
            self.consumer.commit(commit)                  # then acknowledged to Kafka
        except Exception as exc:                          # e.g. a rebalance: the batch comes again, and is skipped
            self.stats["commit_errors"] += 1
            log.warning("commit failed (redelivery will be skipped): %s", exc)
        self.stats["batches"] += 1
        for k in ("records", "parsed", "pending", "binary", "quarantined", "dlq"):
            self.stats[k] += st.get(k, 0)
        return st

    def on_revoke(self, partitions) -> None:
        """Before partitions move to another consumer: nothing to do beyond what step() committed; stored
        offsets make any redelivery to the next owner harmless (it skips them only if it shares this store)."""
        log.info("partitions revoked: %s", [f"{p.topic}:{p.partition}" for p in partitions])

    # ---------------------------------------------------------------- learning
    def _day(self) -> str:
        return time.strftime("%Y-%m-%d", time.gmtime(self.clock()))

    def _spent_today(self) -> float:
        with self.lock:
            return float(self.eng.store.get_state(f"learn_spend:{self._day()}", 0.0))

    def _add_spend(self, usd: float) -> None:
        with self.lock:
            self.eng.store.set_state(f"learn_spend:{self._day()}", round(self._spent_today() + usd, 6))

    def open_work(self) -> dict:
        from ..harness import ORDER, QUEUES
        with self.lock:      # the store is shared with the learning thread: one user at a time
            rows = self.eng.store.q("SELECT name, COUNT(*) n FROM queue WHERE status='open' GROUP BY name")
        n = {r["name"]: r["n"] for r in rows}
        return {role: n.get(QUEUES[role], 0) for role in ORDER} | {"longtail": n.get("longtail", 0)}

    def learning_due(self) -> str | None:
        """Why a learning cycle may not start now, or None if it may."""
        lc = self.cfg.learning
        if not lc.enabled:
            return "learning is off"
        if self.learner is not None and self.learner.is_alive():
            return "a cycle is running"
        with self.lock:
            last = float(self.eng.store.get_state("learn_last", 0.0))
            failures = int(self.eng.store.get_state("learn_failures", 0))
        wait = lc.interval_s * (2 ** min(failures, 5))  # back off after failed cycles
        if self.clock() - last < wait:
            return "interval not reached"
        if not any(self.open_work().values()):
            return "nothing waiting"
        if lc.budget_usd_per_day - self._spent_today() <= 0.01:
            return "daily budget used"
        return None

    def learn_cycle(self) -> dict:
        """One bounded learning cycle: agents, self-audit, fix round, within the cycle and day budgets.
        Spend, time and the outcome are recorded even when the cycle fails."""
        from ..harness import ORDER, Harness, learn
        lc = self.cfg.learning
        budget = max(0.0, min(lc.budget_usd_per_cycle, lc.budget_usd_per_day - self._spent_today()))
        with self.lock:
            gen_before = int(self.eng.store.get_state("registry_generation", 0))
        if lc.roles != "all":
            roles = list(lc.roles)
        elif self.cfg.logstash.variant == "direct":     # Variant B: agents write the Logstash filters themselves
            roles = ["detection", "source-naming", "grouping-repair", "ls-direct"]
        else:
            roles = ORDER + ["longtail"]
        t0 = self.clock()
        h = None
        entry = {"at": t0, "budget_usd": round(budget, 4)}
        try:
            h = Harness(self.eng, client=self.model_client, model=lc.model, budget_usd=budget, lock=self.lock,
                        stop=self.stop)
            report = learn(h, roles, lc.limit, lc.model, fix_rounds=lc.fix_rounds)
            entry["summary"] = json.loads(json.dumps(report, default=str))
            with self.lock:
                self.eng.store.set_state("learn_failures", 0)
        except Exception as exc:
            entry["error"] = f"{type(exc).__name__}: {exc}"[:500]
            self.stats["learn_errors"] += 1
            with self.lock:
                self.eng.store.set_state("learn_failures", int(self.eng.store.get_state("learn_failures", 0)) + 1)
            log.error("learning cycle failed: %s\n%s", exc, traceback.format_exc())
        finally:
            spent = h.spent_usd if h is not None else 0.0
            self._add_spend(spent)
            with self.lock:
                gen_after = int(self.eng.store.get_state("registry_generation", 0))
            entry.update(seconds=round(self.clock() - t0, 1), spent_usd=round(spent, 4),
                         rules_changed=gen_after != gen_before)
            with self.lock:
                self.eng.store.set_state("learn_last", self.clock())
                hist = (self.eng.store.get_state("learn_history", []) or [])[-49:] + [entry]
                self.eng.store.set_state("learn_history", hist)
            self.stats["learn_cycles"] += 1
        if entry["rules_changed"] and self.on_rules_changed:
            self.on_rules_changed(gen_after)
        return entry

    def start_learning(self) -> threading.Thread:
        self.learner = threading.Thread(target=self.learn_cycle, name="learning-cycle", daemon=True)
        self.learner.start()
        return self.learner

    def idle_flush(self) -> bool:
        """When nothing has arrived for `idle_flush_s`, groups still below the parser threshold go to the long
        tail (end-of-input semantics, but only while the stream is quiet, never mid-burst)."""
        if self.idle_since is None or self.flushed_idle:
            return False
        if self.clock() - self.idle_since < self.cfg.kafka.idle_flush_s:
            return False
        with self.lock:
            self.eng.finalize()
        self.flushed_idle = True
        return True

    # ---------------------------------------------------------------- loop
    def run(self, max_batches: int | None = None, idle_exit_s: float | None = None) -> dict:
        """Consume until stopped (or `max_batches`, or `idle_exit_s` seconds with no messages: for tests).
        Learning runs in a background thread; the loop keeps polling while it runs."""
        n = 0
        while not self.stop.is_set():
            st = self.step()
            if st.get("records"):
                n += 1
                self.idle_since, self.flushed_idle = None, False
            else:
                self.idle_since = self.idle_since or self.clock()
                self.idle_flush()
                self.stop.wait(0.05)                  # a real consumer blocks in poll; do not spin on the lock
            if self.learning_due() is None:          # before any exit check: a flush may have queued work
                self.start_learning()
            busy = self.learner is not None and self.learner.is_alive()
            if not st.get("records") and idle_exit_s is not None and not busy and \
                    self.clock() - self.idle_since >= idle_exit_s:
                break
            if max_batches is not None and n >= max_batches:
                break
        if self.learner is not None:
            self.learner.join(timeout=60)
        return self.status()

    def status(self) -> dict:
        lag = {}
        if self.consumer is not None and hasattr(self.consumer, "lag"):
            try:
                lag = self.consumer.lag()
            except Exception as exc:          # status must never fail the service
                lag = {"error": str(exc)[:200]}
        with self.lock:
            gen = int(self.eng.store.get_state("registry_generation", 0))
            last = (self.eng.store.get_state("learn_history", []) or [None])[-1]
            deploy = (self.eng.store.get_state("deploy_history", []) or [None])[-1]
        return {**self.stats, "lag": lag, "open_work": self.open_work(),
                "spent_today_usd": self._spent_today(), "learning": self.learning_due() or "due",
                "rules_generation": gen, "last_learn": last, "last_deploy": deploy, "config": self.cfg.redacted()}

    def install_signal_handlers(self) -> None:
        for s in (signal.SIGINT, signal.SIGTERM):
            signal.signal(s, lambda *_: self.stop.set())
