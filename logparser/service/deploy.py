"""Variant A deployment: compile the learned rules to Logstash, verify them, swap them in, replay.

  snapshot the store (SQLite backup: consistent, includes the write-ahead log)
  -> compile every group; run ONE throwaway Logstash on stored samples; keep only the groups whose
     events equal the engine's, line for line (scripts/ls_verify.py, repeated until nothing is excluded)
  -> write the verified set with the Kafka input (unparsed + replay topics, from the latest offset) and the
     Kafka sink (parsed topic) into a staging directory, then move it into the live directory file by file
     (pipelines.yml last); Logstash watches it (config.reload.automatic) and reloads
  -> re-send the kept lines of groups deployed for the first time to the replay topic: Logstash only reads
     new lines, so lines that arrived before their format was deployed reach it this way

Bounds: only lines the learner kept (retain_unparsed / retain_parsed per signature) can be replayed. A line
that arrives while Logstash reloads may be parsed live and replayed once (a small duplicate window).
"""
from __future__ import annotations

import collections
import importlib.util
import json
import os
import shutil
import sqlite3
import time

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _ls_verify():
    spec = importlib.util.spec_from_file_location("ls_verify", os.path.join(ROOT, "scripts", "ls_verify.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def snapshot(db: str, dst: str) -> str:
    for ext in ("", "-wal", "-shm"):
        if os.path.exists(dst + ext):
            os.remove(dst + ext)
    with sqlite3.connect(db) as src, sqlite3.connect(dst) as out:
        src.backup(out)
    return dst


def swap_in(staging: str, live: str) -> list:
    """Move the files of a written set from staging into the live directory. Paths inside the files point
    at staging and are rewritten. Pipelines first, pipelines.yml last; stale pipelines removed after it."""
    os.makedirs(live, exist_ok=True)
    staging, live = os.path.abspath(staging), os.path.abspath(live)
    names = sorted(os.listdir(staging), key=lambda n: n == "pipelines.yml")
    moved = []
    for n in names:
        src = os.path.join(staging, n)
        if os.path.isdir(src):
            continue
        with open(src, "rb") as fh:
            data = fh.read().replace(staging.encode(), live.encode())
        tmp = os.path.join(live, f".{n}.tmp")
        with open(tmp, "wb") as fh:
            fh.write(data)
        os.replace(tmp, os.path.join(live, n))
        moved.append(n)
    keep = set(moved)
    for n in os.listdir(live):
        if n.endswith(".conf") and n not in keep or (n.startswith("tables_") and n.endswith(".json") and n not in keep):
            os.remove(os.path.join(live, n))
    shutil.rmtree(staging, ignore_errors=True)
    return moved


class Deployer:
    def __init__(self, svc, producer=None):
        self.svc = svc
        self.cfg = svc.cfg
        self._producer = producer

    @property
    def producer(self):
        if self._producer is None:
            from confluent_kafka import Producer
            self._producer = Producer({"bootstrap.servers": self.cfg.kafka.bootstrap, "linger.ms": 50,
                                       **self.cfg.kafka.client_extra()})
        return self._producer

    def verify(self, work: str) -> tuple:
        """Compile, run a throwaway Logstash on stored samples, exclude disagreeing groups until stable."""
        if self.cfg.logstash.variant == "direct":
            return self.verify_direct(work)
        lv = _ls_verify()
        from .. import logstash as L
        db = self._snapshot(work)
        eng = lv.open_engine(db)
        lines = lv.build_lines(eng, db, self.cfg.logstash.verify_per_group, 0,
                               base_events=self.cfg.logstash.base_fallback)
        comp = L.Compiler(eng, base_fallback=self.cfg.logstash.base_fallback)
        include, history, causes = None, [], {}
        gen = used = None
        for it in range(1, self.cfg.logstash.verify_max_iter + 1):
            gen = comp.compile(include)
            used = {gid for gid, leaf in comp.leaves.items() if leaf.included}
            if not used:
                break
            events, timing = lv.run_logstash(gen, lines, work, ROOT)
            verdicts = lv.judge(lines, events, used)
            bad = lv.exclusions(verdicts)
            for gid, cause in bad.items():
                causes.setdefault(gid, cause)
            history.append({"pass": it, "groups": len(used), "timing": timing,
                            "verdicts": dict(collections.Counter(v["verdict"] for v in verdicts))})
            newly = set(bad) & used
            if not newly:
                break
            include = used - newly
        else:
            gen, used = self._drop_last(comp, include, used, history)
        try:
            eng.store.close()
        except Exception:
            pass
        return gen, used or set(), history, causes, len(lines)

    def _snapshot(self, work: str) -> str:
        """A consistent SQLite copy of the store for the verification run (MySQL: every table exported)."""
        dst = os.path.join(work, "engine.db")
        if self.cfg.is_mysql():
            from ..store_mysql import MySQLStore
            st = MySQLStore(self.cfg.store_url())
            try:
                return st.export_sqlite(dst)
            finally:
                st.close()
        return snapshot(self.cfg.sqlite_path(), dst)

    @staticmethod
    def _drop_last(comp, include, used, history) -> tuple:
        """The last allowed pass still found failing groups: leave them out (the smaller set is not run again)."""
        if include is None or include == used:
            return comp.compile(include) if include is not None else None, used
        gen = comp.compile(include)
        used = {gid for gid, leaf in comp.leaves.items() if leaf.included}
        if history:
            history[-1]["final_set_not_rerun"] = True
        return gen, used

    def verify_direct(self, work: str) -> tuple:
        """Variant B: compile the agents' filters, run them on stored lines of every group, keep a group only
        if each of its lines comes back as a passing event of that group and its filter takes no other lines."""
        lv = _ls_verify()
        from .. import logstash as L, lsdirect
        db = self._snapshot(work)
        eng = lv.open_engine(db)
        comp = L.Compiler(eng, direct=True)
        include, history, causes = None, [], {}
        gen = used = None
        for it in range(1, self.cfg.logstash.verify_max_iter + 1):
            gen = comp.compile(include)
            used = {gid for gid, leaf in comp.leaves.items() if leaf.included}
            if not used:
                break
            lines = lsdirect.verify_lines(eng, used, self.cfg.logstash.verify_per_group)
            events, timing = lv.run_logstash(gen, [{"id": l["id"], "raw": l["raw"]} for l in lines], work, ROOT)
            res = lsdirect.verify_judge(eng, lines, events, used, int(lv.NOW * 1000))
            for gid, cause in res["exclude"].items():
                causes.setdefault(gid, cause)
            history.append({"pass": it, "groups": len(used), "lines": len(lines), "timing": timing,
                            "verdicts": res["counts"]})
            newly = set(res["exclude"]) & used
            if not newly:
                break
            include = used - newly
        else:
            gen, used = self._drop_last(comp, include, used, history)
        n_lines = history[-1]["lines"] if history else 0
        try:
            eng.store.close()
        except Exception:
            pass
        return gen, used or set(), history, causes, n_lines

    def deploy(self, generation: int | None = None) -> dict:
        from .. import logstash as L
        t0 = time.time()
        live = os.path.abspath(self.cfg.logstash.config_dir)
        work = os.path.abspath(os.path.join(live, os.pardir, "verify"))
        os.makedirs(work, exist_ok=True)
        gen, used, history, causes, n_lines = self.verify(work)
        if gen is None or not used:
            entry = {"at": t0, "generation": generation, "groups": 0, "note": "nothing verified to deploy",
                     "history": history}
            self._record(entry)
            return entry
        k = self.cfg.kafka
        io = L.kafka_io(k.bootstrap, [k.unparsed_topic, k.replay_topic], k.logstash_group, k.parsed_topic, ROOT,
                        extra=k.client_extra(), failed_topic=k.failed_topic or None)
        staging = live + ".next"
        shutil.rmtree(staging, ignore_errors=True)
        L.write_set(gen, staging, root=ROOT, io=io, workers=self.cfg.logstash.workers,
                    heap=self.cfg.logstash.heap)
        swap_in(staging, live)
        store = self.svc.eng.store
        with self.svc.lock:
            before = set(store.get_state("deployed_groups", []) or [])
        new = sorted(used - before)
        sent = self.replay(new)
        with self.svc.lock:
            store.set_state("deployed_groups", sorted(used))
        entry = {"at": t0, "seconds": round(time.time() - t0, 1), "generation": generation, "groups": len(used),
                 "new_groups": len(new), "excluded": len(causes), "replayed_lines": sent,
                 "verify_lines": n_lines, "passes": history, "excluded_causes": dict(list(causes.items())[:20])}
        self._record(entry)
        return entry

    def replay(self, gids: list) -> int:
        """Send the kept lines of newly deployed groups to the replay topic (Logstash reads it too)."""
        topic = self.cfg.kafka.replay_topic
        n = 0
        for gid in gids:
            with self.svc.lock:
                rows = self.svc.eng.store.raw_by_signature(gid, 100000)
            for r in rows:
                if r["raw"]:
                    while True:
                        try:
                            self.producer.produce(topic, r["raw"].encode("utf-8"))
                            break
                        except BufferError:
                            self.producer.poll(0.5)
                    n += 1
            self.producer.poll(0)
        if n:
            left = self.producer.flush(60)
            if left:
                raise RuntimeError(f"replay: {left} lines not delivered to {topic}")
        return n

    def _record(self, entry: dict) -> None:
        store = self.svc.eng.store
        with self.svc.lock:
            self._save(store, entry)

    @staticmethod
    def _save(store, entry: dict) -> None:
        hist = (store.get_state("deploy_history", []) or [])[-29:] + [json.loads(json.dumps(entry, default=str))]
        store.set_state("deploy_history", hist)
