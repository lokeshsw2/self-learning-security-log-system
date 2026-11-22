"""The learning service, with a fake Kafka consumer and a fake model: no broker, no API calls."""
import json
import os
import re

import pytest

from logparser.service.config import ServiceConfig
from logparser.service.runner import LearnerService
from tests.test_audit import FakeLongtail
from tests.test_engine import SSH

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class FakeConsumer:
    """Batches of (topic, partition, offset, bytes, headers); records commits."""

    def __init__(self, lines, batch=10, topic="logs.unparsed"):
        self.msgs = [(topic, i % 2, i // 2, l.encode() if isinstance(l, str) else l, {}) for i, l in enumerate(lines)]
        self.batch, self.commits, self.fail_next = batch, 0, False

    def poll(self, max_messages):
        out, self.msgs = self.msgs[:min(self.batch, max_messages)], self.msgs[min(self.batch, max_messages):]
        return out

    def commit(self):
        self.commits += 1


class NoModel:
    """A model client that must never be called in these tests."""

    def __getattr__(self, name):
        raise AssertionError("a model call was attempted")


class Clock:
    def __init__(self, t=1795400000.0):
        self.t = t

    def __call__(self):
        return self.t


def config(tmp_path, **learning):
    cfg = ServiceConfig()
    cfg.store = {"url": f"sqlite:///{tmp_path}/svc.db"}
    cfg.engine_settings = None
    for k, v in learning.items():
        setattr(cfg.learning, k, v)
    return cfg


def test_batches_are_processed_then_committed(tmp_path):
    cons = FakeConsumer(SSH + [b"\x00\x01\x02binary\x00\x00\x00\x00\x00"], batch=4)
    svc = LearnerService(config(tmp_path), consumer=cons)
    svc.run(idle_exit_s=0)
    assert svc.stats["records"] == len(SSH) + 1 and svc.stats["binary"] == 1
    assert svc.eng.store.active_rule("detect:syslog3164") is not None      # built-in rules loaded on start
    assert cons.commits == svc.stats["batches"] == 3
    # the read position of each partition is saved with the batch state
    assert svc.eng.store.get_state("offset:kafka:logs.unparsed:0") is not None


def test_nothing_is_committed_when_processing_fails(tmp_path):
    cons = FakeConsumer(SSH, batch=4)
    svc = LearnerService(config(tmp_path), consumer=cons)
    svc.eng.process = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("disk full"))
    with pytest.raises(RuntimeError):
        svc.step()
    assert cons.commits == 0                     # Kafka will deliver the batch again


def test_learning_gates(tmp_path):
    clock = Clock()
    svc = LearnerService(config(tmp_path, enabled=False), consumer=FakeConsumer(SSH), clock=clock,
                         model_client=NoModel())
    assert svc.learning_due() == "learning is off"
    svc.cfg.learning.enabled = True
    assert svc.learning_due() == "nothing waiting"
    svc.cfg.learning.enabled = False
    svc.run(idle_exit_s=0)                                              # lines arrive while learning is off
    svc.cfg.learning.enabled = True
    assert svc.learning_due() is None                                   # lines no rule reads: due
    svc.eng.store.set_state("learn_last", clock.t - 10)
    assert svc.learning_due() == "interval not reached"
    svc.eng.store.set_state("learn_last", 0)
    svc._add_spend(5.0)
    assert svc.learning_due() == "daily budget used"


def test_learn_cycle_is_budgeted_and_announces_rule_changes(tmp_path):
    from tests.test_engine import PG, PG2
    clock = Clock()
    fake = FakeLongtail({"fields": {"src_ip": "10.20.9.56"}, "summary": "Connection received from host 10.20.9.56."})
    cfg = config(tmp_path, enabled=True, roles=["longtail"], budget_usd_per_cycle=0.5, budget_usd_per_day=0.6)
    svc = LearnerService(cfg, consumer=FakeConsumer([PG, PG2]), model_client=fake, clock=clock)
    changed = []
    svc.on_rules_changed = changed.append
    svc.run(idle_exit_s=0)                    # learning runs inside the loop once work is queued
    hist = svc.eng.store.get_state("learn_history")
    assert hist and hist[-1]["rules_changed"] and changed
    assert 0 < hist[-1]["spent_usd"] <= hist[-1]["budget_usd"] <= 0.5
    assert svc._spent_today() == pytest.approx(hist[-1]["spent_usd"])
    st = svc.status()
    assert st["learn_cycles"] == 1 and st["learning"] in ("interval not reached", "nothing waiting")


def test_config_is_checked(tmp_path):
    p = tmp_path / "c.json"
    p.write_text(json.dumps({"kafka": {"bootstrap": "x:1", "nope": 1}}))
    with pytest.raises(ValueError, match="unknown kafka settings"):
        ServiceConfig.load(str(p))
    p.write_text(json.dumps({"logstash": {"variant": "magic"}}))
    with pytest.raises(ValueError, match="variant"):
        ServiceConfig.load(str(p))
    cfg = ServiceConfig.load(os.path.join(ROOT, "deploy", "service", "local.json"))
    assert cfg.kafka.unparsed_topic == "logs.unparsed" and cfg.learning.enabled is False
    cfg.store = {"url": "mysql://u@h/db"}
    with pytest.raises(ValueError, match="MySQL comes in phase 6"):
        cfg.sqlite_path()


# SQLite-only SQL outside store.py: the MySQL port (phase 6) has to touch each of these. New code must
# not add more; when one is moved into store.py, lower the number here.
SQLITE_ONLY = re.compile(r"json_extract|json_set|INSERT OR IGNORE|INSERT OR REPLACE|ON CONFLICT|unixepoch|"
                         r"datetime\(|strftime\('%|ROW_NUMBER|PRAGMA")
BASELINE = 9


def test_sqlite_only_sql_does_not_spread():
    hits = []
    pkg = os.path.join(ROOT, "logparser")
    for dirpath, _, files in os.walk(pkg):
        for f in files:
            if f.endswith(".py") and f != "store.py":
                for n, line in enumerate(open(os.path.join(dirpath, f)), 1):
                    if SQLITE_ONLY.search(line) and ("SELECT" in line or "UPDATE" in line or "INSERT" in line
                                                     or ".q(" in line or ".x(" in line or "json_set" in line):
                        hits.append(f"{f}:{n}")
    assert len(hits) <= BASELINE, f"new SQLite-only SQL outside store.py: {hits}"
