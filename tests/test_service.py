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
        self.batch, self.commits, self.committed, self.fail_commit = batch, 0, {}, False

    def poll(self, max_messages):
        out, self.msgs = self.msgs[:min(self.batch, max_messages)], self.msgs[min(self.batch, max_messages):]
        return out

    def commit(self, offsets):
        if self.fail_commit:
            raise RuntimeError("rebalance in progress")
        self.commits += 1
        self.committed.update(offsets)

    def redeliver(self, msgs):
        self.msgs = list(msgs) + self.msgs


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
    cfg.kafka.idle_flush_s = 0
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


# --------------------------------------------------------------------- review findings
def test_redelivered_messages_are_skipped_not_counted_twice(tmp_path):
    cons = FakeConsumer(SSH, batch=100)
    svc = LearnerService(config(tmp_path), consumer=cons)
    first = list(cons.msgs)
    svc.step()
    raw = svc.eng.store.q("SELECT COUNT(*) n FROM raw")[0]["n"]
    cons.redeliver(first)                       # a crash before the commit, or a rebalance
    svc.step()
    assert svc.stats["duplicates_skipped"] == len(SSH)
    assert svc.eng.store.q("SELECT COUNT(*) n FROM raw")[0]["n"] == raw
    assert sum(g["count"] for g in svc.eng.groups.values() if not g["merged_into"]) == len(SSH)
    assert cons.committed[("logs.unparsed", 0)] == (len(SSH) + 1) // 2      # exact next offsets


def test_a_failed_commit_does_not_stop_the_service(tmp_path):
    cons = FakeConsumer(SSH, batch=4)
    cons.fail_commit = True
    svc = LearnerService(config(tmp_path), consumer=cons)
    svc.run(idle_exit_s=0)
    assert svc.stats["commit_errors"] >= 2 and svc.stats["records"] == len(SSH)


def test_empty_and_oversized_messages(tmp_path):
    big = "x" * 70000
    svc = LearnerService(config(tmp_path), consumer=FakeConsumer([b"", b"   ", SSH[0], big]))
    svc.run(idle_exit_s=0)
    assert svc.stats["empty_skipped"] == 2 and svc.stats["truncated"] == 1
    assert max(len(r["raw"]) for r in svc.eng.store.q("SELECT raw FROM raw")) <= svc.eng.settings.max_line_len


class FailingModel:
    def __init__(self):
        import types
        self.messages = types.SimpleNamespace(create=self._fail)
        self.beta = types.SimpleNamespace(messages=types.SimpleNamespace(create=self._fail))

    def _fail(self, **kw):
        raise ConnectionError("API unreachable")


def test_a_failing_cycle_is_recorded_and_backs_off(tmp_path):
    from tests.test_engine import PG, PG2
    clock = Clock()
    cfg = config(tmp_path, enabled=True, roles=["longtail"], interval_s=100)
    svc = LearnerService(cfg, consumer=FakeConsumer([PG, PG2]), model_client=FailingModel(), clock=clock)
    svc.run(idle_exit_s=0)                                  # the cycle fails; the service keeps going
    hist = svc.eng.store.get_state("learn_history")
    assert hist[-1]["error"].startswith("ConnectionError") and svc.stats["learn_errors"] == 1
    assert svc.eng.store.get_state("learn_last") == clock.t
    clock.t += 150                                          # past the interval, but backing off (2 x 100 s)
    assert svc.learning_due() == "interval not reached"
    clock.t += 100
    assert svc.learning_due() is None


def test_learning_runs_beside_intake(tmp_path):
    import threading
    from tests.test_engine import PG, PG2
    gate = threading.Event()

    class SlowModel(FakeLongtail):
        def _create(self, **kw):
            gate.wait(5)                                    # the cycle waits until more lines arrived
            return super()._create(**kw)

    cons = FakeConsumer([PG, PG2], batch=10)
    cfg = config(tmp_path, enabled=True, roles=["longtail"])
    svc = LearnerService(cfg, consumer=cons, model_client=SlowModel({"fields": {}, "summary": "Connection received."}))
    svc.step()
    svc.idle_since = svc.clock() - 1
    svc.idle_flush()
    assert svc.learning_due() is None
    svc.start_learning()
    cons.redeliver([("logs.unparsed", 5, 0, SSH[0].encode(), {})])
    svc.step()                                              # intake continues while the cycle runs
    assert svc.learner.is_alive() and svc.stats["records"] == 3
    gate.set()
    svc.learner.join(10)
    assert svc.eng.store.get_state("learn_history")[-1]["spent_usd"] > 0


def test_budget_stops_before_an_item_it_probably_cannot_afford():
    import types
    from logparser.harness import Harness
    h = Harness.__new__(Harness)
    h.budget_usd, h.spent_usd, h.item_costs, h.stop, h.role_until = 0.50, 0.42, [0.10, 0.12], None, None
    assert h.over_budget()                                  # 0.42 + 0.11 average > 0.50
    h.spent_usd = 0.30
    assert not h.over_budget()


def test_config_secrets_and_validation(tmp_path, monkeypatch):
    monkeypatch.setenv("KAFKA_PASSWORD", "s3cret")
    p = tmp_path / "c.json"
    p.write_text(json.dumps({"kafka": {"extra": {"sasl.password": "${KAFKA_PASSWORD}", "security.protocol": "SASL_SSL"}},
                             "store": {"url": "sqlite:///x.db"}}))
    cfg = ServiceConfig.load(str(p))
    assert cfg.kafka.client_extra()["sasl.password"] == "s3cret"
    assert cfg.redacted()["kafka"]["extra"] == {"sasl.password": "***", "security.protocol": "SASL_SSL"}
    assert "s3cret" not in json.dumps(cfg.redacted())
    p.write_text(json.dumps({"learning": {"roles": ["parser-gen", "magic"]}}))
    with pytest.raises(ValueError, match="unknown roles"):
        ServiceConfig.load(str(p))
    p.write_text(json.dumps({"learning": {"interval_s": 0}}))
    with pytest.raises(ValueError, match="positive"):
        ServiceConfig.load(str(p))


# --------------------------------------------------------------------- phase 2: deployment pieces
def test_swap_in_rewrites_paths_and_removes_stale_pipelines(tmp_path):
    from logparser.service.deploy import swap_in
    live, staging = tmp_path / "live", tmp_path / "live.next"
    live.mkdir(); staging.mkdir()
    (live / "src_old.conf").write_text("old")
    (staging / "distributor.conf").write_text(f'ruby {{ path => "{staging}/lp_lib.rb" }}')
    (staging / "pipelines.yml").write_text(f'- pipeline.id: distributor\n  path.config: "{staging}/distributor.conf"\n')
    moved = swap_in(str(staging), str(live))
    assert moved[-1] == "pipelines.yml"                        # pipelines.yml goes in last
    assert str(staging) not in (live / "pipelines.yml").read_text()
    assert str(live) in (live / "distributor.conf").read_text()
    assert not (live / "src_old.conf").exists() and not staging.exists()


def test_kafka_io_reads_new_lines_live_and_replays_from_the_start():
    from logparser import logstash as L
    inp, sink = L.kafka_io("b:1", ["logs.unparsed", "logs.replay"], "lp-logstash", "logs.parsed", ROOT,
                           extra={"security.protocol": "SSL"})
    first, second = inp.split("\nkafka {")
    assert '"logs.unparsed"' in first and 'auto_offset_reset => "latest"' in first
    assert '"logs.replay"' in second and 'group_id => "lp-logstash-replay"' in second and '"earliest"' in second
    assert 'topic_id => "logs.parsed"' in sink and "lp_unparsed" in sink and 'security.protocol => "SSL"' in inp


def test_clickhouse_statements():
    from logparser.service.clickhouse import statements
    sts = statements("lpsvc", "b:1", "logs.parsed", "g")
    assert any("ENGINE = Kafka" in s and "'logs.parsed'" in s for s in sts)
    assert any("MATERIALIZED VIEW" in s and "lpsvc.ocsf_events" in s for s in sts)
    assert not any("logs.ocsf_events" in s for s in sts)
    with pytest.raises(ValueError):
        statements("bad;name", "b:1", "t", "g")


def test_sink_time_is_exact_to_the_millisecond():
    text = open(os.path.join(ROOT, "deploy", "logstash", "output-clickhouse.conf")).read()
    assert "t / 1000.0" not in text and "(ti % 1000) * 1000" in text



# --------------------------------------------------------------------- budget shares per agent
def test_allotment_shares_what_is_left():
    from logparser.harness import SHARES, allotment
    later = ["ocsf-mapping", "longtail", "source-naming"]
    # parsers get 0.25 / (0.25 + 0.35 + 0.10 + 0.10) of what is left
    assert allotment(1.0, "parser-gen", later, SHARES) == pytest.approx(0.25 / 0.80)
    assert allotment(0.5, "source-naming", [], SHARES) == pytest.approx(0.5)    # the last agent gets the rest


class CostingClient:
    """Agent-loop fake whose every call costs the same; it never saves, so an agent keeps going until its
    allotment stops it. Records which agent each call was for."""

    def __init__(self):
        import types
        self.calls = []
        self.beta = types.SimpleNamespace(messages=types.SimpleNamespace(create=self._create))

    def _create(self, **kw):
        import types
        role = kw["system"].split("Role: ", 1)[1].split(".", 1)[0] if "Role: " in kw["system"] else "?"
        self.calls.append(role)
        usage = types.SimpleNamespace(input_tokens=10000, output_tokens=2000, cache_read_input_tokens=0,
                                      cache_creation_input_tokens=0)      # $0.04 per call on Sonnet prices
        return types.SimpleNamespace(stop_reason="end_turn", usage=usage,
                                     content=[types.SimpleNamespace(type="text", text="FLAG: cannot tell")])


def test_first_agent_cannot_spend_the_whole_cycle(tmp_path):
    from logparser.harness import Harness, learn
    from tests.test_engine import make
    eng = make(tmp_path)
    for i in range(30):                                       # plenty of naming and parser work
        eng.store.enqueue("needs-source", f"src{i}", {"source": f"src{i}"})
        eng.store.enqueue("needs-parser", f"g{i}", {"signature": f"g{i}"})
    fake = CostingClient()
    h = Harness(eng, client=fake, model="claude-sonnet-5-5", budget_usd=0.40)
    report = learn(h, ["source-naming", "parser-gen"], 30, "claude-sonnet-5-5", fix_rounds=0)
    roles = [c.lower() for c in fake.calls]
    assert roles[0].startswith("parser")                      # parsers first: they make events
    assert any(r.startswith("source") for r in roles)        # naming still got its share
    assert h.spent_usd <= 0.40 + 1e-9
    assert report["parser-gen"]["allotted_usd"] == pytest.approx(0.40 * 0.25 / 0.35, abs=1e-3)
    assert report["source-naming"]["spent_usd"] > 0


def test_agents_with_nothing_waiting_pass_their_share_on(tmp_path):
    from logparser.harness import Harness, learn
    from tests.test_engine import make
    eng = make(tmp_path)
    for i in range(30):
        eng.store.enqueue("needs-source", f"src{i}", {"source": f"src{i}"})
    fake = CostingClient()
    h = Harness(eng, client=fake, model="claude-sonnet-5-5", budget_usd=0.20)
    report = learn(h, ["parser-gen", "ocsf-mapping", "source-naming"], 30, "claude-sonnet-5-5", fix_rounds=0)
    assert report["parser-gen"] == {"skipped": "nothing waiting"}
    assert report["source-naming"]["allotted_usd"] == pytest.approx(0.20)   # the whole budget, nothing else to do


def test_direct_variant_runs_the_filter_writer_not_the_rule_agents(tmp_path, monkeypatch):
    from logparser.service import runner
    from logparser.service.config import ServiceConfig
    cfg = ServiceConfig()
    cfg.store = {"url": f"sqlite:///{tmp_path}/s.db"}
    cfg.logstash.variant = "direct"
    cfg.learning.enabled = True
    seen = {}

    def fake_learn(h, roles, *a, **k):
        seen["roles"] = roles
        return {}
    import logparser.harness as harness
    monkeypatch.setattr(harness, "learn", fake_learn)
    svc = runner.LearnerService(cfg, consumer=FakeConsumer([]), model_client=CostingClient())
    svc.learn_cycle()
    assert seen["roles"] == ["detection", "source-naming", "grouping-repair", "ls-direct"]
    cfg.learning.roles = ["ls-direct"]
    cfg.validate()
