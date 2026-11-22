"""Detection repair: agents add header rules for unread lines; code refuses anything that changes
how lines already read are read."""
import json

import pytest

from logparser import detection
from logparser.harness import Harness
from logparser.tools import Refused, Tools
from tests.test_engine import feed, make
from tests.test_harness import FakeClient


def read_ok(i):        # read today by the built-in syslog_iso rule
    return f"2026-09-20T14:{i % 60:02d}:01.000001+05:30 pc sshd[{100 + i}]: Accepted password for u{i % 3} from 10.0.0.{i} port 22"


def odd(i):            # gdm writes its program name with a stray bracket: no built-in rule reads it
    return f"2026-09-20T15:{i % 60:02d}:02.000002+05:30 pc gdm-password]: pam_unix(gdm-password:auth): authentication failure; user=u{i % 4}"


GOOD = {"name": "ai_syslog_iso_odd_app", "order": 23.5, "type": "envelope", "app": ["app"], "test": {
    "kind": "regex", "pattern": r"^(?P<timestamp>\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:?\d\d)) "
                                r"(?P<host>[A-Za-z0-9][A-Za-z0-9._\-]*) (?P<app>[^\s:\]]+)\]?(?:\[(?P<pid>\d+)\])?: "
                                r"(?P<payload>.*)$"}}
BROAD = {"name": "ai_anything", "order": 1, "type": "envelope", "app": [], "test": {
    "kind": "regex", "pattern": r"^(?P<timestamp>\S+) (?P<payload>.*)$"}}


def setup(tmp_path, n_odd=25):
    eng = make(tmp_path, group_threshold=50)
    feed(eng, tmp_path, [read_ok(i) for i in range(30)] + [odd(i) for i in range(n_odd)])
    return eng


def test_scan_queues_unread_headed_lines_only(tmp_path):
    eng = setup(tmp_path)
    assert detection.scan(eng) == {"sources": 1, "shapes": 1, "queued": 1}
    item = eng.store.queue_items(detection.QUEUE)[0]
    assert item["payload"]["count"] == 25 and all("gdm-password]" in s for s in item["payload"]["samples"])
    assert detection.scan(eng)["queued"] == 0                    # queued once


def test_scan_ignores_few_or_headerless_lines(tmp_path):
    eng = make(tmp_path, group_threshold=50)
    feed(eng, tmp_path, [odd(i) for i in range(5)] + [f"free text line number {i} without a header" for i in range(40)])
    assert detection.scan(eng)["queued"] == 0


def test_good_rule_reads_samples_and_changes_nothing_else(tmp_path):
    eng = setup(tmp_path)
    detection.scan(eng)
    samples = eng.store.queue_items(detection.QUEUE)[0]["payload"]["samples"]
    res = detection.evaluate(eng, samples, GOOD)
    assert res["ok"] and res["regressions"] == 0 and res["target"]["read"] == 25
    assert res["target"]["first"]["header"]["@app"] == "gdm-password"
    bad = detection.evaluate(eng, samples, BROAD)
    assert not bad["ok"] and bad["regressions"] >= 30            # it would re-read every sshd line


@pytest.mark.parametrize("change,why", [
    ({"name": "syslog_iso"}, "start with `ai_`"),
    ({"test": {"kind": "regex", "pattern": "(?P<timestamp>x) (?P<payload>.*)"}}, "anchored"),
    ({"test": {"kind": "regex", "pattern": "^(?P<timestamp>\\S+) .*$"}}, "payload"),
    ({"test": {"kind": "regex", "pattern": "^(?P<x>\\S+) (?P<payload>.*)$"}}, "at least one of"),
    ({"type": "format", "format": "kv"}, "envelope"),
])
def test_static_refusals(tmp_path, change, why):
    eng = setup(tmp_path)
    with pytest.raises(detection.DetectRefused, match=why):
        detection.check_rule(eng, {**GOOD, **change})


def test_agents_cannot_overwrite_a_rule_they_did_not_write(tmp_path):
    from logparser import registry
    eng = setup(tmp_path)
    registry.save_rule(eng.store, "detect:ai_by_human", {**GOOD, "name": "ai_by_human"}, {"created_by": "human"})
    with pytest.raises(detection.DetectRefused, match="not written by the detection agent"):
        detection.check_rule(eng, {**GOOD, "name": "ai_by_human"})


def test_save_moves_the_lines_and_closes_stale_work(tmp_path):
    eng = setup(tmp_path)
    detection.scan(eng)
    key = eng.store.queue_items(detection.QUEUE)[0]["key"]
    old_groups = {g["signature"] for g in eng.store.groups("source='-|unstructured|-' AND merged_into IS NULL")}
    assert eng.store.queue_items("longtail")                       # the unread lines were waiting there
    with pytest.raises(Refused, match="changes how"):
        Tools(eng, "harness:detection").save_detect(key, BROAD)
    res = Tools(eng, "harness:detection").save_detect(key, GOOD, "stray ] after the program")
    assert res["reprocessed"]["moved"] == 25 and res["reprocessed"]["groups_superseded"] == len(old_groups)
    assert eng.store.q("SELECT COUNT(*) n FROM raw WHERE source='-|unstructured|-'")[0]["n"] == 0
    assert all(eng.groups[s]["merged_into"] for s in old_groups)
    assert not [i for i in eng.store.queue_items("longtail") if i["key"] in old_groups]
    new = eng.store.q("SELECT source FROM raw WHERE raw LIKE '%gdm-password]%' LIMIT 1")[0]["source"]
    assert new == "-|ai_syslog_iso_odd_app>unstructured|gdm-password"
    # the hot path reads new lines with the rule at once; lines read before are untouched
    feed(eng, tmp_path, [odd(99), read_ok(99)])
    srcs = [r["source"] for r in eng.store.q("SELECT source FROM raw ORDER BY id DESC LIMIT 2")]
    assert sorted(srcs) == ["-|ai_syslog_iso_odd_app>unstructured|gdm-password", "-|syslog_iso>unstructured|sshd"]
    assert eng.store.queue_items(detection.QUEUE) == []


def test_harness_detection_role_saves_through_the_gate(tmp_path):
    eng = setup(tmp_path)
    detection.scan(eng)
    key = eng.store.queue_items(detection.QUEUE)[0]["key"]
    fake = FakeClient([
        {"tool": "get_samples", "input": {"item": "something-else"}},
        {"tool": "save_detect", "input": {"rule": BROAD}},
        {"tool": "save_detect", "input": {"rule": GOOD, "note": "stray ]"}},
    ])
    res = Harness(eng, client=fake).run_queue("detection")
    assert res == [{"key": key, "saved": True, "reason": None}]
    first = json.loads(fake.requests[1]["messages"][2]["content"][0]["content"])
    assert first["item"] == key                                    # pinned to its own item
    refused = json.loads(fake.requests[2]["messages"][4]["content"][0]["content"])
    assert refused["saved"] is False and "changes how" in refused["refused"]
    assert "Role: detection" in fake.requests[0]["system"]


def test_scan_leaves_lines_that_later_rules_handle_well(tmp_path):
    eng = setup(tmp_path)
    detection.scan(eng)
    key = eng.store.queue_items(detection.QUEUE)[0]["key"]
    sig = eng.store.queue_items("longtail")[0]["key"]
    # a long-tail rule that reads the line's own time handles these lines: nothing to repair
    from logparser import registry
    registry.save_rule(eng.store, "longtail:" + sig, {"fields": {"timestamp": {"var": 0}}, "summary": "gdm auth failure"},
                       {"created_by": "test"})
    eng.reload()
    eng.replay_signatures([sig])
    eng.store.queue_done(detection.QUEUE, key)
    eng.store.x("DELETE FROM queue WHERE name=?", (detection.QUEUE,))
    handled = eng.store.q("SELECT COUNT(*) n FROM raw WHERE signature=? AND status='parsed'", (sig,))[0]["n"]
    left = 25 - handled
    assert detection.scan(eng)["queued"] == (1 if left >= 20 else 0)
