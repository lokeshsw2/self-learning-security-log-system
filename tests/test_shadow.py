import json

from logparser import shadow
from logparser.tools import Tools
from tests.test_engine import SSH, feed, make

V1 = {"kind": "regex", "pattern": r"^Failed password for (?P<user>\S+) from (?P<a>\S+) port (?P<p>\d+) ssh2$"}
V2 = {"kind": "regex", "pattern": r"^Failed password for (?P<account>\S+) from (?P<src_ip>\S+) port (?P<src_port>\d+) ssh2$"}
BROKEN = {"kind": "regex", "pattern": r"^Failed password for (?P<account>admin) from (?P<src_ip>\S+) port (?P<p>\d+) ssh2$"}


def more(n, start=100):
    return ["Dec 12 06:55:46 LabSZ sshd[1]: Failed password for root from 10.1.%d.%d port %d ssh2" % (i // 250, i % 250, 2000 + i)
            for i in range(start, start + n)]


def test_shadow_rule_runs_beside_live_and_is_promoted_only_after_holding(tmp_path):
    eng = make(tmp_path, shadow_min_lines=30, shadow_min_ok=0.99)
    feed(eng, tmp_path, SSH)
    sig = eng.store.queue_items("needs-parser")[0]["key"]
    Tools(eng).save_parser(sig, V1)
    rule_id = f"parser:{sig}"
    shadow.propose(eng.store, rule_id, V2, {"created_by": "test"})
    feed(eng, tmp_path, more(10))
    # live output still comes from the active version; the shadow only counts
    last = json.loads(eng.store.q("SELECT fields FROM events ORDER BY raw_id DESC")[0]["fields"])
    assert "user" in last and "account" not in last
    st = shadow.status(eng.store)[0]
    assert (st["lines"], st["ok"]) == (10, 10)
    assert shadow.review(eng)[0]["decision"] == "waiting"
    feed(eng, tmp_path, more(25, 500))
    d = shadow.review(eng)[0]
    assert d["decision"] == "promoted" and d["replayed"] == 43
    assert all("account" in json.loads(r["fields"]) for r in eng.store.q("SELECT fields FROM events"))
    assert [v["status"] for v in eng.store.rule_versions(rule_id)] == ["retired", "active"]


def test_shadow_rule_that_fails_is_rejected_and_never_touches_output(tmp_path):
    eng = make(tmp_path, shadow_min_lines=20, shadow_min_ok=0.99)
    feed(eng, tmp_path, SSH)
    sig = eng.store.queue_items("needs-parser")[0]["key"]
    Tools(eng).save_parser(sig, V1)
    shadow.propose(eng.store, f"parser:{sig}", BROKEN)
    out = feed(eng, tmp_path, more(25))
    assert out["parsed"] == 25 and out["dlq"] == 0
    d = shadow.review(eng)[0]
    assert d["decision"] == "rejected" and d["ok"] == 0 and "did not match" in d["last_error"]
    assert eng.store.active_rule(f"parser:{sig}")["body"] == V1


def test_shadow_mode_setting_routes_new_versions_of_live_rules_to_shadow(tmp_path):
    eng = make(tmp_path, shadow_mode=True, shadow_min_lines=5)
    feed(eng, tmp_path, SSH)
    sig = eng.store.queue_items("needs-parser")[0]["key"]
    t = Tools(eng)
    assert "status" not in t.save_parser(sig, V1)            # first rule for a group goes live after the gate
    res = t.save_parser(sig, V2)
    assert res["status"] == "shadow" and eng.store.active_rule(f"parser:{sig}")["body"] == V1
    feed(eng, tmp_path, more(6))
    assert shadow.review(eng)[0]["decision"] == "promoted"
    assert eng.store.active_rule(f"parser:{sig}")["body"] == V2
