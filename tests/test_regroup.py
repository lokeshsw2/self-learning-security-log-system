import json

import pytest

from logparser import registry
from logparser.tools import Refused, Tools
from tests.test_engine import feed, make


def pam(i, user=True):
    u = f"  user=u{i % 3}" if user else ""
    return (f"Jun 14 15:16:{i % 60:02d} combo sshd(pam_unix)[{19000 + i}]: authentication failure; logname= uid=0 "
            f"euid=0 tty=NODEVssh ruser= rhost=218.188.2.{i}{u}")


AUTH = {"class": "authentication", "constants": {"activity_id": 1, "status_id": 2, "service.name": "sshd"},
        "fields": [{"to": "user.name", "from": "user", "confidence": "high", "note": "user= value"},
                   {"to": "src_endpoint.ip", "from": "rhost", "confidence": "high", "note": "rhost= value"}]}


def setup(tmp_path):
    eng = make(tmp_path)
    feed(eng, tmp_path, [pam(i, user=i % 4 != 0) for i in range(1, 25)])
    live = eng.store.groups("merged_into IS NULL")
    assert len(live) == 1 and live[0]["count"] == 24        # optional key: one group
    return eng, Tools(eng, "map"), live[0]["signature"]


def test_code_check_names_the_split_and_split_gate_then_each_piece_maps(tmp_path):
    eng, t, sig = setup(tmp_path)
    res = t.test_mapping(sig, AUTH)
    assert res["valid"] < res["samples"]
    assert res["code_check"]["split_suggestions"][0]["split"] == {"presence": ["user"]}
    with pytest.raises(Refused, match="Code check"):
        t.save_mapping(sig, AUTH)
    # gates: a variable is not an event type; a split must separate something
    with pytest.raises(Refused, match="variable"):
        t.save_split(sig, {"fields": ["rhost"]})
    with pytest.raises(Refused, match="one piece"):
        t.save_split(sig, {"presence": ["rhost"]})
    out = t.save_split(sig, {"presence": ["user"]}, note="lines without user= cannot be Authentication")
    pieces = {p["key"]: p for p in out["pieces"]}
    assert pieces["has:user=1"]["lines"] == 18 and pieces["has:user=0"]["lines"] == 6
    assert sorted(i["key"] for i in eng.store.queue_items("needs-mapping")) == sorted(p["group"] for p in out["pieces"])
    assert eng.store.group(sig)["status"] == "split"
    t.save_mapping(pieces["has:user=1"]["group"], AUTH)
    rows = eng.store.q("SELECT class_uid, COUNT(*) n, MIN(valid) v FROM events GROUP BY class_uid ORDER BY class_uid")
    assert [(r["class_uid"], r["n"], r["v"]) for r in rows] == [(0, 6, 1), (3002, 18, 1)]
    # new lines are routed to the right piece by direct lookup
    feed(eng, tmp_path, [pam(100), pam(101, user=False)])
    last = [json.loads(r["ocsf"]) for r in eng.store.q("SELECT ocsf FROM events ORDER BY raw_id DESC LIMIT 2")]
    assert {e["class_uid"] for e in last} == {0, 3002}
    # no other group was created or re-signed
    assert len(eng.store.groups("merged_into IS NULL")) == 3


def test_regroup_limit_stops_oscillation(tmp_path):
    eng, t, sig = setup(tmp_path)
    for body in ({"presence": ["user"]}, {"fields": ["tty"], "presence": ["user"]}, {"presence": ["user"]}):
        t.save_split(sig, body)
    assert sum(g["count"] for g in eng.store.groups("merged_into IS NULL")) == 24     # nothing lost on re-split
    with pytest.raises(Refused, match="regrouped 3 times"):
        t.save_split(sig, {"presence": ["user", "rhost"]})


def test_switch_chooses_class_per_line(tmp_path):
    eng, t, sig = setup(tmp_path)
    t.save_mapping(None, AUTH, base="pam-auth")
    router = {"class": "base_event", "switch": [{"when": {"field": "user", "exists": True}, "use": "mapping:base-pam-auth"}],
              "fields": [{"to": "message", "from": "_text", "confidence": "medium", "note": "text before the pairs"}]}
    with pytest.raises(Refused, match="no active rule"):
        t.save_mapping(sig, {**router, "switch": [{"when": {"field": "user", "exists": True}, "use": "mapping:nope"}]})
    t.save_mapping(sig, router)
    rows = eng.store.q("SELECT class_uid, COUNT(*) n, MIN(valid) v FROM events GROUP BY class_uid ORDER BY class_uid")
    assert [(r["class_uid"], r["n"], r["v"]) for r in rows] == [(0, 6, 1), (3002, 18, 1)]


def test_report_problem_hands_the_item_to_the_other_queue(tmp_path):
    eng, t, sig = setup(tmp_path)
    assert t.report_problem(sig, "needs-parser", "kv parser cuts the value at the first space")["reported"]
    item = eng.store.queue_items("needs-parser")[0]
    assert item["key"] == sig and "first space" in item["payload"]["reason"] and item["payload"]["reported_by"] == "map"
    assert t.get_samples(group=sig)["queue_note"]["reason"].startswith("kv parser")
    assert eng.store.queue_items("needs-mapping") == []          # handed off, not left open in the sender's queue
    for _ in range(2):
        t.report_problem(sig, "needs-parser", "again")
    assert t.report_problem(sig, "needs-parser", "again")["flagged"]
    assert eng.store.queue_items("needs-parser", status="flagged")[0]["key"] == sig


def test_rules_moved_to_a_fresh_database_reach_split_pieces(tmp_path):
    """A split piece created on a fresh database picks up the mapping learned for it elsewhere."""
    eng, t, sig = setup(tmp_path)
    out = t.save_split(sig, {"presence": ["user"]})
    piece = next(p["group"] for p in out["pieces"] if p["key"] == "has:user=1")
    t.save_mapping(piece, AUTH)
    export = tmp_path / "rules.json"
    registry.export_rules(eng.store, str(export))
    fresh_dir = tmp_path / "fresh"
    fresh_dir.mkdir()
    fresh = make(fresh_dir)
    registry.import_rules(fresh.store, str(export))
    fresh.reload()
    feed(fresh, fresh_dir, [pam(i, user=i % 4 != 0) for i in range(1, 25)])
    rows = fresh.store.q("SELECT class_uid, COUNT(*) n FROM events GROUP BY class_uid ORDER BY class_uid")
    assert [(r["class_uid"], r["n"]) for r in rows] == [(0, 6), (3002, 18)]
