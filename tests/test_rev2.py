"""Revision 2: protected words, stable group ids, statistics, the repair loop."""
import json

import pytest

from logparser import repair, signature
from logparser.detect import detect
from logparser.tools import Refused, Tools
from tests.test_engine import feed, make


def sudo(i, args):
    return (f"Feb 10 08:{i % 60:02d}:40 host runner[9]: operator vagrant ran "
            f"/bin/tool{i % 7} " + " ".join(f"/etc/f{i}{k}" for k in range(args)))


def test_protected_words_are_never_masked_or_merged(tmp_path):
    eng = make(tmp_path)
    assert {"failed", "denied", "accepted"} <= eng.snap.protected
    a = signature.sign(eng.snap, detect(eng.snap, 'Jan  1 00:00:01 h fw[1]: rule 7 result "denied" for 10.0.0.1'), None)
    b = signature.sign(eng.snap, detect(eng.snap, 'Jan  1 00:00:01 h fw[1]: rule 7 result "allowed" for 10.0.0.2'), None)
    c = signature.sign(eng.snap, detect(eng.snap, 'Jan  1 00:00:01 h fw[1]: rule 7 result "x7" for 10.0.0.3'), None)
    assert '"denied"' in a.template and '"allowed"' in b.template and "<STR>" in c.template
    assert a.signature != b.signature
    # three outcome words in one position: without the list the merge step would fold them into <*>
    lines = [f"Jan  1 00:00:{i:02d} h app[1]: login {w} for user bob from 10.0.0.{i}"
             for i, w in enumerate(["accepted", "failed", "denied", "accepted", "failed", "denied"])]
    feed(eng, tmp_path, lines)
    tpl = sorted(g["template"] for g in eng.store.groups("merged_into IS NULL"))
    assert len(tpl) == 3 and all("<*>" not in t for t in tpl)
    # a structured field holding an outcome word marks the event type
    x = signature.sign(eng.snap, detect(eng.snap, 'src=1.1.1.1 dst=2.2.2.2 proto=tcp action=allow rule=5 n=1'), None)
    y = signature.sign(eng.snap, detect(eng.snap, 'src=1.1.1.1 dst=2.2.2.2 proto=tcp action=deny rule=5 n=1'), None)
    assert x.signature != y.signature and "action=deny" in y.template


def test_events_carry_group_id_and_rule_versions(tmp_path):
    eng = make(tmp_path)
    feed(eng, tmp_path, ['src=1.1.1.1 dst=2.2.2.2 proto=tcp bytes=5 rule=5 n=%d' % i for i in range(5)])
    ev = eng.store.q("SELECT signature, parser_rule, parser_version, mapping_rule, mapping_version FROM events")[0]
    assert ev["signature"] in eng.groups and ev["parser_version"] == 1 and ev["mapping_version"] == 1


def test_remask_keeps_group_ids_and_rules(tmp_path):
    eng = make(tmp_path, auto_repair=False)
    lines = [sudo(i, 1) for i in range(12)] + [sudo(i, 2) for i in range(6)] + [sudo(i, 3) for i in range(4)]
    feed(eng, tmp_path, lines, label="auth")
    live = eng.store.groups("merged_into IS NULL")
    assert len(live) == 3
    big = max(live, key=lambda g: g["count"])
    t = Tools(eng, "agent")
    t.save_parser(big["signature"], {"kind": "regex", "pattern":
                  r"^operator (?P<user>\S+) ran (?P<command>.+)$"})
    source = big["source"]
    res = t.save_mask(source, {"patterns": [{"name": "cmd", "pattern": " ran (.+)$", "placeholder": "<COMMAND>", "group": 1}]})
    live = eng.store.groups("merged_into IS NULL")
    assert len(live) == 1
    g = live[0]
    assert g["signature"] == big["signature"]                 # the group kept its id ...
    assert g["parser_rule"] == f"parser:{big['signature']}"    # ... and its parser
    assert g["count"] == 22 and "<COMMAND>" in g["template"]
    assert res["replay"]["parsed"] == 22 and res["replay"]["groups_kept"] == 1
    cmds = {json.loads(r["fields"])["command"] for r in eng.store.q("SELECT fields FROM events")}
    assert "/bin/tool3 /etc/f30 /etc/f31 /etc/f32" in cmds
    merged = eng.store.groups("status='merged'")
    assert len(merged) == 2 and all(m["merged_into"] == g["signature"] for m in merged)
    out = feed(eng, tmp_path, [sudo(50, 5)], label="auth")      # a new arity needs nothing new
    assert out["parsed"] == 1 and len(eng.store.groups("merged_into IS NULL")) == 1


def test_loop_asks_one_question_per_source_and_remembers_the_answer(tmp_path):
    eng = make(tmp_path, ambiguous_min_lines=10)
    kinds = ["sync", "probe", "rekey"]
    lines = ['dev=fw1 kind=%s proto=%s peer=10.0.%d.%d bytes=%d' % (kinds[i % 3], ["tcp", "udp"][i % 2], i, i, i * 7)
             for i in range(60)]
    feed(eng, tmp_path, lines, label="vpn")
    g = eng.store.groups("merged_into IS NULL")[0]
    q = eng.store.queue_items("grouping-repair")
    assert len(q) == 1 and q[0]["key"] == f"fields:{g['source']}"
    assert set(q[0]["payload"]["fields"]) == {"kind", "proto", "dev"} - {"dev"}      # dev has one value: fixed text
    t = Tools(eng, "grouping-repair")
    assert t.get_stats(g["signature"])["fields"]["kind"]["class"] == "ambiguous"
    with pytest.raises(Refused, match="variable"):
        t.save_operation({"op": "split", "group": g["signature"], "rule": {"fields": ["peer"]}})
    res = t.save_operation({"op": "classify_fields", "source": g["source"], "event_type_fields": ["kind"],
                            "value_fields": ["proto"]})
    assert res["split"][0]["pieces"] == 3 and res["value_fields"] == ["proto"]
    kids = eng.children(g["signature"])
    assert sorted(k["count"] for k in kids) == [20, 20, 20]
    d = {x["question"]: (x["answer"], x["tier"]) for x in t.get_decisions(g["source"])["decisions"]}
    assert d["field:kind"] == ("event_type", "verified") and d["field:proto"] == ("field_value", "plausible")
    # more lines: nothing is asked again, and the pieces cannot be regrouped during cooldown
    feed(eng, tmp_path, lines[:30], label="vpn")
    assert eng.store.queue_items("grouping-repair") == []
    assert repair.test(eng, {"op": "split", "group": g["signature"], "rule": {"fields": ["proto"]}})["error"].startswith("group is in cooldown")
    ops = eng.store.q("SELECT op, tier, status, verification FROM operations")
    assert ops[0]["op"] == "split" and ops[0]["tier"] == "verified" and json.loads(ops[0]["verification"])["pieces"] == 3
    assert repair.tiers(eng.store)["decisions"] == {"plausible": 1, "verified": 1}


def test_uncertain_answer_is_held_for_a_human(tmp_path):
    eng = make(tmp_path, ambiguous_min_lines=10)
    feed(eng, tmp_path, ['dev=fw1 kind=%s peer=10.0.%d.1 bytes=%d' % (["a1x", "b2y"][i % 2], i, i) for i in range(40)], label="x")
    g = eng.store.groups("merged_into IS NULL")[0]
    Tools(eng, "agent").save_operation({"op": "classify_fields", "source": g["source"], "uncertain": ["kind"]})
    assert eng.children(g["signature"]) == []
    held = eng.store.queue_items("human-review")
    assert len(held) == 1 and held[0]["payload"]["field"] == "kind"
    assert repair.tiers(eng.store)["held_for_human"] == 1


def test_merge_question_and_operation(tmp_path):
    eng = make(tmp_path)
    lines = [f"Jan  1 00:00:{i:02d} h app[1]: tunnel {['north', 'south'][i % 2]} is ready on port {i}" for i in range(12)]
    feed(eng, tmp_path, lines)
    q = [i for i in eng.store.queue_items("grouping-repair") if i["key"].startswith("merge:")]
    assert len(q) == 1 and sorted(q[0]["payload"]["values"]) == ["north", "south"]
    t = Tools(eng, "agent")
    res = t.save_operation({"op": "merge", "groups": q[0]["payload"]["groups"]})
    live = eng.store.groups("merged_into IS NULL")
    assert len(live) == 1 and live[0]["count"] == 12 and "tunnel <*> is ready" in live[0]["template"]
    assert set(eng.store.signature_map().values()) == {res["group"]}
    # an outcome word in that position is refused
    feed(eng, tmp_path, [f"Jan  1 00:01:{i:02d} h app[1]: check {['passed', 'failed'][i % 2]} for unit {i}" for i in range(12)])
    two = [g["signature"] for g in eng.store.groups("merged_into IS NULL AND template LIKE 'check%'")]
    assert len(two) == 2
    with pytest.raises(Refused, match="outcome or action word"):
        t.save_operation({"op": "merge", "groups": two})


def test_split_that_hurts_is_rolled_back(tmp_path):
    eng = make(tmp_path, ambiguous_min_lines=10, cooldown_batches=1)
    lines = ['dev=fw1 kind=%s peer=10.0.%d.1 bytes=%d' % (["sync", "probe"][i % 2], i, i) for i in range(40)]
    feed(eng, tmp_path, lines, label="x")
    g = eng.store.groups("merged_into IS NULL")[0]
    t = Tools(eng, "agent")
    t.save_operation({"op": "split", "group": g["signature"], "rule": {"fields": ["kind"]}})
    kid = eng.children(g["signature"])[0]
    # someone gives one piece a mapping that fails on every line
    from logparser import registry
    registry.save_rule(eng.store, "mapping:bad", {"class": "authentication", "fields": []})
    kid["mapping_rule"] = "mapping:bad"
    eng.store.upsert_group(kid)
    eng.replay_signatures([kid["signature"]])
    eng.batch_no += 2
    out = repair.review(eng)
    assert out[0]["decision"] == "rolled_back"
    assert eng.children(g["signature"]) == [] and eng.store.group(g["signature"])["count"] == 40
    assert [r["op"] for r in eng.store.q("SELECT op FROM operations ORDER BY id")] == ["split", "rollback"]


def test_wrapped_and_embedded_formats(tmp_path):
    eng = make(tmp_path)
    d = detect(eng.snap, '{"GraSource":"GraLinuxAgent","message":"2026-11-02T14:52:46+05:30 hostb crontab[21520]: (paula) LIST (paula)","EventReceivedTime":"2026-11-02 14:52:46"}')
    assert d.chain[0] == "json_wrap" and d.app == "crontab" and d.payload == "(paula) LIST (paula)" and d.header["@GraSource"] == "GraLinuxAgent"
    d = detect(eng.snap, '<134>Nov 2 14:52:59 194.26.29.77 customer.okta.com {"uuid":"0c51","eventType":"user.session.start"}')
    assert d.format == "json" and d.header["@host"] == "194.26.29.77" and d.payload.startswith('{"uuid"')
    d = detect(eng.snap, "<78>{logger_name:'brivo',host:'UK1',siteName:'King's Cross 45',description:'Forced Open',deviceType:'Door'}")
    assert d.format == "kv" and d.dialect == "kv_js"
    from logparser import formats
    f = formats.kv_pairs(d.payload, eng.snap.dialects["kv_js"])[0]
    assert f["siteName"] == "King's Cross 45" and f["description"] == "Forced Open"


def test_label_scoped_mask_applies_to_an_unlabelled_stream_but_not_another_label(tmp_path):
    from logparser import registry
    eng = make(tmp_path)
    registry.save_rule(eng.store, "mask:jobs", {"scope": {"bucket": "^x$", "stream": "jobs"}, "priority": 10,
                                                "patterns": [{"name": "j", "pattern": "J\\w+", "placeholder": "<JOB>"}]})
    eng.reload()
    names = lambda stream: [p[0] for p in eng.snap.mask_patterns("x", stream)]
    assert "j" in names("jobs")          # the stream it was learned on
    assert "j" in names(None)            # a mixed topic with no source label
    assert "j" not in names("other")     # never another labelled source
    assert "j" not in names.__call__("jobs") or "j" not in [p[0] for p in eng.snap.mask_patterns("y", "jobs")]


def test_source_families_and_naming(tmp_path):
    eng = make(tmp_path)
    a = ['{"uuid":"%d","published":"2026-01-01T00:00:0%dZ","eventType":"user.session.start","actor":{"id":"a"},"outcome":{"result":"SUCCESS"}}' % (i, i % 9) for i in range(30)]
    b = ['{"CreationTime":"2026-01-01T00:00:0%d","Operation":"FileAccessed","Workload":"SharePoint","UserId":"u%d","ClientIP":"10.0.0.%d"}' % (i % 9, i, i) for i in range(30)]
    mixed = [x for pair in zip(a, b) for x in pair]
    feed(eng, tmp_path, mixed)                                   # one unlabelled stream
    keys = sorted(s["source"] for s in eng.store.sources())
    assert len(keys) == 2 and all(k.startswith("-|json|-#f") for k in keys)   # two families, not one "json" source
    t = Tools(eng, "namer")
    okta = [k for k in keys if any("uuid" in r["raw"] for r in eng.store.raw_by_source(k)[:1])][0]
    loose = {"vendor": "Okta", "product": "Okta System Log", "match": {"bucket": "^json\\|"}}
    with pytest.raises(Refused, match="did not list"):         # "any JSON" would name the other vendor too
        t.save_source(okta, loose)
    with pytest.raises(Refused, match="does not match"):       # a test that misses this source
        t.save_source(okta, {**loose, "match": {"bucket": "^json\\|", "requires": ["Workload"]}})
    good = {"vendor": "Okta", "product": "Okta System Log", "match": {"bucket": "^json\\\\|", "requires": ["eventType", "uuid"]}}
    res = t.save_source(okta, good)
    assert res["named"] == [okta]
    assert eng.store.source(okta)["vendor"] == "Okta"
    assert [i["key"] for i in eng.store.queue_items("needs-source")] == [k for k in keys if k != okta]
    # a new line of that product in a new engine is named by code, with no agent
    from logparser.engine import Engine
    e2 = Engine(eng.store, eng.settings, schema=eng.schema, now=eng.now)
    eng.store.x("DELETE FROM sources")
    e2.sources = {}
    feed(e2, tmp_path, [a[0].replace('"uuid":"0"', '"uuid":"99"')], name="more.log")
    assert [s["vendor"] for s in eng.store.sources()] == ["Okta"]


def test_gate_refuses_time_and_outcome_that_contradict_the_line(tmp_path):
    eng = make(tmp_path)
    lines = ['<134>1 2026-11-02T14:52:3%d+05:30 fw - - - - 10,11/02/26,14:52:3%d,Deny,10.0.0.%d,host%d,aa:bb:cc:dd:ee:0%d,,0,0'
             % (i, i, i, i, i) for i in range(8)]
    feed(eng, tmp_path, lines)
    g = [x for x in eng.store.groups("merged_into IS NULL") if x["parser_rule"]][0]
    t = Tools(eng, "m")
    base = {"class": "network_activity", "constants": {"activity_id": 6, "src_endpoint.ip": "10.0.0.1"},
            "fields": [{"to": "src_endpoint.ip", "from": "c4", "confidence": "high", "note": "client"}]}
    naive = json.loads(json.dumps(base))       # local date and time read as UTC: 5.5 hours off the header
    naive["fields"].append({"to": "time", "from": ["c1", "c2"], "join": " ", "confidence": "high", "note": "t",
                            "transform": {"fn": "parse_timestamp", "args": {"formats": ["%m/%d/%y %H:%M:%S"]}}})
    res = t.test_mapping(g["signature"], naive)
    assert any(e["error"].startswith("time:") for e in res["errors"])
    with pytest.raises(Refused, match="time"):
        t.save_mapping(g["signature"], naive)
    no_time = json.loads(json.dumps(base))     # no time entry: the engine falls back to the header time
    assert not [e for e in t.test_mapping(g["signature"], no_time)["errors"] if e["error"].startswith("time:")]
    good = json.loads(json.dumps(base))
    good["fields"].append({"to": "time", "from": "@timestamp", "transform": {"fn": "parse_timestamp"},
                           "confidence": "high", "note": "header time with zone"})
    assert not [e for e in t.test_mapping(g["signature"], good)["errors"] if e["error"].startswith("time:")]
    # outcome: a deny word in an action-like field needs an outcome in the event
    from logparser.checks import problems
    from logparser.detect import Detection
    d = Detection(header={})
    ev = {"class_uid": 4001, "time": 1}
    assert problems(d, {"action": "Deny"}, ev, [], {})[0].startswith("outcome:")
    assert problems(d, {"action": "Deny"}, {**ev, "action_id": 2}, [], {}) == []
    assert "Success" in problems(d, {"action": "blocked"}, {**ev, "status_id": 1}, [], {})[0]
    assert problems(d, {"url": "/blocked-page"}, ev, [], {}) == []           # not an outcome field
