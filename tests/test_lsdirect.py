"""Variant B: agents write Logstash filters as structured steps; code validates, renders, tests and deploys them."""
import json
import os
import shutil
import types

import pytest

from logparser import lsdirect as D, registry
from logparser.harness import Harness, learn
from logparser.tools import Refused, Tools
from tests.test_engine import SCHEMA, SSH, feed, make
from tests.test_harness import FakeClient

RULE = {"class": "authentication",
        "extract": [{"grok": {"patterns": ["^Failed password for %{USERNAME:user} from %{IP:src_ip} port %{INT:src_port} ssh2$"]}}],
        "time": {"field": "@timestamp", "formats": ["MMM d HH:mm:ss", "MMM dd HH:mm:ss"]},
        "map": [{"to": "user.name", "from": "user"}, {"to": "src_endpoint.ip", "from": "src_ip"},
                {"to": "src_endpoint.port", "from": "src_port", "convert": "integer"},
                {"to": "service.name", "from": "@app"},
                {"to": "status_id", "value": 2}, {"to": "activity_id", "value": 1}]}


# ------------------------------------------------------------------ static checks and rendering
@pytest.mark.parametrize("bad, words", [
    ({"extract": [{"ruby": {"code": "system('x')"}}]}, "one of"),
    ({"extract": [{"grok": {"patterns": ["x"], "add_field": {"a": "b"}}}]}, "not allowed"),
    ({"extract": [{"kv": {}}, {"json": {}}]}, "first"),
    ({"map": [{"to": "no_such_attribute", "value": 1}]}, "not an attribute"),
    ({"map": [{"to": "time", "from": "x"}]}, "set by code"),
    ({"map": [{"to": "user.name", "from": "a", "value": "b"}]}, "one of from or value"),
    ({"map": [{"to": "user.name", "from": "bad name!"}]}, "field name"),
    ({"profiles": ["Bad-Profile"]}, "profiles"),
    ({"class": "no_such_class"}, "unknown OCSF class"),
])
def test_validate_refuses(bad, words):
    with pytest.raises(D.FilterError, match=words):
        D.validate({**RULE, **bad}, SCHEMA)


def test_render_is_plain_logstash_and_quotes_safely():
    ex, rest = D.render_parts(RULE, SCHEMA, {"vendor": "OpenBSD", "product": "OpenSSH"}, "g1", "T_x", tz="+05:30")
    assert ex.startswith("grok {") and 'target => "[@metadata][s][f]"' in ex
    assert rest.startswith("ruby { code => 'LP.finish(event)' }")          # header merge after extraction
    assert 'timezone => "+05:30"' in rest                                  # a zoneless time: deployment zone
    assert '"[@metadata][s][f][src_port]" => "[ocsf][src_endpoint][port]"' in rest
    assert '"[ocsf][src_endpoint][port]" => "integer"' in rest and '"[ocsf][status_id]" => "integer"' in rest
    assert "LP.fin(event" in rest and '"cls" => 3002' in rest
    with pytest.raises(D.FilterError, match="both quote kinds"):
        D.render_steps({**RULE, "extract": [{"grok": {"patterns": ["a\"b'c"]}}]})
    # a value with one kind of quote is written with the other
    assert D.lit('say "hi"') == "'say \"hi\"'"


def test_dissect_and_nested_names():
    body = {**RULE, "extract": [{"dissect": {"mapping": "%{user} from %{src_ip}"}}],
            "map": [{"to": "user.name", "from": "actor.user"}]}
    D.validate(body, SCHEMA)
    txt = D.render_steps(body)
    assert "%{[@metadata][s][f][user]} from %{[@metadata][s][f][src_ip]}" in txt
    assert "[@metadata][s][f][actor][user]" in txt


# ------------------------------------------------------------------ the gate on one event
def _det(header=None):
    return types.SimpleNamespace(header=header or {"@timestamp": "Dec 10 06:55:46"}, payload="", fmt="unstructured")


GOOD_EVENT = {"class_uid": 3002, "category_uid": 3, "activity_id": 1, "type_uid": 300201, "severity_id": 0,
              "status_id": 2, "time": 1796865946000, "metadata": {"version": "1.10.0", "product": {"name": "OpenSSH"}},
              "user": {"name": "root"}, "src_endpoint": {"ip": "173.234.31.1", "port": 3001},
              "service": {"name": "sshd"}}


F1 = {"user": "root", "src_ip": "173.234.31.1", "src_port": "3001", "@app": "sshd"}


def test_judge_finds_failed_steps_values_and_ingest_time():
    raw = SSH[0]
    ok = {"ocsf": GOOD_EVENT, "sb": {"t": "x", "f": F1}}
    assert D.judge(SCHEMA, _det(), raw, ok, RULE) == []
    bad = {"ocsf": {**GOOD_EVENT, "user": {"name": "admin"}}, "sb": {"t": "x"}, "tags": ["_lp_grokfail"]}
    probs = D.judge(SCHEMA, _det(), raw, bad, RULE)
    assert any("grok step failed" in p for p in probs) and any("'admin' is not in this line" in p for p in probs)
    assert any(p.startswith("time:") for p in D.judge(SCHEMA, _det(), raw, {"ocsf": GOOD_EVENT, "sb": {}}, RULE))
    assert any(p.startswith("schema:") for p in
               D.judge(SCHEMA, _det(), raw, {"ocsf": {k: v for k, v in GOOD_EVENT.items() if k != "service"},
                                             "sb": {"t": 1}}, RULE))


# ------------------------------------------------------------------ test / save tools (fake Logstash)
class FakeSandbox:
    """Returns the event `make(record)` for every record; records which filters it was given."""

    def __init__(self, make_event):
        self.make_event, self.calls, self.stopped = make_event, [], 0

    def run(self, text, records, tables, tz="UTC"):
        self.calls.append(text)
        return {"events": {r["id"]: self.make_event(r) for r in records}}

    def stop(self):
        self.stopped += 1


def _ssh_event(r):
    ip = r["payload"].split(" from ")[1].split(" ")[0]
    port = int(r["payload"].split(" port ")[1].split(" ")[0])
    return {"ocsf": {**GOOD_EVENT, "src_endpoint": {"ip": ip, "port": port}},
            "sb": {"t": "x", "f": {"user": "root", "src_ip": ip, "src_port": str(port), "@app": "sshd"}}}


@pytest.fixture
def ssh(tmp_path):
    eng = make(tmp_path)
    feed(eng, tmp_path, SSH)
    g = next(g for g in eng.groups.values() if g["count"] == 8)
    yield eng, g["signature"]
    Tools.sandbox = None


def test_save_needs_every_line_to_pass(ssh):
    eng, gid = ssh
    t = Tools(eng, "test")
    Tools.sandbox = FakeSandbox(lambda r: {"ocsf": GOOD_EVENT, "sb": {"t": "x"}})    # same ip for every line
    res = t.test_lsfilter(gid, RULE)
    assert res["ok"] and not res["would_save"] and res["samples_valid"] < res["samples"]
    assert any("is not in this line" in e["error"] for e in res["errors"])
    with pytest.raises(Refused, match="every tested line must pass"):
        t.save_lsfilter(gid, RULE, {"vendor": "OpenBSD", "product": "OpenSSH"})
    Tools.sandbox = FakeSandbox(_ssh_event)
    res = t.test_lsfilter(gid, RULE)
    assert res["would_save"], res["errors"]
    out = t.save_lsfilter(gid, RULE, {"vendor": "OpenBSD", "product": "OpenSSH"}, "ok")
    rule = eng.snap.rule(out["saved"])
    assert rule["body"]["labels"] == {"vendor": "OpenBSD", "product": "OpenSSH"} and rule["kind"] == "lsfilter"
    with pytest.raises(Refused, match="unknown OCSF class"):
        t.save_lsfilter(gid, {**RULE, "class": "nope"})


def test_filter_must_not_read_lines_of_other_groups(tmp_path):
    eng = make(tmp_path)
    other = ["Dec 10 07:01:%02d LabSZ sshd[24300]: Accepted password for alice from 10.0.0.%d port 22 ssh2" % (i, i)
             for i in range(1, 9)]
    feed(eng, tmp_path, SSH + other)
    gid = next(g["signature"] for g in eng.groups.values() if "Failed" in (g["template"] or ""))
    t = Tools(eng, "test")
    # a filter that "reads" everything: no failure tag on any record, also on the other group's lines
    Tools.sandbox = FakeSandbox(lambda r: _ssh_event(r) if "Failed" in r["payload"] else {"ocsf": GOOD_EVENT, "sb": {"t": 1}})
    try:
        res = t.test_lsfilter(gid, RULE)
        assert res["other_group_lines"] > 0 and res["other_group_lines_read"] == res["other_group_lines"]
        assert not res["would_save"] and "another group" in res["errors"][0]["error"]
        # failing on the other group's lines (as a specific grok does) is what it should do
        Tools.sandbox = FakeSandbox(lambda r: _ssh_event(r) if "Failed" in r["payload"] else {"tags": ["_lp_grokfail"]})
        assert t.test_lsfilter(gid, RULE)["would_save"]
    finally:
        Tools.sandbox = None


def test_queue_and_compile_direct(ssh):
    eng, gid = ssh
    assert D.enqueue(eng) >= 1 and any(i["key"] == gid for i in eng.store.queue_items("needs-lsfilter"))
    registry.save_rule(eng.store, "lsfilter:" + gid, {**RULE, "labels": {"vendor": "OpenBSD", "product": "OpenSSH"}})
    eng.reload()
    assert D.enqueue(eng) == 0 or not any(i["key"] == gid and i["status"] == "open"
                                          for i in eng.store.queue_items("needs-lsfilter"))
    from logparser.logstash import Compiler
    comp = Compiler(eng, direct=True)
    gen = comp.compile()
    assert comp.leaves[gid].included, comp.leaves[gid].reason
    src = next(v for k, v in gen.files.items() if k.startswith("src_"))
    assert "Failed password for %{USERNAME:user}" in src and '"[lp][writer]", "direct"' in src
    assert '[@metadata][pm] == "0"' in src                     # the bucket cascade dispatches on the match
    # without a direct filter the group is not in a Variant B set
    eng.store.set_rule_status("lsfilter:" + gid, 1, "retired")
    eng.reload()
    comp = Compiler(eng, direct=True)
    comp.compile()
    assert gid not in comp.leaves or not comp.leaves[gid].included


# ------------------------------------------------------------------ the agent loop
def test_ls_direct_role_saves_through_the_gate_and_stops_the_sandbox(ssh):
    eng, gid = ssh
    D.enqueue(eng)
    Tools.sandbox = sb = FakeSandbox(_ssh_event)
    bad = {**RULE, "extract": [{"ruby": {"code": "x"}}]}
    fake = FakeClient([
        {"tool": "ls_samples", "input": {"group": gid}},
        {"tool": "save_lsfilter", "input": {"group": gid, "rule": bad, "labels": {}}},
        {"tool": "save_lsfilter", "input": {"group": "another", "rule": RULE,
                                            "labels": {"vendor": "OpenBSD", "product": "OpenSSH"}}},
    ])
    h = Harness(eng, client=fake)
    rep = learn(h, ["ls-direct"], limit=1, longtail_model="m")
    assert rep["ls-direct"]["saved"] == 1, rep
    assert eng.snap.rule("lsfilter:" + gid) is not None
    refused = json.loads(fake.requests[2]["messages"][4]["content"][0]["content"])
    assert refused["saved"] is False and "one of" in refused["refused"]
    samples = json.loads(fake.requests[1]["messages"][2]["content"][0]["content"])
    assert samples["samples"][0]["header_fields"]["@timestamp"] and "untrusted" in samples["notice"]
    assert "Rule language reference" not in fake.requests[0]["system"]      # Variant B has its own prompt
    assert "audit" not in rep and not h.touched                              # the engine audit is not for B
    assert sb.stopped == 1


# ------------------------------------------------------------------ a real Logstash (slow; skipped without one)
LOGSTASH = "/opt/homebrew/bin/logstash"


@pytest.mark.skipif(not os.path.exists(LOGSTASH) or os.environ.get("LP_SKIP_LOGSTASH"),
                    reason="needs a local Logstash")
def test_real_sandbox(ssh, tmp_path):
    from logparser.sandbox import Sandbox
    eng, gid = ssh
    sb = Sandbox(str(tmp_path / "sb"), http_port=18091, api_port=9621)
    Tools.sandbox = sb
    try:
        t = Tools(eng, "test")
        res = t.test_lsfilter(gid, RULE, {"vendor": "OpenBSD", "product": "OpenSSH"})
        assert res["would_save"], res
        ev = res["first_event"]
        assert ev["src_endpoint"]["port"] == 3001 and ev["class_uid"] == 3002 and ev["status"] == "Failure"
        res = t.test_lsfilter(gid, {**RULE, "extract": [{"grok": {"patterns": ["%{NO_SUCH_PATTERN:x}"]}}]})
        assert not res["ok"] and "NO_SUCH_PATTERN" in res["error"]
    finally:
        sb.stop()
        Tools.sandbox = None


@pytest.mark.parametrize("bad, words", [
    ({"map": [{"to": "user.name", "value": "${ANTHROPIC_API_KEY}"}]}, "environment"),
    ({"extract": [{"grok": {"patterns": ["x\\"]}}]}, "backslash"),
    ({"extract": [{"grok": {"patterns": ["a\nb"]}}]}, "line breaks"),
    ({"extract": [{"dissect": {"mapping": "%{+[ocsf][class_uid]} %{*k}=%{&k}"}}]}, "plain field names"),
    ({"extract": []}, "1 to"),
    ({"extract": [{"grok": {"patterns": ["x"], "when": {"field": "a", "exists": True}}}]}, "first extract step"),
    ({"extract": [{"grok": 5}]}, "options are an object"),
    ({"map": [{"to": "user.name", "from": "u", "translate": {"a": {"b": 1}}}]}, "translate"),
])
def test_review_injection_cases_are_refused(bad, words):
    body = {**RULE, **bad}
    with pytest.raises(D.FilterError, match=words):
        D.validate(body, SCHEMA)
        D.render_steps(body)


def test_missing_mapped_field_and_skipped_steps_fail():
    out = {"ocsf": GOOD_EVENT, "sb": {"t": "x", "f": {"user": "root", "src_ip": "173.234.31.1"}}}
    probs = D.judge(SCHEMA, _det(), SSH[0], out, RULE)
    assert any("`src_port`" in p and "missing" in p for p in probs)
    txt = D.render_steps({**RULE, "extract": [{"grok": {"patterns": ["x"]}}, {"kv": {"field": "rest"}}]})
    assert 'add_tag => ["_lp_nofield"]' in txt and "_lp_noextract" in txt and "timeout_millis => 1000" in txt
    assert "_lp_noextract" in D.FAIL_COND and "_lp_nofield" in D.FAIL_TAG_LIST
    _, rest = D.render_parts(RULE, SCHEMA, {}, "g", "T")
    assert 'event.tag(\\"lp_unparsed\\")' in rest or "lp_unparsed" in rest          # a failed date is not ingest time


def test_sandbox_environment_has_no_secrets(monkeypatch):
    from logparser import sandbox
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    assert "ANTHROPIC_API_KEY" not in sandbox.ENV_KEEP and all("KEY" not in k for k in sandbox.ENV_KEEP)


def test_deploy_check_passes_a_good_event_without_parsed_fields(ssh):
    """The deploy run has no [@metadata] (so no parsed fields): field checks must not count that as missing."""
    eng, gid = ssh
    registry.save_rule(eng.store, "lsfilter:" + gid, RULE)
    eng.reload()
    lines = D.verify_lines(eng, {gid}, per_group=8)
    mine = [l for l in lines if l["expect"] == gid]
    assert mine
    now = 1795000000000
    events = {}
    for l in mine:
        ev = _ssh_event({"payload": l["raw"].split(": ", 1)[1]})
        events[l["id"]] = {"ocsf": ev["ocsf"], "lp": {"group_id": gid}, "tags": []}
    res = D.verify_judge(eng, lines, events, {gid}, now)
    assert res["exclude"] == {} and res["counts"]["ok"] == len(mine), res
    events[mine[0]["id"]]["ocsf"] = {**events[mine[0]["id"]]["ocsf"], "time": now}      # ingest time
    assert gid in D.verify_judge(eng, lines, events, {gid}, now)["exclude"]


@pytest.mark.skipif(not os.path.exists(LOGSTASH) or os.environ.get("LP_SKIP_LOGSTASH"),
                    reason="needs a local Logstash")
def test_every_plugin_renders_to_config_logstash_loads(tmp_path):
    """Each extract kind, with its options, as Logstash really loads it (a bad option fails the reload)."""
    from logparser.sandbox import Sandbox, tables_for
    sb = Sandbox(str(tmp_path / "sb"), http_port=18092, api_port=9622)
    m = [{"to": "user.name", "from": "u"}, {"to": "status_id", "value": 1}, {"to": "activity_id", "value": 1},
         {"to": "service.name", "value": "x"}]
    cases = {
        "csv": ([{"csv": {"columns": ["u", "b"], "separator": ",", "quote_char": "'"}}], "bob,2"),
        "kv": ([{"kv": {"field_split": " ", "value_split": "=", "trim_value": "\"", "include_keys": ["u"],
                        "prefix": ""}}], 'u="bob" b=2'),
        "json": ([{"json": {}}], '{"u": "bob"}'),
        "dissect": ([{"dissect": {"mapping": "%{u} %{}"}}], "bob rest"),
        "grok": ([{"grok": {"patterns": ["^%{WORD:u}"], "pattern_definitions": {"X": "a+"}}}], "bob"),
        "xml": ([{"xml": {"xpath": {"/r/u/text()": "u"}}}], "<r><u>bob</u></r>"),
    }
    try:
        for name, (steps, payload) in cases.items():
            body = {"class": "authentication", "extract": steps, "map": m}
            D.validate(body, SCHEMA)
            res = sb.run(D.render_group(body, SCHEMA, {}, "g", "T_sb"), [{"id": 0, "payload": payload, "h": {}}],
                         tables_for(SCHEMA, "authentication"))
            assert "error" not in res, (name, res)
            ev = res["events"][0]
            got = (ev.get("ocsf") or {}).get("user", {}).get("name")
            assert got in ("bob", ["bob"]), (name, ev.get("tags"), ev.get("sb"))
        bad = sb.run("csv { source => \"x\" tag_on_failure => [\"a\"] }", [{"id": 0, "payload": "a", "h": {}}], {})
        assert "Unknown setting" in bad["error"]
    finally:
        sb.stop()


def test_list_attributes_are_wrapped_by_code():
    body = {"class": "incident_finding", "extract": [{"json": {}}],
            "map": [{"to": "finding_info_list.title", "from": "t"}, {"to": "finding_info_list.uid", "from": "id"},
                    {"to": "status_id", "value": 1}, {"to": "activity_id", "value": 1}]}
    D.validate(body, SCHEMA)
    assert D.array_paths(body, SCHEMA) == [["finding_info_list"]]
    _, rest = D.render_parts(body, SCHEMA, {}, "g", "T")
    assert '[["finding_info_list"]].each' in rest
    assert D.array_paths(RULE, SCHEMA) == []


def test_json_payload_needs_the_json_step(tmp_path):
    eng = make(tmp_path)
    feed(eng, tmp_path, ['{"user": "u%d", "src": "10.0.0.%d", "act": "login"}' % (i, i) for i in range(8)])
    gid = next(g["signature"] for g in eng.groups.values() if g["count"] == 8)
    Tools.sandbox = FakeSandbox(lambda r: {"ocsf": GOOD_EVENT, "sb": {"t": 1}})
    try:
        res = Tools(eng, "t").test_lsfilter(gid, {**RULE, "extract": [{"grok": {"patterns": ["\"user\": \"%{WORD:user}\""]}}]})
        assert not res["ok"] and "JSON object" in res["error"] and not Tools.sandbox.calls
    finally:
        Tools.sandbox = None
