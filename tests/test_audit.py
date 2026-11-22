"""Self-audit: events checked against their own lines, failures routed back to the agents."""
import json
import types

from logparser import audit, registry
from logparser.harness import Harness, learn
from tests.test_engine import PG, PG2, feed, make

PG3 = "2026-11-22 09:30:01.001 UTC [48100] [unknown]@[unknown] LOG:  connection received: host=10.20.7.7 port=40001"


def longtail_group(tmp_path, lines=(PG, PG2, PG3)):
    eng = make(tmp_path, group_threshold=50)
    feed(eng, tmp_path, list(lines))
    return eng, eng.store.queue_items("longtail")[0]["key"]


def save_direct(eng, rule_id, body):
    """Save a rule without its gate: stands in for a rule an older version of the code let through."""
    registry.save_rule(eng.store, rule_id, body, {"created_by": "test"})
    eng.reload()


def test_leak_from_one_sample_is_found_and_routed_with_feedback(tmp_path):
    eng, sig = longtail_group(tmp_path)
    save_direct(eng, "longtail:" + sig, {"fields": {}, "summary": "Connection received from host 10.20.9.56."})
    rep = audit.audit_group(eng, sig)
    assert rep["owner"] == "longtail" and rep["problems"]["leak"]["count"] == 2      # PG2 and PG3, not PG
    assert "10.20.9.56" in rep["problems"]["leak"]["examples"][0]["problem"]
    res = audit.run(eng, [sig], repair=False)
    assert res["routed"] == {"longtail": 1}
    item = eng.store.queue_items("longtail")[0]
    assert item["key"] == sig and item["payload"]["reported_by"] == "audit" and item["payload"]["audit_round"] == 1
    # the long-tail agent gets the feedback even though a rule exists for the group
    from logparser.tools import Tools
    batch = Tools(eng, "t").longtail_batch()["items"]
    assert batch[0]["signature"] == sig and "leak" in batch[0]["feedback"]["problem"]


def test_clean_group_passes(tmp_path):
    eng, sig = longtail_group(tmp_path)
    from logparser.tools import Tools
    Tools(eng, "t").save_longtail(sig, {"src_ip": "10.20.9.56", "timestamp": "2026-11-22 09:23:59.600 UTC"},
                                  "Connection received from host 10.20.9.56.")
    rep = audit.audit_group(eng, sig)
    assert rep["lines"] == 3 and rep["problems"] == {} and rep["owner"] is None


def test_value_not_in_line_is_found(tmp_path):
    eng, sig = longtail_group(tmp_path)
    save_direct(eng, "longtail:" + sig, {"fields": {"src_ip": {"parts": [2, " ZZZ"]}}})
    rep = audit.audit_group(eng, sig)
    assert rep["problems"]["value"]["count"] == 3
    assert "ZZZ" in rep["problems"]["value"]["examples"][0]["problem"]


def test_rule_not_applied_to_its_own_group_goes_to_a_human(tmp_path):
    eng, sig = longtail_group(tmp_path)
    save_direct(eng, "longtail:" + sig, {"fields": {}, "summary": "Connection received."})
    save_direct(eng, "mapping:" + sig, {"class": "base_event", "fields": [], "unmapped": "rest"})
    rep = audit.audit_group(eng, sig)          # the group was created before the mapping existed
    assert rep["owner"] == "code" and "unapplied" in rep["problems"]
    assert audit.route(eng, rep) == "human-review"
    hr = eng.store.queue_items("human-review")
    assert hr[0]["key"] == "audit:" + sig and "code problem" in hr[0]["payload"]["question"]


def test_rounds_count_agent_attempts_not_audits(tmp_path):
    eng, sig = longtail_group(tmp_path)
    save_direct(eng, "longtail:" + sig, {"fields": {}, "summary": "Connection received from host 10.20.9.56."})
    rep = audit.audit_group(eng, sig)
    # auditing again and again while the item still waits uses no round
    assert [audit.route(eng, rep, max_rounds=2) for _ in range(5)] == ["longtail"] * 5
    assert eng.store.get_state("audit_rounds:" + sig) == 1
    went = []
    for _ in range(2):                       # the agent works the item twice and fails twice
        eng.store.queue_done("longtail", sig)
        went.append(audit.route(eng, rep, max_rounds=2))
    assert went == ["longtail", "human-review"]
    assert eng.store.queue_items("longtail") == []          # the agent's copy is closed: nobody pays for it again
    # a human resolves it; later audits never reopen it
    eng.store.queue_done("human-review", "audit:" + sig)
    assert audit.route(eng, rep, max_rounds=2) == "human-review"
    assert eng.store.queue_items("human-review") == []


def test_round_count_survives_other_writers_of_the_queue(tmp_path):
    eng, sig = longtail_group(tmp_path)
    save_direct(eng, "longtail:" + sig, {"fields": {}, "summary": "Connection received from host 10.20.9.56."})
    rep = audit.audit_group(eng, sig)
    audit.route(eng, rep)
    eng.store.reopen("longtail", sig, {"signature": sig})      # e.g. the engine re-queues it without audit info
    eng.store.queue_done("longtail", sig)
    audit.route(eng, rep)
    assert eng.store.get_state("audit_rounds:" + sig) == 2


def test_code_repairs_what_it_can_before_any_model(tmp_path):
    eng, sig = longtail_group(tmp_path)
    save_direct(eng, "longtail:" + sig, {"fields": {}, "summary": "Connection received from host 10.20.9.56."})
    res = audit.run(eng, [sig])
    assert res["fixed_by_code"] == 1 and res["groups_failing"] == 0 and res["routed"] == {}
    assert [i for i in eng.store.queue_items("longtail") if i["payload"].get("reported_by") == "audit"] == []
    msgs = sorted(json.loads(r["ocsf"])["message"] for r in eng.store.q("SELECT ocsf FROM events"))
    assert msgs[0] == "Connection received from host 10.20.1.24."


def test_fix_round_uses_only_the_agents_the_caller_chose(tmp_path, monkeypatch):
    eng, sig = longtail_group(tmp_path)
    calls = iter([{"failing": [{"signature": sig, "sent_to": "needs-mapping"}], "groups_checked": 1,
                   "groups_failing": 1, "lines_checked": 3, "by_check": {"value": 3}, "routed": {"needs-mapping": 1},
                   "fixed_by_code": 0}])
    monkeypatch.setattr(audit, "run", lambda *a, **k: next(calls))
    fake = FakeLongtail({"fields": {}, "summary": "x"})
    h = Harness(eng, client=fake, budget_usd=1.0)
    h.touched = {sig}
    report = learn(h, ["longtail"], 10, "claude-sonnet-5-5", fix_rounds=1)
    assert not any(k.startswith("fix") for k in report)
    assert all("tools" not in r for r in fake.requests)      # no agent-loop (mapping) call, only the long tail


def test_present_and_leak_edge_cases():
    assert not audit._present("ok", "token=book") and audit._present("ok", "status=OK done")
    assert audit._present("GET", "get /x") and not audit._present("GET", "target=x")
    assert audit._present("a\nb", '{"m":"a\\nb"}') or audit._present("a\nb", 'x a\nb')
    assert audit._tokens("Host WEB01.") == {"host", "web01"}
    assert audit._tokens('pulled \\"busybox:1.36\\"') == {"pulled", "busybox", "1.36"}     # JSON-escaped quotes


class FakeLongtail:
    """Stands in for anthropic.Anthropic() on the long-tail path; records the requests."""

    def __init__(self, answer):
        self.answer, self.requests = answer, []
        self.messages = types.SimpleNamespace(create=self._create)
        self.beta = types.SimpleNamespace(messages=types.SimpleNamespace(create=self._create))

    def _create(self, **kw):
        self.requests.append(kw)
        lines = json.loads(kw["messages"][0]["content"].split("\n", 1)[1])
        items = [dict(self.answer, signature=x["signature"]) for x in lines]
        usage = types.SimpleNamespace(input_tokens=100, output_tokens=50, cache_read_input_tokens=0,
                                      cache_creation_input_tokens=0)
        return types.SimpleNamespace(stop_reason="end_turn", usage=usage,
                                     content=[types.SimpleNamespace(type="text", text=json.dumps({"items": items}))])


def test_learn_loop_audits_sends_back_and_the_fixed_rule_passes(tmp_path):
    eng, sig = longtail_group(tmp_path)
    save_direct(eng, "longtail:" + sig, {"fields": {}, "summary": "Connection received from host 10.20.9.56."})
    fake = FakeLongtail({"fields": {"src_ip": "10.20.9.56"}, "summary": "Connection received from host 10.20.9.56."})
    h = Harness(eng, client=fake, budget_usd=1.0)
    h.touched = {sig}                              # as if an agent had just saved this rule
    report = learn(h, ["longtail"], 10, "claude-sonnet-5-5", fix_rounds=1, repair=False)
    assert report["audit"]["groups_failing"] == 1 and report["audit"]["routed"] == {"longtail": 1}
    assert report["fix 1: longtail"]["saved"] == 1
    assert report["audit 2"]["groups_failing"] == 0          # the rule saved in the fix round holds on every line
    sent = json.loads(fake.requests[0]["messages"][0]["content"].split("\n", 1)[1])
    assert sent[0]["feedback"]["other_lines"]                # the agent saw what was wrong
    msgs = sorted(json.loads(r["ocsf"])["message"] for r in eng.store.q("SELECT ocsf FROM events"))
    assert msgs == ["Connection received from host 10.20.1.24.", "Connection received from host 10.20.7.7.",
                    "Connection received from host 10.20.9.56."]


def test_audit_only_when_fix_rounds_is_zero(tmp_path):
    eng, sig = longtail_group(tmp_path)
    save_direct(eng, "longtail:" + sig, {"fields": {}, "summary": "Connection received from host 10.20.9.56."})
    fake = FakeLongtail({"fields": {}, "summary": "x"})
    h = Harness(eng, client=fake, budget_usd=1.0)
    h.touched = {sig}
    report = learn(h, ["longtail"], 10, "claude-sonnet-5-5", fix_rounds=0, repair=False)
    assert report["audit"]["groups_failing"] == 1 and fake.requests == []      # no model call, no spend
