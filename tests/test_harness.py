"""The agent loop, driven by a scripted fake model (no network)."""
import json
import types

import pytest

from logparser.harness import Harness
from tests.test_engine import SSH, feed, make


def block(**kw):
    return types.SimpleNamespace(**kw)


class FakeClient:
    """Stands in for anthropic.Anthropic(): replays scripted tool calls."""

    def __init__(self, script):
        self.script = list(script)
        self.requests = []
        self.beta = types.SimpleNamespace(messages=types.SimpleNamespace(create=self._create))

    def _create(self, **kw):
        self.requests.append(kw)
        step = self.script.pop(0) if self.script else {"text": "FLAG: out of ideas"}
        usage = types.SimpleNamespace(input_tokens=100, output_tokens=20, cache_read_input_tokens=0,
                                      cache_creation_input_tokens=0)
        if "text" in step:
            return types.SimpleNamespace(stop_reason="end_turn", usage=usage,
                                         content=[block(type="text", text=step["text"])])
        return types.SimpleNamespace(stop_reason="tool_use", usage=usage, content=[
            block(type="tool_use", id=f"t{len(self.requests)}", name=step["tool"], input=dict(step["input"]))])


GOOD = {"kind": "regex", "pattern": r"^Failed password for (?P<user>\S+) from (?P<src_ip>\S+) port (?P<src_port>\d+) ssh2$"}


def test_loop_saves_through_the_gate(tmp_path):
    eng = make(tmp_path)
    feed(eng, tmp_path, SSH)
    key = eng.store.queue_items("needs-parser")[0]["key"]
    fake = FakeClient([
        {"tool": "get_samples", "input": {"group": key}},
        {"tool": "save_parser", "input": {"group": key, "rule": {"kind": "regex", "pattern": "^.*$"}, "labels": {}}},
        {"tool": "save_parser", "input": {"group": "some-other-group", "rule": GOOD,
                                          "labels": {"vendor": "OpenBSD", "product": "OpenSSH"}}},
    ])
    res = Harness(eng, client=fake).run_queue("parser-gen")
    assert res == [{"key": key, "saved": True, "reason": None}]
    # the refused save went back to the model as data, and the group id is pinned to the item
    second = json.loads(fake.requests[2]["messages"][4]["content"][0]["content"])
    assert second["saved"] is False and "captures nothing" in second["refused"]
    assert eng.store.q("SELECT COUNT(*) n FROM raw WHERE status='parsed'")[0]["n"] == 8
    first = fake.requests[0]
    assert first["model"] == "claude-opus-5-5" and first["fallbacks"] == "default"
    assert "untrusted" in first["system"] and first["thinking"] == {"type": "adaptive"}
    spend = eng.store.q("SELECT SUM(tokens_in) i, COUNT(*) n FROM tool_calls WHERE tool='model_call'")[0]
    assert spend["n"] == 3 and spend["i"] == 300


def test_loop_is_bounded_and_flags_for_a_human(tmp_path):
    eng = make(tmp_path)
    feed(eng, tmp_path, SSH)
    key = eng.store.queue_items("needs-parser")[0]["key"]
    fake = FakeClient([{"tool": "test_parser", "input": {"group": key, "rule": {"kind": "regex", "pattern": "^x$"}}}] * 50)
    res = Harness(eng, client=fake, max_iterations=5).run_queue("parser-gen")
    assert len(fake.requests) == 5 and res[0]["saved"] is False
    flagged = eng.store.queue_items("needs-parser", status="flagged")
    assert flagged[0]["key"] == key and "iteration limit" in flagged[0]["payload"]["flag_reason"]
    with pytest.raises(ValueError):
        Harness(eng, client=fake, max_iterations=50)


SSHD = {"vendor": "OpenBSD", "product": "OpenSSH", "match": {"bucket": r"\|sshd$", "text": r"^Failed password for "}}


def test_source_naming_role_names_the_source(tmp_path):
    eng = make(tmp_path)
    feed(eng, tmp_path, SSH)
    key = eng.store.queue_items("needs-source")[0]["key"]
    fake = FakeClient([
        {"tool": "get_samples", "input": {"source": "some-other-source", "limit": 5}},
        {"tool": "test_source", "input": {"rule": SSHD}},
        {"tool": "save_source", "input": {"rule": SSHD, "note": "sshd program name and message"}},
    ])
    h = Harness(eng, client=fake)
    res = h.run_queue("source-naming")
    assert res == [{"key": key, "saved": True, "reason": None}]
    # the source id is pinned to the item even when the model names another one
    got = json.loads(fake.requests[1]["messages"][2]["content"][0]["content"])
    assert got["source"] == key
    assert not eng.store.queue_items("needs-source")
    src = next(s for s in eng.store.sources() if s["source"] == key)
    assert (src["vendor"], src["product"]) == ("OpenBSD", "OpenSSH")
    assert "source_naming" not in fake.requests[0]["system"] and "Role: source naming" in fake.requests[0]["system"]


def test_budget_stops_new_items(tmp_path):
    eng = make(tmp_path)
    feed(eng, tmp_path, SSH)
    fake = FakeClient([{"text": "FLAG: cannot tell"}] * 10)
    h = Harness(eng, client=fake, budget_usd=0.000001)
    res = h.run_queue("parser-gen") + h.run_queue("source-naming")
    assert len(fake.requests) == 1 and len(res) == 1     # the first call spent the budget; nothing else started
    assert h.spent_usd == pytest.approx((100 * 4 + 20 * 20) / 1e6)
