"""Unit tests for the Logstash compiler: pattern conversion, strftime -> Joda, a small compile
snapshot.  None of them starts a JVM.  One slow end-to-end test runs only with LS_SLOW=1."""
import os
import re

import pytest

from logparser import logstash as L
from logparser import registry
from logparser.config import Settings
from logparser.engine import Engine
from logparser.ocsf import Schema
from logparser.store import SqliteStore

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCHEMA = Schema()


# ---------------------------------------------------------------- pattern conversion
def test_named_groups_and_anchors():
    out = L.re2_to_onig(r"^Failed password for (?P<user>\S+) from (?P<ip>\S+)$")
    assert out == r"\AFailed password for (?<user>\S+) from (?<ip>\S+)\z"


def test_capture_names_can_be_rewritten_for_grok():
    out = L.re2_to_onig(r"^(?P<a>\d+)$", cap=lambda n: f"[@metadata][s][f][{n}]", grok=True)
    assert out == r"\A(?<[@metadata][s][f][a]>\d+)\z"


def test_quotes_dollar_and_percent_are_hex_escaped_for_grok():
    out = L.re2_to_onig(r'^msg="(?P<m>[^"]*)" \$x 100%$', grok=True)
    assert '"' not in out and "'" not in out and "%" not in out and "$" not in out
    assert r"\x22" in out and r"\x25" in out and r"\x24" in out
    assert out.endswith(r"\z")


def test_dollar_and_caret_inside_a_class_stay_literal():
    assert L.re2_to_onig(r"^[$^a]+$") == r"\A[$^a]+\z"


def test_literal_open_bracket_inside_class_is_escaped():
    assert L.re2_to_onig(r"[[]x[^]]") == r"[\[]x[^\]]"


def test_posix_class_survives():
    assert L.re2_to_onig(r"^[[:alpha:]]+$") == r"\A[[:alpha:]]+\z"


def test_dotall_flag_is_renamed_and_unsupported_flags_refused():
    assert L.re2_to_onig(r"(?s)^a.b$") == r"(?m)\Aa.b\z"
    with pytest.raises(L.Unsupported):
        L.re2_to_onig(r"(?U)a+")
    with pytest.raises(L.Unsupported):
        L.re2_to_onig(r"\Qa.b\E")


def test_hex_codepoint_escape():
    assert L.re2_to_onig(r"\x{1F600}") == r"\u{1F600}"


def test_converted_pattern_matches_like_the_original():
    import re2
    pat = r'^(?P<ts>\d{4}-\d\d-\d\d) "(?P<w>[^"]+)" (?:ok|fail)$'
    ruby_like = L.re2_to_onig(pat).replace(r"\A", "^").replace(r"\z", "$").replace("(?<", "(?P<")
    for text in ['2026-01-02 "x y" ok', '2026-01-02 "x y" nope']:
        assert bool(re2.compile(pat).search(text)) == bool(re.search(ruby_like, text))


# ---------------------------------------------------------------- strftime -> Joda
@pytest.mark.parametrize("fmt,joda", [
    ("%Y-%m-%d %H:%M:%S", "yyyy-MM-dd HH:mm:ss"),
    ("%d/%b/%Y:%H:%M:%S %z", "dd/MMM/yyyy:HH:mm:ss Z"),
    ("%b %d %H:%M:%S", "MMM dd HH:mm:ss"),
    ("%Y-%m-%dT%H:%M:%S", "yyyy-MM-dd'T'HH:mm:ss"),
    ("%I:%M %p", "hh:mm a"),
    ("%m/%d/%Y %I:%M:%S %p", "MM/dd/yyyy hh:mm:ss a"),
    ("%A, %B %d", "EEEE, MMMM dd"),
    ("%Y%m%d", "yyyyMMdd"),
    ("%Y-%m-%d %H:%M:%S.%f", "yyyy-MM-dd HH:mm:ss.SSS"),
    ("at %H", "'at' HH"),
])
def test_strptime_to_joda(fmt, joda):
    assert L.strptime_to_joda(fmt) == joda


def test_strptime_unknown_directive_refused():
    with pytest.raises(L.Unsupported):
        L.strptime_to_joda("%Q")


# ---------------------------------------------------------------- literals
def test_ruby_literals_are_safe_for_single_quoted_config_strings():
    s = L.rb({"a'b": ["x#{y}", "${HOME}", 3, 1.5, True, None]})
    assert "'" not in s and "#{" not in s and "${" not in s
    assert s.startswith('{"a\\x27b" =>')


def test_config_string_quoting():
    assert L.cstr("abc") == '"abc"'
    assert L.cstr('a"b') == "'a\"b'"
    with pytest.raises(L.Unsupported):
        L.cstr("a${b}")
    with pytest.raises(L.Unsupported):
        L.cstr("a\"b'c")
    with pytest.raises(L.Unsupported):
        L.cstr("ends\\")


def test_ruby_library_has_no_single_quotes():
    from logparser.logstash_rb import RUBY_LIB
    assert "'" not in RUBY_LIB


def test_digests_agree_between_python_and_the_documented_formula():
    import hashlib
    assert L.dig("x") == hashlib.sha1(b"x").hexdigest()[:16]
    assert L.sig_digest("json", ["a", "b"], ["t=1"], "") == hashlib.sha1("json\x1fa\x1eb\x1ft=1\x1f".encode()).hexdigest()[:16]


# ---------------------------------------------------------------- compile snapshot
def make_engine(tmp_path):
    store = SqliteStore(str(tmp_path / "t.db"))
    registry.import_rules(store, os.path.join(ROOT, "registry", "builtin.json"))
    eng = Engine(store, Settings(group_threshold=3), schema=SCHEMA, now=1767225600.0)
    return eng


def add_group(eng):
    store = eng.store
    registry.save_rule(store, "parser:t1", {
        "kind": "regex",
        "pattern": r"^Failed password for (?P<user>\S+) from (?P<src_ip>\S+) port (?P<src_port>\d+) ssh2$"})
    registry.save_rule(store, "mapping:t1", {
        "class": "authentication",
        "constants": {"activity_id": 1, "status_id": 2, "severity_id": 1, "service.name": "sshd"},
        "fields": [
            {"to": "user.name", "from": "user", "confidence": "high", "note": "n"},
            {"to": "src_endpoint.ip", "from": "src_ip", "confidence": "high", "note": "n"},
            {"to": "src_endpoint.port", "from": "src_port", "confidence": "high", "note": "n"},
            {"to": "time", "from": "@timestamp", "transform": {"fn": "parse_timestamp"}, "confidence": "medium",
             "note": "n"},
            {"to": "message", "from": "msg", "transform": {"fn": "enum_lookup", "args": {"map": {"a": "A"}, "default": "Z"}},
             "confidence": "low", "note": "n"},
        ]})
    eng.reload()
    g = {"signature": "g1", "bucket": "syslog3164>unstructured|sshd", "source": "ssh|syslog3164>unstructured|sshd",
         "format": "unstructured", "template": "t", "detail": {}, "count": 5, "first_batch": 0, "last_batch": 0,
         "status": "mapped", "parser_rule": "parser:t1", "mapping_rule": "mapping:t1", "merged_into": None,
         "drift_of": None, "labels": {"vendor": "OpenBSD", "product": "OpenSSH"}, "parse_failures": 0,
         "_samples": None, "_tokens": None, "_stats": None}
    eng.groups["g1"] = g
    return g


def test_compile_snapshot(tmp_path):
    eng = make_engine(tmp_path)
    add_group(eng)
    comp = L.Compiler(eng)
    gen = comp.compile()
    assert gen.stats["leaves"] == 1 and gen.stats["sources"] == 1
    assert gen.pipelines == ["distributor", "src_ssh", "sink"]
    src = gen.files["src_ssh.filter"]
    # the parser is a grok with inline captures into the field namespace
    assert r"(?<[@metadata][s][f][user]>\S+)" in src and "timeout_millis => 1000" in src
    # simple moves are native renames, the status constant is a typed constant, no ruby entry for them
    assert '"[@metadata][s][f][user]" => "[ocsf][user][name]"' in src
    assert '"[ocsf][status_id]" => "integer"' in src
    # enum_lookup with a map is a translate; time and the integer port need typed handling
    assert "translate { source" in src
    assert 'LP.tr(v, "parse_timestamp"' in src
    leaf = comp.leaves["g1"]
    assert leaf.status == "ok" and leaf.native >= 4 and leaf.ruby >= 1


def test_excluded_group_is_not_compiled(tmp_path):
    eng = make_engine(tmp_path)
    add_group(eng)
    gen = L.Compiler(eng).compile(include=set())
    assert gen.stats["leaves"] == 0 and gen.pipelines == ["distributor", "sink"]
    assert "src_ssh" not in "".join(gen.files)


def test_write_set_layout_and_pipelines_yml(tmp_path):
    eng = make_engine(tmp_path)
    add_group(eng)
    gen = L.Compiler(eng).compile()
    out = tmp_path / "gen"
    files = L.write_set(gen, str(out), root=ROOT)
    assert {"distributor.conf", "src_ssh.conf", "sink.conf", "pipelines.yml"} <= set(files)
    assert 'port => 8088' in files["distributor.conf"] and "codec => line" in files["distributor.conf"]
    assert 'pipeline { send_to => ["src_ssh"] }' in files["distributor.conf"]
    assert "logs.ocsf_events" in files["sink.conf"] and "logs.unparsed" in files["sink.conf"]
    assert "lp_unparsed" in files["src_ssh.conf"]
    yml = files["pipelines.yml"]
    assert str(out / "src_ssh.conf") in yml and yml.count("pipeline.id") == 3
    text = L.compile_pipeline(eng)
    assert "LP.bucket" in text and 'if [@metadata][dest] == "src_ssh"' in text


# ---------------------------------------------------------------- slow end to end
@pytest.mark.skipif(os.environ.get("LS_SLOW") != "1", reason="needs Logstash and the trained database; set LS_SLOW=1")
def test_end_to_end_verified_groups_agree(tmp_path):
    import subprocess
    import sys
    db = os.path.join(ROOT, "work", "logstash", "ls.db")
    if not os.path.exists(db):
        pytest.skip("work/logstash/ls.db missing")
    r = subprocess.run([sys.executable, os.path.join(ROOT, "scripts", "ls_verify.py"), db, str(tmp_path), "--mixed", "300",
                        "--per-group", "2"], capture_output=True, text=True, timeout=1800)
    assert r.returncode == 0, r.stderr[-2000:]
    import json
    rep = json.load(open(tmp_path / "report.json"))
    last = rep["passes"][-1]["verdicts"]
    assert last.get("disagree", 0) == 0 and last.get("misrouted", 0) == 0 and last.get("overreach", 0) == 0
