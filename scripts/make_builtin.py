"""Authoring helper: writes registry/builtin.json.

The JSON file is what the engine loads. This script exists only because long
regular expressions are easier to keep correct in Python raw strings than in
hand-escaped JSON. These are the generic, vendor-neutral rules; vendor rules
are in registry/seeds/.
"""
from __future__ import annotations

import json
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
META = {"created_by": "builtin", "source": "this project", "license": "project licence"}

MON = r"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)"
DAY = r"(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)"
TS3164 = MON + r" {1,2}\d{1,2}(?: \d{4})? \d\d:\d\d:\d\d(?:\.\d+)?"
ISO = r"\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d(?:[.,]\d+)?(?:Z|[+-]\d\d:?\d\d)?"
HOST = r"[A-Za-z0-9][A-Za-z0-9._\-:]*"
PRI = r"(?:<(?P<pri>\d{1,3})>)?"
HEADER_PREFIX = [
    r"^(?:\[[^\]]{1,40}\])*\s*" + PRI + r"(?:\d+: )?(?P<timestamp>" + TS3164 + "|" + ISO + r")(?: (?P<host>" + HOST
    + r"))?(?: (?P<proc>[^\s\[:]+)(?:\[(?P<pid>\d+)\])?)?",
    r"^<(?P<pri>\d{1,3})>(?P<version>\d{1,2}) (?P<timestamp>\S+) (?P<host>\S+)",
    r"^<(?P<pri>\d{1,3})>",
]
SD = r'(?:\[(?:[^\]\\"]|\\.|"(?:[^"\\]|\\.)*")*\])+'

rules = []


def add(rule_id, body, note=""):
    meta = dict(META)
    if note:
        meta["note"] = note
    rules.append({"rule_id": rule_id, "body": body, "meta": meta})


add("framing:default", {
    "continuation": [r"^\s+at [\w.$<>]+\(", r"^Caused by: ", r"^\s+\.\.\. \d+ more", r'^\s{2,}File "'],
    "multiline_json": True, "multiline_xml": True, "octet_counting": True, "max_record_lines": 500,
}, "Java and Python stack traces, pretty-printed JSON and XML, RFC 6587 octet counting")

add("directive:w3c", {"pattern": r"^#Fields: (?P<fields>.+)$", "field_sep": " ", "delimiter": " ",
                      "drop_pattern": r"^#[A-Za-z_]+(?:: |\t| \\x)"}, "W3C extended log format header")
add("directive:zeek-tsv", {"pattern": r"^#fields\t(?P<fields>.+)$", "field_sep": "\t", "delimiter": "\t",
                           "drop_pattern": r"^#[A-Za-z_]+(?:: |\t| \\x)"}, "Zeek TSV header")

# ---------------------------------------------------------------- detection
det = []


def check(order, name, typ, test, **kw):
    det.append({"order": order, "name": name, "type": typ, "test": test, **kw})


check(0, "binary", "format", {"kind": "binary", "max_nonprintable": 0.1}, format="binary")
check(3, "json_wrap", "envelope", {"kind": "json_wrap", "fields": ["message", "msg", "log", "raw", "_raw", "line"],
                                   "max_keys": 6})
check(4, "embedded_json", "format", {"kind": "regex", "pattern":
      r'^(?P<prefix>[^{]{1,300}?)(?P<payload>\{\s*".*\})\s*$'},
      format="json", header_patterns={"prefix": HEADER_PREFIX})
check(5, "json", "format", {"kind": "json"}, format="json")
check(6, "xml", "format", {"kind": "xml"}, format="xml")
check(10, "cef", "format", {"kind": "regex", "pattern":
      r"^(?P<prefix>.*?)(?P<payload>CEF: ?\d+\|(?P<vendor>[^|]*)\|(?P<product>[^|]*)\|.*)$"},
      format="cef", app=["vendor", "product"], header_patterns={"prefix": HEADER_PREFIX})
check(11, "leef", "format", {"kind": "regex", "pattern":
      r"^(?P<prefix>.*?)(?P<payload>LEEF: ?\d(?:\.\d)?\|(?P<vendor>[^|]*)\|(?P<product>[^|]*)\|.*)$"},
      format="leef", app=["vendor", "product"], header_patterns={"prefix": HEADER_PREFIX})
check(15, "cisco", "envelope", {"kind": "regex", "pattern":
      r"^(?P<prefix>.*?)%(?P<cisco_facility>[A-Z][A-Z0-9_]{1,20})-(?P<cisco_severity>[0-7])-"
      r"(?P<cisco_mnemonic>[A-Z0-9_]{2,40}): ?(?P<payload>.*)$"},
      app=["cisco_facility", "cisco_mnemonic"], header_patterns={"prefix": HEADER_PREFIX})
check(19, "syslog5424_event", "envelope", {"kind": "regex", "pattern":
      r"^<(?P<pri>\d{1,3})>(?P<version>\d{1,2}) (?P<timestamp>\S+) (?P<host>\S+) (?P<app>\S+) (?P<procid>\S+) "
      r"(?P<msgid>[A-Za-z]\S*) (?P<payload>" + SD + r")(?: (?P<message>.*))?$"}, app=["app", "msgid"])
check(20, "syslog5424", "envelope", {"kind": "regex", "pattern":
      r"^<(?P<pri>\d{1,3})>(?P<version>\d{1,2}) (?P<timestamp>\S+) (?P<host>\S+) (?P<app>\S+) (?P<procid>\S+) "
      r"(?P<msgid>\S+) (?:-|(?P<sd>" + SD + r")) ?(?P<payload>.*)$"}, app=["app"], payload_fallback="sd")
check(21, "syslog5424_short", "envelope", {"kind": "regex", "pattern":
      r"^<(?P<pri>\d{1,3})>(?P<version>\d{1,2}) (?P<timestamp>\d{4}-\S+) (?P<host>\S+) (?P<payload>[{\[].*)$"})
check(22, "syslog3164", "envelope", {"kind": "regex", "pattern":
      r"^" + PRI + r"(?P<timestamp>" + TS3164 + r") (?P<host>" + HOST
      + r") (?P<app>[^\s:\[\]]+)(?:\[(?P<pid>\d+)\])?:(?: (?P<payload>.*))?$"}, app=["app"])
check(23, "syslog_iso", "envelope", {"kind": "regex", "pattern":
      r"^" + PRI + r"(?P<timestamp>\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:?\d\d)?) (?P<host>" + HOST
      + r") (?P<app>[^\s:\[\]]+)(?:\[(?P<pid>\d+)\])?:(?: (?P<payload>.*))?$"}, app=["app"])
check(24, "syslog3164_notag", "envelope", {"kind": "regex", "pattern":
      r"^" + PRI + r"(?P<timestamp>" + TS3164 + r") (?P<host>" + HOST + r") (?P<payload>.*)$"})
check(25, "syslog_ts_only", "envelope", {"kind": "regex", "pattern":
      r"^" + PRI + r"(?P<timestamp>" + TS3164 + r") (?P<payload>.*)$"})
check(26, "pri_tag", "envelope", {"kind": "regex", "pattern":
      r"^<(?P<pri>\d{1,3})> ?(?P<app>[A-Za-z_][\w\-./]*)(?:\[(?P<pid>\d+)\])?: (?P<payload>.*)$"}, app=["app"])
check(27, "pri_only", "envelope", {"kind": "regex", "pattern": r"^<(?P<pri>\d{1,3})>(?P<payload>[^\d].*)$"})
check(30, "ts_level", "envelope", {"kind": "regex", "pattern":
      r"^\[?(?P<timestamp>\d{4}-\d\d-\d\d[ T]\d\d:\d\d:\d\d(?:[.,]\d+)?(?:Z|[+-]\d\d:?\d\d)?)\]?,? +(?:- )?"
      r"\[?(?P<level>TRACE|DEBUG|INFO|NOTICE|WARN|WARNING|ERROR|ERR|FATAL|CRITICAL|Info|Warning|Error|Debug)\]?"
      r" +(?:- )?(?P<payload>.*)$"})
check(31, "bracket_ts", "envelope", {"kind": "regex", "pattern":
      r"^\[(?P<timestamp>\d{4}-\d\d-\d\d[T ][^\]]+)\] (?:(?P<level>[A-Z]) )?(?:(?P<app>[\w.\-]+): )?(?P<payload>.*)$"},
      app=["app"])
check(47, "kv_checkpoint", "format", {"kind": "kv", "dialect": "kv_colon", "min_pairs": 4, "min_coverage": 0.6},
      format="kv")
check(46, "kv_js", "format", {"kind": "kv", "dialect": "kv_js", "min_pairs": 4, "min_coverage": 0.6}, format="kv")
check(48, "kv_pipe", "format", {"kind": "kv", "dialect": "kv_pipe", "min_pairs": 4, "min_coverage": 0.6},
      format="kv")
check(50, "kv", "format", {"kind": "kv", "dialect": "kv_eq", "min_pairs": 4, "min_coverage": 0.55}, format="kv")
check(60, "csv", "format", {"kind": "delimited", "delimiter": ",", "min_fields": 8, "max_first_share": 0.3}, format="delimited")
check(61, "tsv", "format", {"kind": "delimited", "delimiter": "\t", "min_fields": 5}, format="delimited")
check(62, "psv", "format", {"kind": "delimited", "delimiter": "|", "min_fields": 6}, format="delimited")
for d in det:
    add(f"detect:{d['name']}", d)

add("dialect:kv_eq", {"mode": "pair", "pair_pattern":
    r"""(?:^|[\s,;|(\[{])(?P<k>[A-Za-z_][\w.\-]*)=(?:"(?P<q>(?:[^"\\]|\\.)*)"|'(?P<s>[^']*)'|(?P<v>[^\s"']*))"""},
    "key=value, key=\"quoted value\", key='quoted value'")
add("dialect:kv_colon", {"mode": "pair", "pair_pattern": r'(?P<k>[A-Za-z_][\w.\-]*)::?"(?P<q>(?:[^"\\]|\\.)*)"'},
    'key:"value"; pairs')
add("dialect:kv_pipe", {"mode": "span", "key_pattern": r"(?:^|\|)(?P<k>[A-Za-z_]\w*)=", "strip": " |"},
    "key=value|key=value")
add("dialect:kv_label", {"mode": "span", "key_pattern": r"(?:^|, )(?P<k>[A-Z][A-Za-z0-9_]*(?: [A-Za-z0-9_]+){0,4}): ",
                           "strip": " ,"}, "Label: value, Label: value (labels may contain spaces)")
add("dialect:kv_js", {"mode": "pair", "pair_pattern": r"(?:[{,]\s*)?(?P<k>[A-Za-z_]\w*):'(?P<s>.*?)'\s*[,}]"},
    "key:'value' pairs with unquoted keys (JavaScript-style object text)")
add("dialect:kv_lines", {"mode": "span", "key_pattern": r"(?:^|\n)(?P<k>[A-Za-z][A-Za-z0-9]*): ?", "strip": " \r\n\t"},
    "one `Key: value` per line inside a multi-line text field")
add("dialect:kv_span", {"mode": "span", "key_pattern": r"(?:^|\s)(?P<k>[A-Za-z_][\w.\-]*)=", "strip": " \t"},
    "key=value where values may contain spaces and run to the next key")

HEXD = "[0-9A-Fa-f]"
add("mask:default", {"scope": {"bucket": "*"}, "priority": 0, "mode": "extend", "patterns": [
    {"name": "dquoted", "pattern": r'"[^"]{0,400}"', "placeholder": "<STR>"},
    {"name": "squoted", "pattern": r"(?:^|[^A-Za-z0-9])('[^']{0,200}')", "placeholder": "<STR>", "group": 1},
    {"name": "iso_ts", "pattern": ISO, "placeholder": "<TS>"},
    {"name": "syslog_ts", "pattern": r"(?:" + DAY + r",? )?" + MON + r" +\d{1,2}(?: \d{4})? \d\d:\d\d:\d\d(?:\.\d+)?(?: \d{4}\b)?",
     "placeholder": "<TS>"},
    {"name": "clf_ts", "pattern": r"\d\d/" + MON + r"/\d{4}:\d\d:\d\d:\d\d(?: [+-]\d{4})?", "placeholder": "<TS>"},
    {"name": "date", "pattern": r"\b(?:\d{4}[-/]\d\d?[-/]\d\d?|\d\d?/\d\d?/\d{2,4})\b", "placeholder": "<DATE>"},
    {"name": "time", "pattern": r"\b\d{1,2}:\d{1,2}:\d{1,2}(?:[.,:]\d+)?(?: ?[AP]M\b)?", "placeholder": "<TIME>"},
    {"name": "uuid", "pattern": rf"\b{HEXD}{{8}}-{HEXD}{{4}}-{HEXD}{{4}}-{HEXD}{{4}}-{HEXD}{{12}}\b",
     "placeholder": "<UUID>"},
    {"name": "mac", "pattern": rf"\b(?:{HEXD}{{2}}[:-]){{5}}{HEXD}{{2}}\b", "placeholder": "<MAC>"},
    {"name": "ipv6", "pattern": rf"\b(?:{HEXD}{{1,4}}:){{2,7}}{HEXD}{{1,4}}\b|\b(?:{HEXD}{{1,4}}:){{1,6}}:(?:{HEXD}{{1,4}}\b)?"
     rf"|::(?:{HEXD}{{1,4}}:){{0,5}}{HEXD}{{1,4}}\b", "placeholder": "<IP>"},
    {"name": "ipv4", "pattern": r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", "placeholder": "<IP>"},
    {"name": "url", "pattern": r"""\b[a-z][a-z0-9+.\-]*://[^\s"'<>\])]+""", "placeholder": "<URL>"},
    {"name": "email", "pattern": r"\b[\w.+\-]+@[\w\-]+(?:\.[\w\-]+)+\b", "placeholder": "<EMAIL>"},
    {"name": "path", "pattern": r"(?:\b[A-Za-z]:)?(?:[/\\][\w.\-$@+~%]+){2,}[/\\]?", "placeholder": "<PATH>"},
    {"name": "hex0x", "pattern": rf"\b0[xX]{HEXD}+\b", "placeholder": "<HEX>"},
    {"name": "id", "pattern": r"\b[A-Za-z]+(?:[_\-][A-Za-z]+)*[_\-]-?[0-9a-fA-F]*\d[\w\-]*\b", "placeholder": "<ID>"},
    {"name": "num", "pattern": r"-?\b\d+(?:\.\d+)?\b", "placeholder": "<NUM>"},
    {"name": "hex", "pattern": rf"\b{HEXD}{{8,}}\b", "placeholder": "<HEX>"},
]}, "Variables the spec names: timestamps, IPs, numbers, hex, UUIDs, quoted strings; plus MAC, URL, email, paths")

add("words:protected", {"words": [
    "accepted", "accept", "allowed", "allow", "permitted", "permit", "granted", "grant", "passed", "pass",
    "succeeded", "success", "successful", "authenticated", "authorized", "opened", "open", "started", "start",
    "connected", "connect", "established", "built", "created", "create", "added", "add", "enabled", "enable",
    "login", "logon", "logged in",
    "failed", "fail", "failure", "denied", "deny", "blocked", "block", "rejected", "reject", "dropped", "drop",
    "refused", "refuse", "forbidden", "invalid", "unauthorized", "error", "timeout", "expired", "locked",
    "closed", "close", "stopped", "stop", "disconnected", "disconnect", "terminated", "teardown", "deleted",
    "delete", "removed", "remove", "disabled", "disable", "logout", "logoff", "logged out",
    "detected", "quarantined", "cleaned", "alert", "warning", "critical", "modified", "changed", "updated"]},
    "Outcome and action words: never masked, never merged away, and a field holding one marks the event type")
add("sign:default", {"scope": {"bucket": "*"}, "priority": 0, "keys": "auto", "depth": 1, "text": True,
                     "discriminators": ["type", "subtype", "event_type", "eventType", "eventName", "EventID",
                                        "event_simpleName", "log_type", "log_subtype", "Operation", "@msgid"]},
    "Structured records: top-level key set plus common event-type keys")

add("mapping:default-base", {
    "class": "base_event", "unmapped": "rest",
    "fields": [
        {"to": "message", "from": ["message", "msg", "summary", "_text", "cef.name"], "confidence": "medium",
         "note": "first free-text field found"},
        {"to": "severity_id", "from": "@pri", "transform": {"fn": "syslog_severity", "args": {"from_pri": True}},
         "confidence": "high", "note": "syslog PRI severity bits"},
        {"to": "metadata.original_time", "from": "@timestamp", "confidence": "high", "note": "envelope timestamp"},
    ]}, "Fallback for groups with a parser but no class mapping yet: OCSF Base Event, all fields in unmapped")

add("mapping:longtail-base", {
    "class": "base_event", "unmapped": "rest",
    "fields": [
        {"to": "message", "from": "summary", "confidence": "medium",
         "note": "one-line summary written by the long-tail agent, filled with this line's values"},
        {"to": "time", "from": ["timestamp", "@timestamp"], "transform": {"fn": "parse_timestamp"},
         "confidence": "medium", "note": "time stated in the line (long-tail extraction), else the envelope time"},
        {"to": "metadata.original_time", "from": ["timestamp", "@timestamp"], "confidence": "high",
         "note": "the time text as written"},
        {"to": "severity_id", "from": "@pri", "transform": {"fn": "syslog_severity", "args": {"from_pri": True}},
         "confidence": "high", "note": "syslog PRI severity bits"},
        {"to": "status_id", "from": "outcome", "confidence": "medium",
         "transform": {"fn": "enum_lookup", "args": {"default": 99, "case_insensitive": True, "patterns": {
             # checked first (patterns are stored sorted and "(" sorts before "\\"): a negated word
             # ("not blocked", "no error") is not read either way
             "(?i)(\\b(not|no|never)\\b)": 99,
             "(?i)\\b(denied|deny|blocked|block|dropped|drop|rejected|reject|refused|failed|fail|failure|"
             "unauthorized|forbidden)\\b": 2,
             "(?i)\\b(allowed|allow|accepted|accept|permitted|permit|granted|success|succeeded|successful|"
             "authorized|authenticated|passed)\\b": 1}}},
         "note": "outcome word the long-tail agent copied from the line: explicit failure words -> Failure, "
                 "explicit success words -> Success, negated or anything else -> Other"},
        {"to": "status_detail", "from": "outcome", "confidence": "high", "note": "the outcome word as written"},
    ]}, "Fallback for rare lines handled by the long-tail agent: OCSF Base Event with the line's own time")

os.makedirs(os.path.join(ROOT, "registry", "seeds"), exist_ok=True)
with open(os.path.join(ROOT, "registry", "builtin.json"), "w") as fh:
    json.dump({"format": "logparser-registry/1", "rules": rules}, fh, indent=1, sort_keys=True)
print(len(rules), "builtin rules written")
