"""Authoring helper: writes the seeded registry, registry/seeds/*.json.

Seeds are rules for popular vendors taken from existing open-source parsers and
OCSF mappings. Every seeded rule records its source and licence. Only
permissively licensed sources are used:

  logstash-patterns-core  Apache-2.0  grok patterns, converted to RE2 here
  ocsf/examples           Apache-2.0  field mappings, re-expressed as mapping rules

Grok is converted mechanically: %{NAME:field} references are expanded, grok
field names such as [source][ip] become group names such as source_ip, and
constructs RE2 does not have (lookarounds, atomic groups) are dropped. A
converted pattern that RE2 rejects is skipped and reported, never hand-patched.
"""
from __future__ import annotations

import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from logparser import registry, rx  # noqa: E402
from logparser.ocsf import Schema, resolve_mapping  # noqa: E402

GROK_DIR = os.path.join(ROOT, "data", "raw", "logstash-patterns-core", "patterns", "ecs-v1")
OUT = os.path.join(ROOT, "registry", "seeds")
GROK_META = {"created_by": "seed", "source": "https://github.com/logstash-plugins/logstash-patterns-core "
             "(patterns/ecs-v1), converted from grok to RE2", "license": "Apache-2.0"}
OCSF_META = {"created_by": "seed", "source": "https://github.com/ocsf/examples (mappings/markdown), re-expressed "
             "as a mapping rule for OCSF 1.10.0", "license": "Apache-2.0", "needs_human_review": True}
OWN_META = {"created_by": "seed", "source": "this project", "license": "project licence"}

# RE2-safe replacements for grok base patterns that rely on lookarounds.
OVERRIDE = {
    "IPV4": r"(?:\d{1,3}\.){3}\d{1,3}",
    "IPV6": r"(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f.]{0,15}",
    "BASE10NUM": r"[+-]?(?:\d+(?:\.\d+)?|\.\d+)",
    "HOSTNAME": r"[0-9A-Za-z][0-9A-Za-z\-]{0,62}(?:\.[0-9A-Za-z][0-9A-Za-z\-]{0,62})*\.?",
    "WORD": r"\w+", "POSINT": r"[1-9][0-9]*", "NONNEGINT": r"[0-9]+", "YEAR": r"\d{2,4}",
    "TIME": r"(?:2[0123]|[01]?[0-9]):[0-5][0-9]:(?:[0-5]?[0-9]|60)(?:[:.,][0-9]+)?",
    "QUOTEDSTRING": r'"(?:\\.|[^\\"])*"',
    "EMAILLOCALPART": r"[a-zA-Z0-9!#$%&'*+\-/=?^_`{|}~.]{1,64}",
}


def load_grok() -> dict:
    pats = {}
    for name in sorted(os.listdir(GROK_DIR)):
        for line in open(os.path.join(GROK_DIR, name), encoding="utf-8"):
            line = line.rstrip("\n")
            if not line.strip() or line.startswith("#") or " " not in line:
                continue
            k, v = line.split(" ", 1)
            pats[k] = v
    pats.update(OVERRIDE)
    return pats


REF = re.compile(r"%\{(\w+)(?::([^}:]+))?(?::\w+)?\}")


def expand(pattern: str, pats: dict, used: dict, depth: int = 0) -> str:
    if depth > 30:
        raise ValueError("grok recursion too deep")

    def repl(m):
        name, fld = m.group(1), m.group(2)
        if name not in pats:
            raise KeyError(name)
        inner = expand(pats[name], pats, used, depth + 1)
        if not fld:
            return f"(?:{inner})"
        g = re.sub(r"[^A-Za-z0-9]+", "_", fld).strip("_") or "field"
        if g[0].isdigit():
            g = "f_" + g
        if g.startswith("metadata_"):
            g = g[len("metadata_"):]
        n = used.get(g, 0) + 1
        used[g] = n
        return f"(?P<{g if n == 1 else f'{g}__{n}'}>{inner})"
    out = REF.sub(repl, pattern)
    out = out.replace("(?>", "(?:")
    out = re.sub(r"\(\?<([A-Za-z_]\w*)>", r"(?P<\1>", out)
    out = re.sub(r"\(\?<?[=!][^()]*\)", "", out)       # drop lookarounds (none nest in these files)
    return out


def grok_rule(name: str, pats: dict) -> str | None:
    try:
        pat = "^" + expand(pats[name], pats, {}).lstrip("^").rstrip("$") + "$"
    except (KeyError, ValueError) as exc:
        print(f"  skip {name}: {exc}")
        return None
    err = rx.check(pat)
    if err:
        print(f"  skip {name}: {err[:100]}")
        return None
    return pat


def F(to, frm=None, value=None, transform=None, when=None, confidence="high", note=""):
    d = {"to": to, "confidence": confidence, "note": note}
    if frm is not None:
        d["from"] = frm
    else:
        d["value"] = value
    if transform:
        d["transform"] = transform
    if when:
        d["when"] = when
    return d


OUTBOUND = {"field": "cisco_asa_network_direction", "matches": "(?i)^outbound$"}
IPISH = r"^(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9A-Fa-f:]*:[0-9A-Fa-f:.]+)$"
NOT_IP = r"[G-Zg-z]"
SEV_SYSLOG = {"fn": "enum_lookup", "args": {"map": {"0": 6, "1": 5, "2": 5, "3": 4, "4": 3, "5": 2, "6": 1, "7": 1},
                                            "default": 0}}
PROTO_NUM = {"fn": "enum_lookup", "args": {"map": {"tcp": 6, "udp": 17, "icmp": 1, "icmp6": 58, "gre": 47,
                                                   "esp": 50, "ah": 51}}}
HTTP_ACT = {"fn": "enum_lookup", "args": {"map": {"connect": 1, "delete": 2, "get": 3, "head": 4, "options": 5,
                                                  "post": 6, "put": 7, "trace": 8, "patch": 9}, "default": 0}}


def build() -> dict:
    pats = load_grok()
    files: dict = {"cisco_asa": [], "web": [], "zeek": [], "aws": [], "generic": []}

    def add(group, rule_id, body, meta, note=""):
        m = dict(meta)
        if note:
            m["note"] = note
        registry.validate_rule(registry.kind_of(rule_id), body)
        files[group].append({"rule_id": rule_id, "body": body, "meta": m})

    # ---------------- Cisco ASA: parsers from grok, mapping after ocsf/examples Cisco/ASA
    asa_map = "mapping:seed-cisco-asa-network"
    conn_ids = set()
    for name in sorted(n for n in pats if n.startswith("CISCOFW")):
        ids = [p for p in name[len("CISCOFW"):].split("_") if re.fullmatch(r"\d{6}", p)]
        pat = grok_rule(name, pats)
        if not ids or not pat:
            continue
        names = set(rx.compile(pat).groupindex)
        body = {"kind": "regex", "pattern": pat,
                "scope": {"bucket": r"^cisco>unstructured\|(?:ASA|FTD|PIX|FWSM)-(?:" + "|".join(ids) + ")$"},
                "labels": {"vendor": "Cisco", "product": "ASA", "event_type": "message " + "/".join(ids)}}
        if {"source_ip", "destination_ip"} <= names or {"source_ip"} <= names and "destination_address" in names:
            body["mapping"] = asa_map
            conn_ids.update(ids)
        add("cisco_asa", f"parser:seed-cisco-asa-{'-'.join(ids)}", body, GROK_META, f"grok {name}")
    add("cisco_asa", asa_map, {
        "class": "network_activity", "profiles": ["host", "security_control"],
        "constants": {"metadata.product.name": "ASA", "metadata.product.vendor_name": "Cisco",
                      "connection_info.direction_id": 0},
        "fields": [
            F("activity_id", "cisco_asa_outcome", transform={"fn": "enum_lookup", "args": {
                "map": {"built": 1, "teardown": 2, "deny": 5, "denied": 5, "denied by acl": 5, "discarded": 5,
                        "dropping": 5, "permitted": 6, "est-allowed": 6, "created": 1, "deleted": 2},
                "default": 0}}, note="Built=Open, Teardown=Close, Deny=Refuse, as in ocsf/examples Cisco ASA"),
            F("status_id", "cisco_asa_outcome", transform={"fn": "enum_lookup", "args": {
                "map": {"built": 1, "teardown": 1, "permitted": 1, "est-allowed": 1, "deny": 2, "denied": 2,
                        "denied by acl": 2, "discarded": 2, "dropping": 2}}}, confidence="medium",
              note="allowed traffic = Success, blocked traffic = Failure"),
            F("severity_id", "@cisco_severity", transform=SEV_SYSLOG, note="Cisco severity digit is syslog severity"),
            F("metadata.event_code", "@cisco_mnemonic", note="ASA message id"),
            F("src_endpoint.ip", ["source_ip"], note="source address"),
            F("src_endpoint.port", ["source_port"], note="source port"),
            F("src_endpoint.interface_name", ["observer_ingress_interface_name"], confidence="medium",
              note="interface name the packet came in on"),
            F("dst_endpoint.ip", ["destination_ip"], note="destination address"),
            F("dst_endpoint.port", ["destination_port"], note="destination port"),
            F("dst_endpoint.interface_name", ["observer_egress_interface_name"], confidence="medium",
              note="interface name the packet left on"),
            F("connection_info.protocol_name", "cisco_asa_network_transport", transform={"fn": "lower"},
              note="transport protocol word"),
            F("connection_info.protocol_num", "cisco_asa_network_transport", transform=PROTO_NUM,
              note="IANA number for the protocol word"),
            F("connection_info.direction_id", "cisco_asa_network_direction", transform={"fn": "enum_lookup", "args": {
                "map": {"inbound": 1, "outbound": 2}, "default": 0}}, note="Inbound/Outbound word"),
            F("connection_info.uid", "cisco_asa_connection_id", note="ASA connection id"),
            F("traffic.bytes", "network_bytes", note="bytes reported at teardown"),
            F("actor.user.name", ["source_user_name", "user_name"], confidence="medium", note="user in parentheses"),
            F("message", "event_reason", confidence="medium", note="teardown reason text"),
            # "Built outbound ... for outside:X to inside:Y": the inside host Y started the connection
            F("src_endpoint.ip", "destination_ip", when=OUTBOUND, note="outbound: initiator is the second address"),
            F("src_endpoint.port", "destination_port", when=OUTBOUND, note="outbound: initiator port"),
            F("src_endpoint.interface_name", "observer_egress_interface_name", when=OUTBOUND, confidence="medium",
              note="outbound: initiator's interface"),
            F("dst_endpoint.ip", "source_ip", when=OUTBOUND, note="outbound: responder is the first address"),
            F("dst_endpoint.port", "source_port", when=OUTBOUND, note="outbound: responder port"),
            F("dst_endpoint.interface_name", "observer_ingress_interface_name", when=OUTBOUND, confidence="medium",
              note="outbound: responder's interface"),
            F("action_id", "cisco_asa_outcome", transform={"fn": "enum_lookup", "args": {
                "map": {"deny": 2, "denied": 2, "denied by acl": 2, "discarded": 2, "dropping": 2,
                        "built": 1, "permitted": 1, "est-allowed": 1}}}, note="deny words = Denied, built = Allowed"),
            F("disposition_id", "cisco_asa_outcome", transform={"fn": "enum_lookup", "args": {
                "map": {"deny": 2, "denied": 2, "denied by acl": 2, "discarded": 2, "dropping": 2,
                        "built": 1, "permitted": 1, "est-allowed": 1}}}, note="deny words = Blocked, built = Allowed"),
        ]}, OCSF_META, "Cisco ASA connection messages (106023, 302013-302016, 305011, 305012 and similar)")

    # ---------------- web access logs
    for gname, rid, label in (("HTTPD_COMBINEDLOG", "parser:seed-httpd-combined", "combined access log"),
                              ("HTTPD_COMMONLOG", "parser:seed-httpd-common", "common access log")):
        pat = grok_rule(gname, pats)
        if pat:
            add("web", rid, {"kind": "regex", "pattern": pat, "scope": {"bucket": r"unstructured\|"},
                             "mapping": "mapping:seed-http-access",
                             "labels": {"product": "HTTP server", "event_type": label}}, GROK_META, f"grok {gname}")
    add("web", "mapping:seed-http-access", {
        "class": "http_activity", "profiles": ["host"],
        "fields": [
            F("time", "timestamp", transform={"fn": "parse_timestamp"}, note="request time in CLF format"),
            F("activity_id", "http_request_method", transform=HTTP_ACT, note="HTTP method to activity"),
            F("http_request.http_method", "http_request_method", transform={"fn": "upper"}, note="request method"),
            F("http_request.url.path", "url_original", confidence="medium",
              note="request target; usually a path with optional query string"),
            F("http_request.version", "http_version", note="HTTP version"),
            F("http_request.referrer", "http_request_referrer", note="Referer header"),
            F("http_request.user_agent", "user_agent_original", note="User-Agent header"),
            F("http_response.code", "http_response_status_code", note="status code"),
            F("http_response.length", "http_response_body_bytes", confidence="medium", note="response size in bytes"),
            F("src_endpoint.ip", "source_address", when={"field": "source_address", "matches": IPISH},
              note="client address when it is an IP"),
            F("src_endpoint.hostname", "source_address", when={"field": "source_address", "matches": NOT_IP},
              note="client address when it is a host name"),
            F("actor.user.name", "user_name", confidence="medium", note="authenticated user (third CLF field)"),
            F("status_id", "http_response_status_code", transform={"fn": "enum_lookup", "args": {
                "map": {}, "patterns": {"^[123]": 1, "^[45]": 2}}}, confidence="medium",
              note="1xx-3xx Success, 4xx-5xx Failure"),
        ]}, OWN_META, "Apache/nginx common and combined log format to HTTP Activity")
    for gname, rid, label, mp in (("HAPROXYHTTPBASE", "parser:seed-haproxy-http", "HAProxy HTTP log", None),
                                  ("SQUID3", "parser:seed-squid-access", "Squid access log", "mapping:seed-squid-access")):
        pat = grok_rule(gname, pats)
        if pat:
            body = {"kind": "regex", "pattern": pat, "scope": {"bucket": r"unstructured\|"},
                    "labels": {"product": label.split(" ")[0], "event_type": label}}
            if mp:
                body["mapping"] = mp
            add("web", rid, body, GROK_META, f"grok {gname}")
    add("web", "mapping:seed-squid-access", {
        "class": "http_activity", "profiles": ["host"],
        "constants": {"metadata.product.name": "Squid"},
        "fields": [
            F("time", "timestamp", transform={"fn": "parse_timestamp"}, note="epoch seconds with milliseconds"),
            F("activity_id", "http_request_method", transform=HTTP_ACT, note="HTTP method to activity"),
            F("http_request.http_method", "http_request_method", note="request method"),
            F("http_request.url.url_string", "url_original", note="requested URL"),
            F("http_response.code", "http_response_status_code", note="status code after the slash"),
            F("http_response.length", "http_response_bytes", confidence="medium", note="bytes sent to the client"),
            F("http_response.content_type", "http_response_mime_type", note="MIME type"),
            F("src_endpoint.ip", "source_ip", note="client address"),
            F("dst_endpoint.ip", "destination_address", when={"field": "destination_address", "matches": IPISH},
              note="origin server address"),
            F("actor.user.name", "user_name", confidence="medium", note="ident/user field"),
            F("duration", "squid_request_duration", note="elapsed milliseconds"),
        ]}, OWN_META, "Squid native access log to HTTP Activity")

    # ---------------- Zeek JSON, after ocsf/examples Zeek mappings
    def zeek_common():
        return [
            F("time", "ts", transform={"fn": "parse_timestamp"}, note="Zeek ts (epoch seconds or ISO)"),
            F("src_endpoint.ip", "id.orig_h", note="originator address"),
            F("src_endpoint.port", "id.orig_p", note="originator port"),
            F("dst_endpoint.ip", "id.resp_h", note="responder address"),
            F("dst_endpoint.port", "id.resp_p", note="responder port"),
            F("connection_info.uid", "uid", note="Zeek connection uid"),
        ]
    zc = {"metadata.product.name": "Zeek", "metadata.product.vendor_name": "Zeek", "severity_id": 1}
    add("zeek", "mapping:seed-zeek-1-dns", {
        "class": "dns_activity", "scope": {"bucket": r"json\|"}, "match": {"requires": ["id.orig_h", "query", "qtype_name"]},
        "labels": {"vendor": "Zeek", "product": "Zeek", "event_type": "dns.log"},
        "constants": {**zc, "activity_id": 6, "connection_info.direction_id": 0, "metadata.log_name": "dns"},
        "fields": zeek_common() + [
            F("query.hostname", "query", note="queried name"),
            F("query.type", "qtype_name", note="query type name"),
            F("query.class", "qclass_name", note="query class name"),
            F("rcode", "rcode_name", note="response code name"),
            F("rcode_id", "rcode", note="numeric response code"),
            F("connection_info.protocol_name", "proto", note="transport"),
            F("transaction_id", "trans_id", confidence="medium", note="DNS transaction id"),
        ]}, OCSF_META, "Zeek dns.log")
    add("zeek", "mapping:seed-zeek-2-http", {
        "class": "http_activity", "scope": {"bucket": r"json\|"}, "match": {"requires": ["id.orig_h", "method", "uri", "trans_depth"], "absent": ["call_id"]},
        "labels": {"vendor": "Zeek", "product": "Zeek", "event_type": "http.log"},
        "constants": {**zc, "connection_info.direction_id": 0, "metadata.log_name": "http"},
        "fields": zeek_common() + [
            F("activity_id", "method", transform=HTTP_ACT, note="HTTP method to activity"),
            F("http_request.http_method", "method", note="request method"),
            F("http_request.url.path", "uri", note="request URI"),
            F("http_request.url.hostname", "host", confidence="medium", note="Host header"),
            F("http_request.user_agent", "user_agent", note="User-Agent header"),
            F("http_request.referrer", "referrer", note="Referer header"),
            F("http_request.version", "version", note="HTTP version"),
            F("http_response.code", "status_code", note="status code"),
            F("http_response.message", "status_msg", note="status message"),
            F("http_response.length", "response_body_len", confidence="medium", note="response body length"),
        ]}, OCSF_META, "Zeek http.log")
    add("zeek", "mapping:seed-zeek-3-conn", {
        "class": "network_activity", "scope": {"bucket": r"json\|"},
        "match": {"requires": ["id.orig_h", "id.resp_h", "conn_state", "proto"]},
        "labels": {"vendor": "Zeek", "product": "Zeek", "event_type": "conn.log"},
        "constants": {**zc, "activity_id": 6, "connection_info.direction_id": 0, "metadata.log_name": "conn"},
        "fields": zeek_common() + [
            F("connection_info.protocol_name", "proto", note="transport"),
            F("connection_info.protocol_num", "proto", transform=PROTO_NUM, note="IANA number for the transport"),
            F("connection_info.flag_history", "history", confidence="medium", note="Zeek connection history string"),
            F("app_protocol_name", "service", confidence="medium", note="application protocol Zeek identified"),
            F("duration", "duration", transform={"fn": "scale", "args": {"factor": 1000}},
              note="seconds to milliseconds"),
            F("traffic.bytes_out", "orig_bytes", note="payload bytes from originator"),
            F("traffic.bytes_in", "resp_bytes", note="payload bytes from responder"),
            F("traffic.packets_out", "orig_pkts", note="packets from originator"),
            F("traffic.packets_in", "resp_pkts", note="packets from responder"),
        ]}, OCSF_META, "Zeek conn.log")

    # ---------------- AWS
    add("aws", "directive:aws-vpcflow-header", {
        "pattern": r"^(?P<fields>version (?:[a-z\-]+ ){3,}[a-z\-]+)$", "field_sep": " ", "delimiter": " "},
        OWN_META, "VPC flow log files start with a header line naming the fields")
    add("aws", "mapping:seed-aws-vpcflow", {
        "class": "network_activity", "scope": {"bucket": r"^directive>delimited\|"},
        "match": {"requires": ["srcaddr", "dstaddr", "action", "log-status"]},
        "labels": {"vendor": "AWS", "product": "VPC Flow Logs", "event_type": "flow record"},
        "profiles": ["cloud"],
        "constants": {"metadata.product.name": "Amazon VPC", "metadata.product.vendor_name": "AWS",
                      "cloud.provider": "AWS", "severity_id": 1, "connection_info.direction_id": 0},
        "fields": [
            F("time", "start", transform={"fn": "parse_timestamp", "args": {"unit": "s"}}, note="flow start, epoch seconds"),
            F("start_time", "start", transform={"fn": "parse_timestamp", "args": {"unit": "s"}}, note="flow start"),
            F("end_time", "end", transform={"fn": "parse_timestamp", "args": {"unit": "s"}}, note="flow end"),
            F("activity_id", "action", transform={"fn": "enum_lookup", "args": {"map": {"accept": 6, "reject": 5},
                                                                                 "default": 0}},
              note="ACCEPT=Traffic, REJECT=Refuse"),
            F("status_id", "action", transform={"fn": "enum_lookup", "args": {"map": {"accept": 1, "reject": 2}}},
              confidence="medium", note="accepted = Success, rejected = Failure"),
            F("src_endpoint.ip", "srcaddr", transform={"fn": "null_if", "args": {"values": ["-"]}}, note="source address"),
            F("dst_endpoint.ip", "dstaddr", transform={"fn": "null_if", "args": {"values": ["-"]}}, note="destination address"),
            F("src_endpoint.port", "srcport", transform={"fn": "null_if", "args": {"values": ["-"]}}, note="source port"),
            F("dst_endpoint.port", "dstport", transform={"fn": "null_if", "args": {"values": ["-"]}}, note="destination port"),
            F("src_endpoint.interface_uid", "interface-id", confidence="medium", note="ENI the flow was recorded on"),
            F("connection_info.protocol_num", "protocol", transform={"fn": "null_if", "args": {"values": ["-"]}},
              note="IANA protocol number"),
            F("traffic.packets", "packets", transform={"fn": "null_if", "args": {"values": ["-"]}}, note="packet count"),
            F("traffic.bytes", "bytes", transform={"fn": "null_if", "args": {"values": ["-"]}}, note="byte count"),
            F("cloud.account.uid", "account-id", note="AWS account id"),
            F("status_code", "log-status", confidence="medium", note="OK / NODATA / SKIPDATA"),
        ]}, OCSF_META, "AWS VPC Flow Logs, default and custom formats with a header line")
    ct_fields = [
        F("time", "eventTime", transform={"fn": "parse_timestamp"}, note="event time (ISO 8601 UTC)"),
        F("api.operation", "eventName", note="API action"),
        F("api.service.name", "eventSource", note="AWS service endpoint"),
        F("api.version", "apiVersion", confidence="medium", note="API version when present"),
        F("api.request.uid", "requestID", note="request id"),
        F("api.response.error", "errorCode", note="error code when the call failed"),
        F("api.response.message", "errorMessage", note="error message when the call failed"),
        F("actor.user.uid", ["userIdentity.arn", "userIdentity.principalId", "userIdentity.accountId"],
          note="caller identity"),
        F("actor.user.name", ["userIdentity.userName", "userIdentity.sessionContext.sessionIssuer.userName"],
          note="caller user name"),
        F("actor.user.type", "userIdentity.type", confidence="medium", note="identity type"),
        F("actor.user.account.uid", "userIdentity.accountId", note="account of the caller"),
        F("actor.invoked_by", "userIdentity.invokedBy", confidence="medium", note="AWS service that made the call"),
        F("src_endpoint.ip", "sourceIPAddress", when={"field": "sourceIPAddress", "matches": IPISH},
          note="caller address when it is an IP"),
        F("src_endpoint.domain", "sourceIPAddress", when={"field": "sourceIPAddress", "matches": NOT_IP},
          confidence="medium", note="AWS service DNS name when the caller is a service"),
        F("http_request.user_agent", "userAgent", note="user agent"),
        F("cloud.region", "awsRegion", note="region"),
        F("cloud.account.uid", "recipientAccountId", note="account that received the event"),
        F("metadata.uid", "eventID", note="CloudTrail event id"),
        F("metadata.event_code", "eventType", confidence="medium", note="CloudTrail event type"),
        F("status_id", value=2, when={"field": "errorCode", "exists": True}, confidence="medium",
          note="an errorCode means the call failed"),
        F("status_id", value=1, when={"field": "errorCode", "exists": False}, confidence="medium",
          note="no errorCode means the call succeeded"),
    ]
    ct_const = {"metadata.product.name": "CloudTrail", "metadata.product.vendor_name": "AWS",
                "cloud.provider": "AWS", "severity_id": 1}
    add("aws", "mapping:seed-aws-cloudtrail-1-consolelogin", {
        "class": "authentication", "scope": {"bucket": r"json\|"},
        "match": {"requires": ["eventSource", "awsRegion", "eventVersion"], "equals": {"eventName": "ConsoleLogin"}},
        "labels": {"vendor": "AWS", "product": "CloudTrail", "event_type": "ConsoleLogin"},
        "profiles": ["cloud"], "constants": {**ct_const, "activity_id": 1, "is_remote": True},
        "fields": [f for f in ct_fields if not f["to"].startswith(("api.response", "actor.", "api.request"))
                   and f["to"] != "status_id"] + [
            F("user.uid", ["userIdentity.arn", "userIdentity.principalId"], note="identity that signed in"),
            F("user.name", ["userIdentity.userName"], note="IAM user name"),
            F("user.account.uid", "userIdentity.accountId", note="account"),
            F("service.name", "eventSource", note="sign-in service"),
            F("is_mfa", "additionalEventData.MFAUsed", transform={"fn": "enum_lookup", "args": {
                "map": {"yes": True, "no": False}}}, note="MFAUsed Yes/No"),
            F("status_id", "responseElements.ConsoleLogin", transform={"fn": "enum_lookup", "args": {
                "map": {"success": 1, "failure": 2}, "default": 0}}, note="ConsoleLogin Success/Failure"),
            F("status_detail", "errorMessage", note="failure reason"),
        ]}, OCSF_META, "AWS console sign-in to Authentication")
    add("aws", "mapping:seed-aws-cloudtrail-9-api", {
        "class": "api_activity", "scope": {"bucket": r"json\|"},
        "match": {"requires": ["eventSource", "eventName", "awsRegion", "eventVersion", "userIdentity.type"]},
        "labels": {"vendor": "AWS", "product": "CloudTrail", "event_type": "API call"},
        "profiles": ["cloud"], "constants": dict(ct_const),
        "fields": ct_fields + [
            F("activity_id", "eventName", transform={"fn": "enum_lookup", "args": {"map": {}, "default": 0, "patterns": {
                "^(?:Create|Add|Put|Run|Start|Enable|Attach|Upload|Associate|Register)": 1,
                "^(?:Get|Describe|Head|Lookup|Check)": 2,
                "^(?:Update|Modify|Set|Change|Assume)": 3,
                "^(?:Delete|Remove|Stop|Terminate|Deactivate|Disable|Detach|Disassociate|Deregister)": 4,
                "^List": 5}}}, confidence="medium", note="verb prefix of the API action"),
        ]}, OCSF_META, "AWS CloudTrail management and data events to API Activity")

    add("generic", "detect:meraki_inner", {
        "order": 16, "name": "meraki_inner", "type": "envelope", "app": ["app"], "test": {"kind": "regex", "pattern":
            r"^<(?P<inner_pri>\d{1,3})>1 (?P<timestamp>\d{10}\.\d+) (?P<host>\S+) (?P<app>[a-z][a-z_]+) (?P<payload>.*)$"}},
        OWN_META, "Cisco Meraki syslog: priority, epoch time, network name, event type")
    # ---------------- generic helpers
    add("generic", "detect:apache_error", {
        "order": 29, "name": "apache_error", "type": "envelope", "test": {"kind": "regex", "pattern":
            r"^\[(?P<timestamp>[A-Z][a-z]{2} [A-Z][a-z]{2} [ \d]\d \d\d:\d\d:\d\d(?:\.\d+)? \d{4})\] "
            r"\[(?P<level>[a-z:_\w]+)\] (?:\[pid (?P<pid>\d+)(?::tid \d+)?\] )?(?:\[client (?P<client>[^\]]+)\] )?"
            r"(?P<payload>.*)$"}}, OWN_META, "Apache httpd error log header")
    return files


def verify(files: dict) -> None:
    """Static check of every seeded mapping against the OCSF schema."""
    schema = Schema()
    by_id = {r["rule_id"]: r for rs in files.values() for r in rs}
    bad = 0
    for rid, r in by_id.items():
        if not rid.startswith("mapping:"):
            continue
        res = resolve_mapping(r["body"], by_id.get)
        c = schema.cls(res["class"])
        for p in list(res["constants"]) + [f["to"] for f in res["fields"]]:
            if schema.attr_at(c["name"], p) is None:
                print(f"  BAD PATH {rid}: {p}")
                bad += 1
    for r in by_id.values():
        m = r["body"].get("mapping")
        if m and m not in by_id:
            print(f"  BAD LINK {r['rule_id']} -> {m}")
            bad += 1
    if bad:
        raise SystemExit(f"{bad} problems in seeds")


def main() -> None:
    files = build()
    verify(files)
    os.makedirs(OUT, exist_ok=True)
    for name, rules in files.items():
        with open(os.path.join(OUT, f"{name}.json"), "w") as fh:
            json.dump({"format": "logparser-registry/1", "rules": rules}, fh, indent=1, sort_keys=True)
        print(f"{name}: {len(rules)} rules")


if __name__ == "__main__":
    main()
