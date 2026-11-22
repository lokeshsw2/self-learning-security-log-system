"""Build the evaluation set: eval/labels.jsonl.

Labels come from ground truth that ships with the public datasets, never from
this project's engine or its AI-written rules:

  loghub-template  Loghub's hand-labelled template id per line (group) and the
                   template parameters (values). OCSF class per template is a
                   small hand table in this file.
  ecs-expected     Elastic Beats golden files (<log>-expected.json). Network
                   and identity fields are translated from ECS to OCSF paths.
  ocsf-gold        ocsf/examples raw + .ocsf pairs written by OCSF contributors.
  manual           Hand table per source plus a tiny independent CEF/LEEF reader.

Each label line:
  id, source, raw, basis, license
  group    label for grouping checks, or null when the dataset has no template truth
  values   strings that a correct parser must extract (all literally in raw)
  ocsf     {"class_uid_any": [..] or null, "attrs": {"path|alt.path": value}}
           attrs pass when any alternative path holds the value.
"""
from __future__ import annotations

import csv
import glob
import hashlib
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import build_corpus as bc  # noqa: E402

ROOT = bc.ROOT
RAW = bc.RAW
CORPUS = bc.OUT
OUT = os.path.join(ROOT, "eval")
PER_SOURCE = 10

USER = "user.name|actor.user.name"
SRC_IP = "src_endpoint.ip"
DST_IP = "dst_endpoint.ip"
SRC_HOST = "src_endpoint.ip|src_endpoint.hostname|src_endpoint.name"

# ---------------------------------------------------------------- Loghub
LOGHUB = {
    "loghub_openssh": "OpenSSH", "loghub_linux": "Linux", "loghub_apache_error": "Apache",
    "loghub_mac": "Mac", "loghub_windows_cbs": "Windows", "loghub_hdfs": "HDFS",
    "loghub_zookeeper": "Zookeeper", "loghub_bgl": "BGL",
}
AUTH, NET, SSH, FTP, BASE = 3002, 4001, 4007, 4008, 0
NETISH = [NET, SSH, AUTH, BASE]
# template id -> (classes, fixed enum expectations, {ocsf path: parameter index})
OPENSSH_T = {
    "E1": ([AUTH], {"activity_id": 1, "status_id": 1}, {USER: 0, SRC_IP: 1, "src_endpoint.port": 2}),
    "E8": ([AUTH], {"status_id": 2}, {USER: 0, SRC_IP: 1, "src_endpoint.port": 2}),
    "E9": ([AUTH], {"activity_id": 1, "status_id": 2}, {USER: 0, SRC_IP: 1, "src_endpoint.port": 2}),
    "E10": ([AUTH], {"activity_id": 1, "status_id": 2}, {USER: 0, SRC_IP: 1, "src_endpoint.port": 2}),
    "E12": ([AUTH], {}, {USER: 0}),
    "E13": ([AUTH], {}, {USER: 0, SRC_IP: 1}),
    "E19": ([AUTH], {"status_id": 2}, {SRC_HOST: 2}),
    "E20": ([AUTH], {"status_id": 2}, {SRC_HOST: 2, USER: 3}),
    "E21": ([AUTH], {}, {}),
    "E22": ([AUTH], {"activity_id": 2}, {USER: 0}),
    "E23": ([AUTH], {"activity_id": 1}, {USER: 0}),
    "E4": ([AUTH, SSH, NET], {}, {}), "E5": ([AUTH, SSH, NET], {}, {}),
    "E6": ([AUTH, SSH, NET], {}, {SRC_IP: 0}), "E7": ([AUTH, SSH, NET], {}, {SRC_IP: 0}),
    "E14": ([AUTH], {"status_id": 2}, {SRC_IP: 1}),
    "E15": ([AUTH], {"status_id": 2}, {SRC_HOST: 3}), "E16": ([AUTH], {"status_id": 2}, {SRC_HOST: 3}),
    "E17": ([AUTH], {"status_id": 2}, {SRC_HOST: 3}),
    "E18": (NETISH, {}, {}),
    "E2": (NETISH, {}, {SRC_IP: 0}), "E3": (NETISH, {}, {SRC_IP: 0}), "E11": (NETISH, {}, {}),
    "E24": (NETISH, {}, {SRC_IP: 0}), "E25": (NETISH, {}, {SRC_IP: 0}), "E26": (NETISH, {}, {SRC_IP: 0}),
    "E27": (NETISH, {}, {SRC_IP: 1}),
}
LINUX_T = {
    "E29": ([NET, FTP], {}, {SRC_IP: 0}),
    "E16": ([AUTH], {"status_id": 2}, {SRC_HOST: 0}), "E17": ([AUTH], {"status_id": 2}, {SRC_HOST: 0}),
    "E18": ([AUTH], {"status_id": 2}, {SRC_HOST: 0}), "E19": ([AUTH], {"status_id": 2}, {SRC_HOST: 0}),
    "E27": ([AUTH], {}, {}),
    "E101": ([AUTH], {"activity_id": 2}, {USER: 0}),
    "E102": ([AUTH], {"activity_id": 1}, {USER: 0}),
    "E61": ([AUTH], {"status_id": 2}, {}),
    "E13": ([AUTH], {"status_id": 2}, {SRC_HOST: 0}), "E14": ([AUTH], {"status_id": 2}, {SRC_HOST: 0}),
}
LOGHUB_T = {"loghub_openssh": OPENSSH_T, "loghub_linux": LINUX_T}


def template_params(template: str, content: str):
    parts = [re.escape(p) for p in template.split("<*>")]
    rx = "^" + "(.*?)".join(parts) + "$"
    m = re.match(rx, content)
    return list(m.groups()) if m else None


def loghub_labels(source: str, lines: list[str]):
    ds = LOGHUB[source]
    path = os.path.join(RAW, "loghub", ds, f"{ds}_2k.log_structured.csv")
    rows = list(csv.DictReader(open(path, encoding="utf-8", errors="replace")))
    out = []
    table = LOGHUB_T.get(source, {})
    for i, row in enumerate(rows):
        raw = lines[i]
        params = template_params(row["EventTemplate"], row["Content"]) or []
        values = [p.strip() for p in params if len(p.strip()) >= 2 and p.strip() in raw]
        ocsf = {"class_uid_any": None, "attrs": {}}
        if row["EventId"] in table:
            classes, fixed, pmap = table[row["EventId"]]
            ocsf["class_uid_any"] = classes
            ocsf["attrs"].update(fixed)
            for pth, idx in pmap.items():
                if idx < len(params) and params[idx].strip():
                    ocsf["attrs"][pth] = params[idx].strip()
        out.append({"raw": raw, "group": f"{source}:{row['EventId']}", "values": values,
                    "ocsf": ocsf, "basis": "loghub-template"})
    return out


# ---------------------------------------------------------------- Beats ECS
CAT_CLASS = {
    "authentication": [3002], "network": [4001], "web": [4002],
    "intrusion_detection": [2004], "malware": [2004], "threat": [2004],
    "process": [1007], "file": [1001], "iam": [3001, 3004, 3005, 3006],
    "session": [3002, 4001], "database": [6005], "email": [4009],
}
SOURCE_CLASS = {  # extra classes that are also right for a source
    "aws_cloudtrail": [6003, 3001, 3002, 3004, 3005, 3006],
    "gcp_audit": [6003], "okta_system": [3002, 3001, 3004, 3005, 3006, 6003, 2004],
    "o365_audit": [6003, 6001, 6002, 3001, 3002, 3004, 3005, 3006, 1001, 4009],
    "azure_signin": [3002], "aws_vpcflow": [4001], "aws_elb": [4002, 4001],
    "apache_access": [4002], "nginx_access": [4002], "iis_access": [4002], "haproxy": [4002, 4001],
    "iptables": [4001], "suricata_eve": [4001, 4002, 4003, 2004, 4005, 4007, 4014],
    "zeek_json": None, "auditd": None, "osquery": None, "crowdstrike_falcon": None,
    "cyberark_pas": None, "santa": [1007, 1001], "system_auth": None,
}
GROUP_KEYS = {
    "cisco_asa": ["cisco.asa.message_id", "event.code"], "cisco_ftd": ["cisco.ftd.message_id", "event.code"],
    "cisco_ios": ["cisco.ios.facility", "event.code"],
    "panw_panos": ["panw.panos.type", "panw.panos.sub_type"],
    "fortinet_fortigate": ["fortinet.firewall.type", "fortinet.firewall.subtype"],
    "juniper_srx": ["juniper.srx.tag"], "sophos_xg": ["sophos.xg.log_type", "sophos.xg.log_subtype"],
    "suricata_eve": ["suricata.eve.event_type"], "zeek_json": ["fileset.name"],
    "auditd": ["auditd.log.record_type"], "aws_cloudtrail": ["event.action"],
    "okta_system": ["event.action"], "o365_audit": ["event.code", "event.action"],
    "crowdstrike_falcon": ["crowdstrike.metadata.eventType", "crowdstrike.event.event_simpleName"],
}
ECS_ATTR = [
    ("source.ip", "src_endpoint.ip"), ("destination.ip", "dst_endpoint.ip"),
    ("source.port", "src_endpoint.port"), ("destination.port", "dst_endpoint.port"),
    ("user.name", USER + "|user.email_addr|actor.user.email_addr|user.uid|actor.user.uid"),
    ("http.request.method", "http_request.http_method"),
    ("http.response.status_code", "http_response.code"),
    ("dns.question.name", "query.hostname"),
]
ECS_VALUES = ["source.ip", "destination.ip", "source.port", "destination.port", "user.name",
              "http.request.method", "http.response.status_code", "url.original", "url.path",
              "process.name", "process.pid", "source.nat.ip", "destination.nat.ip",
              "dns.question.name", "file.path", "process.executable", "user_agent.original"]


def literal(v, raw: str) -> bool:
    s = str(v)
    if not s or s not in raw:
        return False
    if s.isdigit():  # a number must stand as a whole token, not inside a longer number
        return re.search(r"(?<![0-9.])" + re.escape(s) + r"(?![0-9])", raw) is not None
    return True


def beats_labels(source: str, lines: list[str], manifest: dict):
    out = [None] * len(lines)
    pos = 0
    for origin in manifest["origin"]:
        f = os.path.join(RAW, origin["file"])
        n = origin["lines"]
        exp_path = f + "-expected.json"
        if os.path.exists(exp_path):
            data = open(f, "rb").read()
            offsets, off = {}, 0
            for j, ln in enumerate(data.split(b"\n")):
                offsets[off] = j
                off += len(ln) + 1
            for ev in json.load(open(exp_path)):
                j = offsets.get(ev.get("log.offset"))
                if j is None or j >= n or "multiline" in (ev.get("log.flags") or []):
                    continue
                raw = lines[pos + j]
                keys = GROUP_KEYS.get(source)
                group = None
                if keys:
                    parts = [str(ev[k]) for k in keys if k in ev]
                    group = f"{source}:{'/'.join(parts)}" if parts else None
                cats = ev.get("event.category") or []
                if isinstance(cats, str):
                    cats = [cats]
                classes = []
                for c in cats:
                    classes += CAT_CLASS.get(c, [])
                if "dns.question.name" in ev:
                    classes.append(4003)
                if "http.request.method" in ev:
                    classes.append(4002)
                extra = SOURCE_CLASS.get(source, [])
                if extra is None:
                    classes = None
                else:
                    classes = sorted(set(classes + extra)) or None
                attrs = {}
                for ecs, pth in ECS_ATTR:
                    if ecs in ev and not isinstance(ev[ecs], list) and literal(ev[ecs], raw):
                        attrs[pth] = ev[ecs]
                if ev.get("event.outcome") in ("success", "failure") and classes:
                    attrs["status_id"] = 1 if ev["event.outcome"] == "success" else 2
                values = sorted({str(ev[k]) for k in ECS_VALUES
                                 if k in ev and not isinstance(ev[k], list) and literal(ev[k], raw)})
                out[pos + j] = {"raw": raw, "group": group, "values": values,
                                "ocsf": {"class_uid_any": classes, "attrs": attrs},
                                "basis": "ecs-expected"}
        pos += n
    return [o for o in out if o]


# ---------------------------------------------------------------- manual / CEF
MANUAL_CLASS = {
    "barracuda_waf": [4002, 2004], "citrix_adc": [4002, 2004], "fortiweb": [2004, 4002],
    "radiflow_isid": [2004, 4001], "withsecure": [2004, 1001, 1007, 4002], "votiro": None,
    "illumio_core": [3002, 6003, 3001], "trendmicro_leef": None, "metron_asa": [4001, 3002, 4002, 2004, 0],
    "squid": [4002], "snort": [2004], "yaf": [4001], "websphere": [3002], "syslog5424": None,
    "cef_generic": None,
}
CEF_KV = re.compile(r"(?:^|[\s|\t])(src|dst|spt|dpt|suser|duser|usrName|request|requestMethod)=([^\s\t]+)")
CEF_ATTR = {"src": SRC_IP, "dst": DST_IP, "spt": "src_endpoint.port", "dpt": "dst_endpoint.port",
            "suser": USER, "duser": USER + "|dst_user.name", "usrName": USER,
            "requestMethod": "http_request.http_method"}
IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def manual_labels(source: str, lines: list[str]):
    out = []
    for raw in lines:
        group, attrs, values = None, {}, []
        m = re.search(r"(CEF|LEEF):\s?\d+(?:\.\d+)?\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|", raw)
        if m:
            group = f"{source}:{m.group(2)}|{m.group(3)}|{m.group(5)}"
            for k, v in CEF_KV.findall(raw):
                v = v.strip('"')
                if v in ("-", "", "N/A"):
                    continue
                if k in ("src", "dst") and not IPV4.match(v):
                    continue
                if k in ("spt", "dpt") and not v.isdigit():
                    continue
                values.append(v)
                if k in CEF_ATTR and CEF_ATTR[k] not in attrs:
                    attrs[CEF_ATTR[k]] = int(v) if v.isdigit() else v
        elif source == "squid":
            p = raw.split()
            values = [p[2], p[5], p[6]]
            attrs = {SRC_IP: p[2], "http_request.http_method": p[5]}
        elif source == "snort":
            p = raw.split(",")
            values = [p[6], p[8]]
            attrs = {SRC_IP: p[6], DST_IP: p[8], "src_endpoint.port": int(p[7]), "dst_endpoint.port": int(p[9])}
        elif source == "yaf":
            p = [x.strip() for x in raw.split("|")]
            values = [p[5], p[7]]
            attrs = {SRC_IP: p[5], DST_IP: p[7], "src_endpoint.port": int(p[6]), "dst_endpoint.port": int(p[8])}
        elif source == "metron_asa":
            m = re.search(r"%ASA-\d-(\d+)", raw)
            group = f"{source}:{m.group(1)}" if m else None
        out.append({"raw": raw, "group": group, "values": sorted(set(values)),
                    "ocsf": {"class_uid_any": MANUAL_CLASS.get(source), "attrs": attrs}, "basis": "manual"})
    return out


# ---------------------------------------------------------------- OCSF gold pairs
GOLD_PATHS = ["src_endpoint.ip", "dst_endpoint.ip", "src_endpoint.port", "dst_endpoint.port",
              "user.name", "actor.user.name", "actor.user.uid", "user.uid", "api.operation",
              "http_request.http_method", "query.hostname", "actor.user.email_addr", "user.email_addr"]
GOLD_ENUM = ["activity_id", "status_id"]


def flat(d, prefix=""):
    out = {}
    if isinstance(d, dict):
        for k, v in d.items():
            out.update(flat(v, f"{prefix}{k}."))
    elif not isinstance(d, list):
        out[prefix[:-1]] = d
    return out


def gold_pairs():
    """Return (records, labels). Skips superseded mapping versions."""
    recs, labels = [], []
    base = os.path.join(RAW, "ocsf-examples", "mappings")
    for rawf in sorted(glob.glob(base + "/**/*.raw", recursive=True)):
        rel = os.path.relpath(rawf, base)
        if any(v in rel for v in ("rc.2", "v1.0.0", "v1.1.0", "Zeek/v1.3.0/conn_log")):
            continue
        ocsff = rawf[:-4] + ".ocsf"
        if not os.path.exists(ocsff):
            continue
        raw = open(rawf, encoding="utf-8", errors="replace").read().strip("\n")
        try:
            gold = json.load(open(ocsff, encoding="utf-8", errors="replace"))
        except Exception:
            continue
        if isinstance(gold, list):
            if len(gold) != 1:
                continue
            gold = gold[0]
        if not isinstance(gold, dict) or "class_uid" not in gold or not raw.strip():
            continue
        try:  # a .raw holding several records cannot be paired with one .ocsf
            parsed = json.loads(raw)
            if isinstance(parsed, list):
                continue
        except Exception:
            if raw.lstrip().startswith(("{", "[")) or "\n" in raw.strip():
                continue
        fl = flat(gold)
        attrs = {p: fl[p] for p in GOLD_PATHS if p in fl and literal(fl[p], raw)}
        for p in GOLD_ENUM:
            if isinstance(fl.get(p), int) and fl[p] not in (0, 99):
                attrs[p] = fl[p]
        recs.append(raw)
        labels.append({"raw": raw, "group": None,
                       "values": sorted({str(v) for k, v in attrs.items() if k not in GOLD_ENUM}),
                       "ocsf": {"class_uid_any": [int(gold["class_uid"])], "attrs": attrs},
                       "basis": "ocsf-gold", "origin": rel})
    return recs, labels


# ---------------------------------------------------------------- sampling
def pick(labels: list[dict], n: int) -> list[dict]:
    """Round-robin over group labels (most frequent first), deterministic."""
    by = {}
    for lb in labels:
        by.setdefault(lb["group"] or "~" + str(len(lb["ocsf"]["attrs"])), []).append(lb)
    order = sorted(by, key=lambda g: (-len(by[g]), g))
    for g in order:
        by[g].sort(key=lambda lb: hashlib.md5(lb["raw"].encode("utf-8", "replace")).hexdigest())
    out, seen, i = [], set(), 0
    while len(out) < n and any(by.values()):
        g = order[i % len(order)]
        i += 1
        if by[g]:
            lb = by[g].pop(0)
            if lb["raw"] not in seen:
                seen.add(lb["raw"])
                out.append(lb)
    return out


def main() -> None:
    os.makedirs(OUT, exist_ok=True)
    manifest = json.load(open(os.path.join(CORPUS, "manifest.json")))
    schema = json.load(open(os.path.join(RAW, "ocsf-schema", "schema-1.10.0.json")))
    uids = {c["uid"] for c in schema["classes"].values()} | {0}
    all_labels = []
    for source, meta in manifest.items():
        if source == "ocsf_gold":
            continue
        lines = open(os.path.join(CORPUS, source + ".log"), encoding="utf-8",
                     errors="replace", newline="\n").read().split("\n")[:-1]
        if source in LOGHUB:
            labels = loghub_labels(source, lines)
        elif source in MANUAL_CLASS:
            labels = manual_labels(source, lines)
        else:
            labels = beats_labels(source, lines, meta)
        chosen = pick(labels, PER_SOURCE)
        for lb in chosen:
            lb["source"] = source
            lb["license"] = meta["license"]
        all_labels += chosen
        print(f"{source:22s} labelled {len(labels):5d}  picked {len(chosen):3d}  "
              f"groups {len({lb['group'] for lb in chosen if lb['group']}):2d}  "
              f"with class {sum(1 for lb in chosen if lb['ocsf']['class_uid_any']):2d}")

    recs, gold = gold_pairs()
    with open(os.path.join(CORPUS, "ocsf_gold.log"), "w", encoding="utf-8") as fh:
        for r in recs:
            fh.write(r + "\n")
    manifest["ocsf_gold"] = {
        "vendor": "various", "product": "ocsf/examples raw + .ocsf pairs", "lines": len(recs),
        "license": bc.LIC["ocsf-examples"][0], "attribution": bc.LIC["ocsf-examples"][1],
        "origin": [{"file": "ocsf-examples/mappings/" + g["origin"], "lines": 1} for g in gold],
    }
    json.dump(manifest, open(os.path.join(CORPUS, "manifest.json"), "w"), indent=1)
    for lb in gold:
        lb["source"] = "ocsf_gold"
        lb["license"] = bc.LIC["ocsf-examples"][0]
    all_labels += gold
    print(f"{'ocsf_gold':22s} labelled {len(gold):5d}  picked {len(gold):3d}")

    bad = sorted({u for lb in all_labels for u in (lb["ocsf"]["class_uid_any"] or []) if u not in uids})
    assert not bad, f"class uids missing from OCSF 1.10.0: {bad}"
    with open(os.path.join(OUT, "labels.jsonl"), "w", encoding="utf-8") as fh:
        for i, lb in enumerate(all_labels):
            lb = {"id": f"ev{i:04d}", **lb}
            fh.write(json.dumps(lb, ensure_ascii=False) + "\n")
    n = len(all_labels)
    print(f"\n{n} labelled lines, {len({lb['source'] for lb in all_labels})} sources; "
          f"{sum(1 for lb in all_labels if lb['group'])} with group truth, "
          f"{sum(1 for lb in all_labels if lb['values'])} with value truth, "
          f"{sum(1 for lb in all_labels if lb['ocsf']['class_uid_any'])} with OCSF class truth, "
          f"{sum(1 for lb in all_labels if lb['ocsf']['attrs'])} with OCSF attribute truth")


if __name__ == "__main__":
    main()
