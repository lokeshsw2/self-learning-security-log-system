"""Phase 5: Variant A and Variant B on the same mixed stream.

  python -m logparser.compare --a STORE_A --b STORE_B --files "logs/*.log" [--lines 20000] [--out report.json]

Each variant's set is built and verified as a deploy would (Variant A: rules compiled to Logstash, kept where
Logstash equals the engine; Variant B: the agents' Logstash filters, kept where they pass the gate). Both sets
then run in Logstash on the same lines. Per line and per format:

  coverage     lines that came out as an OCSF event
  correctness  the same checks for both: schema, values present in the line, time from the line, outcome words
  agreement    where both parse a line: class, activity, status, time, IPs, user
  richness     mapped attributes per event (excluding `unmapped`)
  speed        events per second in Logstash on the same lines
  cost         model spend per learned format, from each store's call log
"""
from __future__ import annotations

import argparse
import collections
import glob
import json
import os
import re
import time
import types

from .reader import Record

KEYS = [("class_uid",), ("activity_id",), ("status_id",), ("time",), ("src_endpoint", "ip"), ("dst_endpoint", "ip"),
        ("user", "name"), ("actor", "user", "name")]


def sample_lines(files: list, n: int, seed: int = 11) -> list:
    """A mixed stream: the files interleaved, every k-th line of each so the sample spans whole files."""
    import random
    sizes, per = {}, max(1, n // max(1, len(files)))
    for f in files:
        with open(f, "rb") as fh:
            sizes[f] = sum(1 for _ in fh)
    out = []
    for f in files:
        k = max(1, sizes[f] // per)
        with open(f, "rb") as fh:
            for i, ln in enumerate(fh):
                if i % k == 0 and ln.strip():
                    out.append(ln.rstrip(b"\r\n").decode("utf-8", "replace"))
    random.Random(seed).shuffle(out)
    return out[:n]


def _get(ev: dict, path: tuple):
    cur = ev
    for p in path:
        cur = cur.get(p) if isinstance(cur, dict) else None
    return cur


def _leaves(ev, prefix=""):
    n = 0
    for k, v in (ev or {}).items():
        if not prefix and k in ("unmapped", "metadata", "raw_data"):
            continue
        if isinstance(v, dict):
            n += _leaves(v, prefix + k + ".")
        elif isinstance(v, list):
            n += sum(_leaves(x, prefix + k + ".") if isinstance(x, dict) else 1 for x in v)
        elif v not in (None, ""):
            n += 1
    return n


def judge_a(e, det, raw: str, ev: dict, gid: str, now_ms: int) -> list:
    """Variant A event, the same checks as Variant B gets (schema, values in the line, time, outcome)."""
    from . import audit, checks
    probs = [f"schema: {x}" for x in e.schema.validate(ev)[0][:3]]
    g = e.canonical(gid)
    mapping = e._mapping(g["mapping_rule"]) if g and g["mapping_rule"] else {}
    consts, derived = audit._mapping_exempt(mapping, e.snap.rule)
    for p, v in audit._event_strings(ev):
        if v in consts or re.sub(r"\[\d+\]", "", p) in derived or audit._present(v, raw):
            continue
        probs.append(f"value: event `{p}` = {v!r} is not in this line")
    tags = ["time_from_ingest"] if ev.get("time") == now_ms else []
    probs += checks.problems(det, {}, ev, tags, mapping or {})
    return probs


def judge_b(e, det, raw: str, ev: dict, gid: str, now_ms: int) -> list:
    from . import lsdirect as D
    rule = e.snap.rule("lsfilter:" + gid)
    return D.judge(e.schema, det, raw, {"ocsf": ev, "sb": {"t": ev.get("time") != now_ms, "f": None}},
                   rule["body"] if rule else {})


def cost_per_group(store, roles: tuple) -> dict:
    """Model spend per group from the call log: {group: dollars} for the given agent roles."""
    out: dict = collections.defaultdict(float)
    for r in store.q("SELECT agent, target, detail FROM tool_calls WHERE tool='model_call'"):
        if r["agent"].split(":", 1)[-1] not in roles:
            continue
        m = re.search(r"\$([0-9.]+)", r["detail"] or "")
        if m and r["target"]:
            out[r["target"]] += float(m.group(1))
    return dict(out)


def build(store: str, variant: str, work: str, verify_per_group: int = 8):
    """The verified deploy set of one variant, as `Deployer.verify` builds it."""
    from .service.config import ServiceConfig
    from .service.deploy import Deployer
    cfg = ServiceConfig()
    cfg.store = {"url": "sqlite:///" + os.path.abspath(store)}
    cfg.logstash.variant = variant
    cfg.logstash.verify_per_group = verify_per_group
    os.makedirs(work, exist_ok=True)
    gen, used, history, causes, _n = Deployer(types.SimpleNamespace(cfg=cfg)).verify(work)
    return gen, used, history, causes


def run(store_a: str, store_b: str, lines: list, work: str, settings: str = "config/production.json") -> dict:
    from .cli import open_engine
    from .service.deploy import ROOT, _ls_verify
    lv = _ls_verify()
    now_ms = int(lv.NOW * 1000)
    ea = open_engine(types.SimpleNamespace(db=store_a, settings=settings))
    eb = open_engine(types.SimpleNamespace(db=store_b, settings=settings))
    res: dict = {"lines": len(lines), "variants": {}}
    events: dict = {}
    sets: dict = {}
    for name, store, variant in (("A", store_a, "compiled"), ("B", store_b, "direct")):
        gen, used, history, causes = build(store, variant, os.path.join(work, name))
        sets[name] = used
        recs = [{"id": i, "raw": l} for i, l in enumerate(lines)]
        evs, timing = lv.run_logstash(gen, recs, os.path.join(work, name), ROOT) if used else ({}, {})
        events[name] = evs
        res["variants"][name] = {"groups_deployed": len(used), "excluded": len(causes),
                                 "excluded_causes": dict(list(causes.items())[:10]), "timing": timing}
    # per line: which group the line belongs to (both stores share signatures), and each variant's verdict
    per_fmt: dict = collections.defaultdict(lambda: collections.Counter())
    agree = collections.Counter()
    disagreements: list = []
    examples: dict = {"A": [], "B": []}
    rich = {"A": [], "B": []}
    for i, raw in enumerate(lines):
        det, _, cols = ea.analyse(Record("cmp", 0, text=raw))
        sg = ea._sign(det, None, cols)
        cg = ea.canonical(sg.signature)
        gid = cg["signature"] if cg else None
        fmt = (cg or {}).get("format") or "new"
        got = {}
        for name, judge, eng in (("A", judge_a, ea), ("B", judge_b, eb)):
            ev = events[name].get(i) or {}
            g = (ev.get("lp") or {}).get("group_id")
            if not g or "lp_unparsed" in (ev.get("tags") or []):
                continue
            o = ev.get("ocsf") or {}
            probs = judge(eng, det, raw, o, g, now_ms)
            per_fmt[fmt][f"{name}_parsed"] += 1
            per_fmt[fmt][f"{name}_correct"] += 0 if probs else 1
            if probs and len(examples[name]) < 8:
                examples[name].append({"group": g, "line": raw[:300], "problem": probs[0][:200]})
            rich[name].append(_leaves(o))
            got[name] = o
        per_fmt[fmt]["lines"] += 1
        if gid in sets["A"] and gid in sets["B"]:
            per_fmt[fmt]["both_learned"] += 1
        if len(got) == 2:
            agree["both_parsed"] += 1
            diff = [".".join(p) for p in KEYS if _get(got["A"], p) != _get(got["B"], p)
                    and not (_get(got["A"], p) in (None, "") and _get(got["B"], p) in (None, ""))]
            agree["same_key_fields" if not diff else "differ"] += 1
            for p in diff:
                agree["differ:" + p] += 1
            if diff and len(disagreements) < 12:
                disagreements.append({"group": gid, "fields": {p: [_get(got["A"], tuple(p.split("."))),
                                                                  _get(got["B"], tuple(p.split(".")))] for p in diff},
                                      "line": raw[:250]})
    tot = collections.Counter()
    for c in per_fmt.values():
        tot.update(c)
    for name in ("A", "B"):
        v = res["variants"][name]
        v["parsed_lines"] = tot[f"{name}_parsed"]
        v["correct_lines"] = tot[f"{name}_correct"]
        v["coverage"] = round(tot[f"{name}_parsed"] / max(1, len(lines)), 4)
        v["correct_share_of_parsed"] = round(tot[f"{name}_correct"] / max(1, tot[f"{name}_parsed"]), 4)
        v["mapped_attributes_per_event"] = round(sum(rich[name]) / max(1, len(rich[name])), 1)
        v["problems"] = examples[name]
    res["by_format"] = {f: dict(c) for f, c in sorted(per_fmt.items(), key=lambda kv: -kv[1]["lines"])}
    res["agreement"] = dict(agree)
    res["disagreements"] = disagreements
    # cost of what each variant learned for its deployed groups
    ca = cost_per_group(ea.store, ("parser-gen", "ocsf-mapping"))
    cb = cost_per_group(eb.store, ("ls-direct",))
    for name, c, used in (("A", ca, sets["A"]), ("B", cb, sets["B"])):
        paid = [c[g] for g in used if g in c]
        res["variants"][name]["learning_cost_usd"] = {"deployed_groups_with_agent_rules": len(paid),
                                                     "total": round(sum(paid), 4),
                                                     "per_group": round(sum(paid) / len(paid), 4) if paid else None}
    res["groups"] = {"A_only": len(sets["A"] - sets["B"]), "B_only": len(sets["B"] - sets["A"]),
                     "both": len(sets["A"] & sets["B"])}
    return res


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(prog="logparser.compare")
    ap.add_argument("--a", required=True, help="Variant A store (sqlite path)")
    ap.add_argument("--b", required=True, help="Variant B store (sqlite path)")
    ap.add_argument("--files", required=True, help="glob of log files for the mixed stream")
    ap.add_argument("--lines", type=int, default=20000)
    ap.add_argument("--work", default="work/compare")
    ap.add_argument("--out")
    ap.add_argument("--settings", default="config/production.json")
    a = ap.parse_args(argv)
    lines = sample_lines(sorted(glob.glob(a.files)), a.lines)
    t0 = time.time()
    res = run(a.a, a.b, lines, os.path.abspath(a.work), a.settings)
    res["seconds"] = round(time.time() - t0)
    text = json.dumps(res, indent=1, default=str)
    if a.out:
        with open(a.out, "w") as fh:
            fh.write(text)
    print(text[:6000])


if __name__ == "__main__":
    main()
