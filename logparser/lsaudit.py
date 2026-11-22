"""Variant B self-audit and drift check: run each saved Logstash filter again, on more and newer lines.

A filter is saved after passing on 40 stored lines. The audit runs it in the sandbox on up to `limit` of the
group's most recent stored lines (the newest show format drift first) and, when ClickHouse is configured,
checks events Logstash already wrote there against their raw lines. Problems go back to the agent with
examples and the current rule (`needs-lsfilter`, reported_by audit); after `max_rounds` audits that still
fail, the group goes to a human (`human-review`, key `lsaudit:<group>`).

  python -m logparser.lsaudit --db run.db [--clickhouse http://localhost:8123 --ch-db lpsvc] [--no-route]
"""
from __future__ import annotations

import argparse
import json
import re
import urllib.request

from . import lsdirect as D
from .reader import Record

MAX_EXAMPLES = 3


def _records(e, g: dict, limit: int) -> list:
    rows = e.store.raw_by_signature(g["signature"], 100000)
    rows = [r for r in rows if r.get("raw")][-limit:]                 # the newest lines
    seen = {r["raw"] for r in rows}
    rows += [{"raw": s["raw"]} for s in e.store.samples(g["signature"]) if s["raw"] not in seen][:max(0, limit - len(rows))]
    out = []
    for i, r in enumerate(rows):
        det, _, _c = e.analyse(Record("lsaudit", 0, text=r["raw"]))
        h = {k: v for k, v in (det.header or {}).items() if isinstance(v, (str, int, float))}
        out.append({"id": i, "raw": r["raw"], "payload": det.payload, "h": h, "det": det})
    return out


def _add(found: dict, problem: str, raw: str, where: str) -> None:
    code = problem.split(":", 1)[0]
    f = found.setdefault(code, {"count": 0, "examples": []})
    f["count"] += 1
    if len(f["examples"]) < MAX_EXAMPLES:
        f["examples"].append({"line": raw[:400], "problem": problem[:300], "where": where})


def audit_group(e, sandbox, sig: str, limit: int = 200, clickhouse: tuple | None = None) -> dict | None:
    """Problems of one group's saved filter on its newest stored lines (sandbox) and, optionally, on events
    already in ClickHouse (url, database)."""
    from .sandbox import tables_for
    g = e.canonical(sig)
    rule = e.snap.rule("lsfilter:" + sig)
    if g is None or rule is None:
        return None
    body = rule["body"]
    found: dict = {}
    notes = []
    recs = _records(e, g, limit)
    lines = 0
    if recs:
        lab = {**D.labels_of(e, g), **(body.get("labels") or {})}
        text = D.render_group(body, e.schema, lab, sig, "T_sb", tz=e.deployment_tz())
        res = sandbox.run(text, [{"id": r["id"], "payload": r["payload"], "h": r["h"]} for r in recs],
                          tables_for(e.schema, body["class"]), tz=e.deployment_tz() or "UTC")
        if "error" in res:
            _add(found, f"config: Logstash refused the saved filter: {res['error']}", recs[0]["raw"], "sandbox")
        else:
            for r in recs:
                out = res["events"].get(r["id"]) or res["events"].get(str(r["id"]))
                probs = ["event: Logstash returned nothing for this line"] if out is None else \
                    D.judge(e.schema, r["det"], r["raw"], out, body)
                for p in probs[:3]:
                    _add(found, p, r["raw"], "stored lines")
            lines += len(recs)
    if clickhouse and re.fullmatch(r"[0-9a-f]{8,64}", sig) and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", clickhouse[1]):
        url, db = clickhouse
        q = (f"SELECT message, event_json FROM {db}.ocsf_events WHERE lp_group_id = '{sig}' "
             f"ORDER BY time DESC LIMIT {int(limit)} FORMAT JSONEachRow")
        try:
            rows = urllib.request.urlopen(urllib.request.Request(url.rstrip("/") + "/", data=q.encode()),
                                          timeout=30).read().decode().splitlines()
        except Exception as exc:          # an outage is not a fault of the filter
            rows = []
            notes.append(f"ClickHouse not checked: {exc}"[:200])
        for line in rows:
            r = json.loads(line)
            det, _, cols = e.analyse(Record("lsaudit", 0, text=r["message"]))
            sg = e._sign(det, None, cols)
            cg = e.canonical(sg.signature)
            if not cg or cg["signature"] != sig:
                _add(found, f"route: this line belongs to group {cg['signature'] if cg else None}, not this one",
                     r["message"], "clickhouse")
                continue
            ev = json.loads(r["event_json"])
            for p in D.judge(e.schema, det, r["message"], {"ocsf": ev, "sb": {"t": True, "f": None}}, body)[:3]:
                _add(found, p, r["message"], "clickhouse")
            lines += 1
    return {"signature": sig, "lines": lines, "rule": "lsfilter:" + sig, "rule_version": rule.get("version"),
            "problems": found, "notes": notes}


def route(e, report: dict, max_rounds: int = 2) -> str | None:
    """Back to the filter writer with the findings, or to a human after `max_rounds` failing audits."""
    if not report or not report["problems"]:
        if report:
            e.store.set_state(f"lsaudit_rounds:{report['signature']}", 0)
        return None
    sig = report["signature"]
    key = f"lsaudit_rounds:{sig}"
    rounds = int(e.store.get_state(key, 0) or 0)
    waiting = e.store.q("SELECT 1 FROM queue WHERE name='needs-lsfilter' AND key=? AND status='open' AND "
                        "json_extract(payload,'$.reported_by')='audit'", (sig,))
    if not waiting:
        rounds += 1
        e.store.set_state(key, rounds)
    g = e.canonical(sig)
    reason = ("Self-audit found problems in the events the saved Logstash filter produces: " +
              "; ".join(f"{c} on {p['count']} of {report['lines']} lines" for c, p in report["problems"].items()))
    examples = [dict(x, check=c) for c, p in report["problems"].items() for x in p["examples"][:2]][:6]
    payload = {"signature": sig, "bucket": g["bucket"], "format": g["format"], "source": g["source"],
               "count": g["count"], "reported_by": "audit", "audit_round": rounds, "reason": reason[:800],
               "examples": examples, "current_rule": e.snap.rule("lsfilter:" + sig)["body"]}
    if rounds > max_rounds:
        if e.store.q("SELECT 1 FROM queue WHERE name='human-review' AND key=?", (f"lsaudit:{sig}",)):
            return "human-review"
        e.store.enqueue("human-review", f"lsaudit:{sig}", {**payload, "question": (
            f"The filter writer could not fix this group's Logstash filter in {max_rounds} audit rounds. "
            f"{reason}")[:900]})
        e.store.queue_done("needs-lsfilter", sig, "flagged")
        return "human-review"
    e.store.reopen("needs-lsfilter", sig, payload)
    return "needs-lsfilter"


def run(e, sandbox, sigs: list | None = None, route_failures: bool = True, max_rounds: int = 2, limit: int = 200,
        clickhouse: tuple | None = None) -> dict:
    if sigs is None:
        sigs = sorted(r["rule_id"].split(":", 1)[1] for r in e.store.q(
            "SELECT rule_id FROM rules WHERE kind='lsfilter' AND status='active'"))
    reports, routed = [], {}
    for sig in sigs:
        rep = audit_group(e, sandbox, sig, limit, clickhouse)
        if rep is None:
            continue
        reports.append(rep)
        if route_failures:
            q = route(e, rep, max_rounds)
            if q:
                routed[q] = routed.get(q, 0) + 1
    failing = [r for r in reports if r["problems"]]
    by_check: dict = {}
    for r in failing:
        for c, p in r["problems"].items():
            by_check[c] = by_check.get(c, 0) + p["count"]
    out = {"groups_checked": len(reports), "groups_failing": len(failing),
           "lines_checked": sum(r["lines"] for r in reports), "by_check": by_check, "routed": routed,
           "failing": [{"signature": r["signature"], "lines": r["lines"], "problems": r["problems"]} for r in failing]}
    e.store.set_state("last_lsaudit", {k: v for k, v in out.items() if k != "failing"} |
                      {"failing": [{"signature": f["signature"], "checks": sorted(f["problems"])} for f in out["failing"][:50]]})
    return out


def main(argv=None) -> None:
    from .cli import open_engine
    from .sandbox import Sandbox
    import os
    ap = argparse.ArgumentParser(prog="logparser.lsaudit")
    ap.add_argument("--db", required=True)
    ap.add_argument("--settings", default="config/production.json")
    ap.add_argument("--clickhouse")
    ap.add_argument("--ch-db", default="lpsvc")
    ap.add_argument("--limit", type=int, default=200)
    ap.add_argument("--no-route", action="store_true")
    a = ap.parse_args(argv)
    e = open_engine(a)
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    sb = Sandbox(os.path.join(root, "work", "sandbox"))
    try:
        res = run(e, sb, route_failures=not a.no_route, limit=a.limit,
                  clickhouse=(a.clickhouse, a.ch_db) if a.clickhouse else None)
    finally:
        sb.stop()
    print(json.dumps(res, indent=1, default=str)[:20000])


if __name__ == "__main__":
    main()
