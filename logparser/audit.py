"""Self-audit: check the events that saved rules produce against their own lines.

The save gates check a rule once, on its samples, on what that gate knows to look at.
The audit checks the end result, the event that reaches the event store, on every stored
line of a group, whatever produced it. No model calls; everything here is code.

Per line:
  unparsed  the group has a rule, but this line does not parse
  invalid   the event fails OCSF schema validation
  value     a string the rule copied into the event is not in this line
  leak      the event message names a value that only other lines of the group carry
            (a description built from one sample line and reused for all)
  time      the event time disagrees with the line's own timestamp (checks.problems)
  outcome   the line says blocked or failed and the event says otherwise (checks.problems)
Per group:
  unapplied a rule saved for this exact group (`parser:` or `mapping:` + its id) is not the
            one the group uses. No rule the agents write can fix that: the code is
            wrong, so it goes straight to human review.

Before anything goes to a model, the fixed code re-applies itself: a long-tail rule whose
description was turned into slots by older code is rebuilt from the agent's own text
(Tools.retemplate_longtail) and audited again. Only what that does not fix is routed.

A failing group goes back to the queue of the agent that owns the rule, with the problem
and example lines as feedback. Rounds count agent attempts, not audits: auditing again while
the item still waits does not use up a round. A group whose agent has tried `audit_max_rounds`
times and still fails goes to human review: the agent could not fix it with a rule, so either
the rule language or the code is short of something.

Known limits: a value is checked for presence in its line, not its position, so two swapped
values that are both in the line (source and destination address) pass; tokens shorter than
three characters are not checked for leaks.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import types

from . import checks
from .engine import TOK
from .reader import Record

# transforms whose output is a new value, not text cut from the line
DERIVED = {"enum_lookup", "prefix", "dns_name", "scale", "syslog_severity", "windows_filetime", "parse_timestamp",
           "to_int", "to_float", "to_bool"}
SKIP_TOP = {"message", "raw_data", "unmapped", "metadata", "observables", "enrichments"}
MAX_EXAMPLES = 3


def _tokens(text: str) -> set:
    """Value-like tokens, lower-cased, without the punctuation that ends a sentence or wraps a value."""
    return {t.lower() for t in (x.strip(".-\\") for x in TOK.findall(text)) if len(t) >= 3}   # \" in JSON


def _present(v: str, raw: str) -> bool:
    """Is a copied value in the line, allowing for the decoding a parser does (JSON escapes,
    backslash escapes, case changes from lower/upper). A short value must be a whole token:
    "ok" is not in "token=book"."""
    if not v:
        return True
    if len(v) <= 3:
        return re.search(r"(?<![A-Za-z0-9])" + re.escape(v) + r"(?![A-Za-z0-9])", raw, re.I) is not None
    if v in raw:
        return True
    low = raw.lower()
    if v.lower() in low:
        return True
    for enc in (json.dumps(v, ensure_ascii=False)[1:-1], json.dumps(v)[1:-1]):
        if enc in raw:
            return True
    return v.replace("\\", "") in raw.replace("\\", "")


def _mapping_exempt(mapping: dict | None, lookup=None) -> tuple[set, set]:
    """(constant values, target paths filled by derived values) anywhere in a resolved mapping,
    following `use` / `extends` references to other mapping rules through `lookup`."""
    consts, derived, followed = set(), set(), set()

    def walk(m):
        if isinstance(m, dict):
            for key in ("use", "extends"):
                ref = m.get(key)
                if lookup and isinstance(ref, str) and ref not in followed:
                    followed.add(ref)
                    r = lookup(ref if ref.startswith("mapping:") else "mapping:base-" + ref)
                    if r:
                        walk(r["body"])
            for v in (m.get("constants") or {}).values():
                if isinstance(v, str):
                    consts.add(v)
            for f in m.get("fields") or []:
                if not isinstance(f, dict) or "to" not in f:
                    continue
                tr = f.get("transform")
                fns = {t.get("fn") for t in (tr if isinstance(tr, list) else [tr]) if isinstance(t, dict)}
                if fns & DERIVED or f.get("join") is not None:
                    derived.add(re.sub(r"\[\d+\]", "", f["to"]))
            for v in m.values():
                if isinstance(v, (dict, list, tuple)):
                    walk(v)
        elif isinstance(m, (list, tuple)):        # resolved switch branches are (when, mapping, rule id)
            for x in m:
                walk(x)
    walk(mapping or {})
    return consts, derived


def _event_strings(ev: dict, path: str = ""):
    """(path, value) for string leaves an event copied from the line; OCSF captions such as
    `status` next to `status_id` are produced by code and skipped."""
    for k, v in ev.items():
        p = f"{path}.{k}" if path else k
        if not path and k in SKIP_TOP:
            continue
        if isinstance(v, dict):
            yield from _event_strings(v, p)
        elif isinstance(v, list):
            for x in v:
                if isinstance(x, dict):
                    yield from _event_strings(x, p)
                elif isinstance(x, str):
                    yield p, x
        elif isinstance(v, str):
            base = k[:-5] if k.endswith("_name") else k
            if any(s in ev for s in (k + "_id", k + "_uid", base + "_id", base + "_uid")):
                continue
            yield p, v


def _lines(e, g: dict, limit: int) -> list:
    """Stored lines of a group: kept raw lines first, then samples; each line once."""
    seen, out = set(), []
    for r in e.store.raw_by_signature(g["signature"], limit):
        if r["raw"] and r["raw"] not in seen:
            seen.add(r["raw"])
            out.append((r["raw"], r["stream"], r["offset"], r["source"]))
    for s in e.store.samples(g["signature"]):
        if s["raw"] and s["raw"] not in seen and len(out) < limit:
            seen.add(s["raw"])
            out.append((s["raw"], "audit", 0, g["source"]))
    return out


def audit_group(e, sig: str, limit: int = 200) -> dict | None:
    """Check every stored line of one group. None when the group has nothing to audit."""
    g = e.canonical(sig)
    if g is None or g["status"] == "split" or g["merged_into"]:
        return None
    unapplied = []
    for kind, used in (("parser", g["parser_rule"]), ("mapping", g["mapping_rule"])):
        own = e.snap.rule(f"{kind}:{g['signature']}")
        if own and used != own["rule_id"]:
            unapplied.append(f"`{own['rule_id']}` exists, but the group uses {used or 'no ' + kind}")
    has_rule = g["parser_rule"] or e.snap.rule("longtail:" + g["signature"]) or g["mapping_rule"]
    if not has_rule and not unapplied:
        return None
    rows = []
    for raw, stream, offset, source in _lines(e, g, limit):
        label = (source or "-").split("|", 1)[0]
        rec = Record(stream or "audit", offset or 0, text=raw, label=None if label == "-" else label,
                     columns=e._header_of(g))
        det, _, cols = e.analyse(rec)
        sg = e._sign(det, rec.label, cols)
        rows.append((raw, det, sg, e.parse_record(g, det, sg, rec)))
    if not rows:
        return None
    # tokens of every line's masked values and header: a message token from this set that is
    # not in its own line came from another line of the group
    group_tokens = set()
    for _, det, sg, _ in rows:
        for _, v in sg.variables:
            group_tokens |= _tokens(v)
        for h in det.header.values():
            if isinstance(h, str):
                group_tokens |= _tokens(h)
    found: dict = {}

    def add(code: str, raw: str, detail: str) -> None:
        f = found.setdefault(code, {"count": 0, "examples": []})
        f["count"] += 1
        if len(f["examples"]) < MAX_EXAMPLES:
            f["examples"].append({"line": raw[:400], "problem": detail[:300]})

    owner = "mapping"
    for raw, det, sg, res in rows:
        if res.get("status") != "parsed":
            add("unparsed", raw, f"the group's rule does not parse this line ({res.get('reason') or res.get('status')})")
            continue
        longtail = str(res.get("parser_rule") or "").startswith("longtail:")
        if longtail:
            owner = "longtail"
        fields, ev = res.get("fields") or {}, res.get("event") or {}
        for k, v in fields.items():
            if k.startswith(("@", "_")) or k == "summary" or not isinstance(v, str):   # _text: parser leftovers
                continue
            if not _present(v, raw):
                add("value", raw, f"parsed field `{k}` = {v!r} is not in this line")
                if not longtail:
                    owner = "parser"
        if ev:
            if res.get("valid") is False:
                add("invalid", raw, "; ".join(str(x) for x in (res.get("errors") or [])[:2]) or "schema validation failed")
            mapping = e._mapping(res.get("mapping_rule"))
            consts, derived = _mapping_exempt(mapping, e.snap.rule)
            for p, v in _event_strings(ev):
                if v in consts or re.sub(r"\[\d+\]", "", p) in derived or _present(v, raw):
                    continue
                add("value", raw, f"event `{p}` = {v!r} is not in this line")
            msg = ev.get("message")
            if isinstance(msg, str) and msg.strip() != raw.strip():
                static = sg.template
                own = _tokens(raw) | _tokens(static)
                leaked = sorted(t for t in _tokens(msg) if t in group_tokens and t not in own)
                if leaked:
                    add("leak", raw, f"the event message names {', '.join(leaked[:4])}, which this line does not "
                                     f"contain (taken from another line of the group): {msg[:160]!r}")
            for p in checks.problems(det, fields, ev, res.get("tags") or [], mapping or {}):
                add(p.split(":", 1)[0], raw, p)
    if found.get("unparsed") and owner == "mapping":
        owner = "longtail" if not g["parser_rule"] and e.snap.rule("longtail:" + g["signature"]) else "parser"
    for u in unapplied:
        found.setdefault("unapplied", {"count": 0, "examples": []})
        found["unapplied"]["count"] += 1
        found["unapplied"]["examples"].append({"line": rows[0][0][:400], "problem": u})
    if unapplied:
        owner = "code"
    return {"signature": g["signature"], "source": g["source"], "lines": len(rows),
            "rule": g["parser_rule"] or "longtail:" + g["signature"], "mapping": g["mapping_rule"],
            "owner": owner if found else None, "problems": found}


QUEUE = {"parser": "needs-parser", "mapping": "needs-mapping", "longtail": "longtail"}


def route(e, report: dict, max_rounds: int = 2) -> str | None:
    """Send a failing group back to the agent that owns it, with the findings as feedback, or to
    human review once it has failed `max_rounds` audits. Returns the queue used."""
    if not report or not report["problems"]:
        return None
    sig = report["signature"]
    key = f"audit_rounds:{sig}"
    rounds = int(e.store.get_state(key, 0) or 0)
    q_owner = QUEUE.get(report["owner"])
    waiting = q_owner and e.store.q("SELECT 1 FROM queue WHERE name=? AND key=? AND status='open' AND "
                                    "json_extract(payload,'$.reported_by')='audit'", (q_owner, sig))
    if not waiting:          # the agent worked the last report (or there was none): this is a new round
        rounds += 1
        e.store.set_state(key, rounds)
    g = e.canonical(sig)
    reason = "Self-audit found problems in the events this group's saved rules produce: " + "; ".join(
        f"{code} on {p['count']} of {report['lines']} lines" for code, p in report["problems"].items())
    examples = [dict(x, check=code) for code, p in report["problems"].items() for x in p["examples"][:2]][:6]
    payload = {"signature": sig, "bucket": g["bucket"], "source": g["source"], "count": g["count"],
               "reported_by": "audit", "audit_round": rounds, "current_rule": report["rule"],
               "current_mapping": report["mapping"], "reason": reason[:800], "examples": examples}
    if rounds > max_rounds or report["owner"] == "code":
        if e.store.q("SELECT 1 FROM queue WHERE name='human-review' AND key=?", (f"audit:{sig}",)):
            return "human-review"      # already with a human, open or resolved: never reopened by code
        why = ("A saved rule is not applied to its own group: this is a code problem, not one a rule can fix."
               if report["owner"] == "code" else
               f"The agents could not fix this group in {max_rounds} rounds. Either a rule cannot express what "
               f"is needed or the code is wrong.")
        e.store.enqueue("human-review", f"audit:{sig}", {**payload, "question": f"{why} {reason}"[:900]})
        if q_owner:
            e.store.queue_done(q_owner, sig, "flagged")
        return "human-review"
    q = QUEUE[report["owner"]]
    e.store.reopen(q, sig, payload)
    return q


def run(e, sigs: list | None = None, route_failures: bool = True, max_rounds: int = 2, limit: int = 200,
        repair: bool = True) -> dict:
    """Audit these groups (all groups with a rule when None) and route the failures."""
    if sigs is None:
        sigs = [g["signature"] for g in e.store.groups("merged_into IS NULL AND status != 'split'")
                if g["parser_rule"] or e.snap.rule("longtail:" + g["signature"])]
    e.reload()
    out = {"groups_checked": 0, "groups_failing": 0, "lines_checked": 0, "by_check": {}, "routed": {},
           "fixed_by_code": 0, "failing": []}
    done = set()
    for sig in sigs:
        rep = audit_group(e, sig, limit)
        if rep and rep["problems"] and repair and rep["owner"] == "longtail" and set(rep["problems"]) <= {"leak"}:
            from .tools import Refused, Tools
            try:
                if Tools(e, "audit").retemplate_longtail(rep["signature"])["changed"]:
                    e.reload()
                    again = audit_group(e, sig, limit)
                    if again is not None and not again["problems"]:
                        out["fixed_by_code"] += 1
                        e.replay_signatures([rep["signature"]])       # stored events and the sink get the fix
                    rep = again or rep
            except Refused:
                pass
        if rep is None or rep["signature"] in done:
            continue
        done.add(rep["signature"])
        out["groups_checked"] += 1
        out["lines_checked"] += rep["lines"]
        if not rep["problems"]:
            continue
        out["groups_failing"] += 1
        for code, p in rep["problems"].items():
            out["by_check"][code] = out["by_check"].get(code, 0) + p["count"]
        q = route(e, rep, max_rounds) if route_failures else None
        if q:
            out["routed"][q] = out["routed"].get(q, 0) + 1
        out["failing"].append({"signature": rep["signature"], "source": rep["source"], "lines": rep["lines"],
                               "owner": rep["owner"], "sent_to": q,
                               "problems": {c: {"count": p["count"], "example": p["examples"][0]}
                                            for c, p in rep["problems"].items()}})
    e.store.log_tool("audit", "audit", None, True, json.dumps({k: out[k] for k in (
        "groups_checked", "groups_failing", "by_check", "routed", "fixed_by_code")})[:1000])
    return out


def main(argv=None) -> None:
    from .cli import open_engine
    from .envfile import load_env
    load_env()
    ap = argparse.ArgumentParser(prog="logparser.audit", description="Self-audit saved rules against their own lines "
                                                                     "(no model calls).")
    ap.add_argument("--db", required=True)
    ap.add_argument("--settings")
    ap.add_argument("--sig", action="append", help="audit only these groups (default: every group with a rule)")
    ap.add_argument("--route", action="store_true", help="send failing groups back to the agents' queues")
    ap.add_argument("--limit", type=int, default=200, help="lines per group")
    a = ap.parse_args(argv)
    e = open_engine(types.SimpleNamespace(db=a.db, settings=a.settings))
    res = run(e, a.sig, route_failures=a.route, max_rounds=e.settings.audit_max_rounds, limit=a.limit,
              repair=a.route)
    json.dump(res, sys.stdout, indent=1, default=str)
    print()


if __name__ == "__main__":
    main()
