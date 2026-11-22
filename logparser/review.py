"""Review loop: human corrections to AI-written rules.

A reviewer replaces a rule body and says why. The corrected rule goes through
the same validation as any other rule and becomes the active version. The
correction is stored, and the agent harness shows the most recent corrections
of that kind to the agent the next time it runs.

  python -m logparser.review --db run.db pending
  python -m logparser.review --db run.db correct mapping:SIG --file fixed.json --why "status was inverted" --author ana
"""
from __future__ import annotations

import argparse
import json
import time

from . import registry

ROLE = {"mask": "mask-repair", "sign": "mask-repair", "parser": "parser-gen", "mapping": "ocsf-mapping"}


def pending(store) -> list:
    """AI-written mappings no human has looked at yet."""
    out = []
    for r in store.rules("mapping"):
        if r["meta"].get("needs_human_review") and not r["meta"].get("reviewed_by"):
            out.append({"rule_id": r["rule_id"], "version": r["version"], "class": r["body"].get("class"),
                        "created_by": r["meta"].get("created_by"),
                        "low_confidence": [f["to"] for f in r["body"].get("fields", [])
                                           if f.get("confidence") == "low"]})
    return out


def correct(engine, rule_id: str, body: dict, why: str, author: str) -> dict:
    kind = registry.kind_of(rule_id)
    old = engine.store.active_rule(rule_id)
    version = registry.save_rule(engine.store, rule_id, body, {
        "created_by": f"human:{author}", "reviewed_by": author, "note": why})
    engine.store.x("INSERT INTO corrections(at,kind,target,body,author) VALUES(?,?,?,?,?)", (
        time.time(), ROLE.get(kind, kind), rule_id,
        json.dumps({"why": why, "before": old["body"] if old else None, "after": body}, ensure_ascii=False), author))
    sigs = [g["signature"] for g in engine.store.groups("parser_rule=? OR mapping_rule=?", (rule_id, rule_id))]
    return {"rule_id": rule_id, "version": version, "replay": engine.replay_signatures(sigs)}


def approve(store, rule_id: str, author: str) -> None:
    r = store.active_rule(rule_id)
    if not r:
        raise registry.RuleError(f"no active rule {rule_id}")
    meta = {**r["meta"], "reviewed_by": author, "reviewed_at": time.time()}
    store.x("UPDATE rules SET meta=? WHERE rule_id=? AND version=?", (json.dumps(meta), rule_id, r["version"]))


def main(argv=None) -> None:
    from .cli import open_engine
    ap = argparse.ArgumentParser(prog="logparser.review")
    ap.add_argument("--db", required=True)
    ap.add_argument("--settings")
    ap.add_argument("cmd", choices=["pending", "correct", "approve"])
    ap.add_argument("rule_id", nargs="?")
    ap.add_argument("--file")
    ap.add_argument("--why", default="")
    ap.add_argument("--author", default="reviewer")
    a = ap.parse_args(argv)
    eng = open_engine(a)
    if a.cmd == "pending":
        print(json.dumps(pending(eng.store), indent=1))
    elif a.cmd == "approve":
        approve(eng.store, a.rule_id, a.author)
        print("approved")
    else:
        print(json.dumps(correct(eng, a.rule_id, json.load(open(a.file)), a.why, a.author), indent=1))


if __name__ == "__main__":
    main()
