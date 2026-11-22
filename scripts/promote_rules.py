"""Copy what the agents learned in one database (e.g. a test copy) into another.

  python scripts/promote_rules.py --from work/learn_test/test3.db --to work/app.db [--dry-run]
  python scripts/promote_rules.py --from local.db --to "mysql://lp:${MYSQL_PASSWORD}@db.host:3306/logparser"

Copies:
- active rules that the target lacks or holds with a different body (validated first,
  all or nothing, through registry.import_rules; the original author stays in meta)
- grouping decisions the target has not answered, so the repair scan does not ask again
- grouping operations (the audit trail a rollback needs) that the target does not have
Group and source state is not copied: the target builds it from its own traffic, and new
groups pick up `parser:<sig>`, `mapping:<sig>` and `longtail:<sig>` rules by signature.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from logparser import registry  # noqa: E402
from logparser.store import open_store  # noqa: E402


def natural_ids(db: str, rule_ids: list) -> dict:
    """rule id -> signatures the group's stored lines get under the current masks, other than its own id."""
    import types
    from logparser.cli import open_engine
    from logparser.reader import Record
    e = open_engine(types.SimpleNamespace(db=db, settings=None))
    out = {}
    for rid in rule_ids:
        kind, _, sig = rid.partition(":")
        if kind not in ("parser", "mapping", "longtail", "lsfilter") or sig not in e.groups:
            continue
        g = e.groups[sig]
        if g["detail"].get("parent"):
            continue                          # split pieces are keyed by parent and value: stable already
        lab = g["source"].split("|", 1)[0]
        lines = [s["raw"] for s in e.store.samples(sig)]
        lines += [r["raw"] for r in e.store.raw_by_signature(sig, 500) if r["raw"]]
        nat = set()
        for raw in lines:
            rec = Record("promote", 0, text=raw, label=None if lab == "-" else lab)
            det, _, cols = e.analyse(rec)
            n = e._sign(det, rec.label, cols).signature
            if n != sig and (e.canonical(n) or {}).get("signature") == sig:
                nat.add(n)
        if nat:
            out[rid] = sorted(nat)
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--from", dest="src", required=True)
    ap.add_argument("--to", dest="dst", required=True)
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()
    src, dst = open_store(a.src), open_store(a.dst)

    rules = []
    for r in src.rules(status="active"):
        cur = dst.active_rule(r["rule_id"])
        if cur and cur["body"] == r["body"]:
            continue
        meta = dict(r["meta"] or {})
        meta["imported_from"] = os.path.basename(a.src) if not a.src.startswith("mysql") else src.path
        rules.append({"rule_id": r["rule_id"], "status": "active", "body": r["body"], "meta": meta})

    # A merged group keeps an old id; a fresh database computes the id from the current masks.
    # File group-keyed rules under every id the group's stored lines produce now as well.
    aliases = natural_ids(a.src, [r["rule_id"] for r in rules])
    for r in list(rules):
        for nat in aliases.get(r["rule_id"], ()):
            rid = r["rule_id"].split(":", 1)[0] + ":" + nat
            if any(x["rule_id"] == rid for x in rules) or src.active_rule(rid) or dst.active_rule(rid):
                continue
            rules.append({**r, "rule_id": rid, "meta": {**r["meta"], "alias_of": r["rule_id"]}})

    have = {(d["scope"], d["question"]) for d in dst.decisions()}
    decisions = [d for d in src.decisions() if (d["scope"], d["question"]) not in have]

    seen = {(o["op"], o["target"], o["params"]) for o in dst.q("SELECT op, target, params FROM operations")}
    ops = [dict(o) for o in src.q("SELECT * FROM operations ORDER BY id") if (o["op"], o["target"], o["params"]) not in seen]

    by_kind: dict = {}
    for r in rules:
        k = r["rule_id"].split(":", 1)[0]
        by_kind[k] = by_kind.get(k, 0) + 1
    print(json.dumps({"rules": len(rules), "by_kind": by_kind, "decisions": len(decisions), "operations": len(ops)}))
    if a.dry_run:
        for r in rules:
            print("  ", r["rule_id"], "by", r["meta"].get("created_by"))
        return

    if rules:
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            json.dump({"format": "logparser-registry/1", "rules": rules}, fh)
        try:
            print("rules (saved, unchanged):", registry.import_rules(dst, fh.name))
        finally:
            os.unlink(fh.name)
    for d in decisions:
        dst.x("INSERT OR IGNORE INTO decisions(at,scope,question,answer,answered_by,tier) VALUES(?,?,?,?,?,?)",
              (d["at"], d["scope"], d["question"], d["answer"], d["answered_by"], d["tier"]))
    for o in ops:
        dst.x("INSERT INTO operations(at,batch,op,target,params,verification,tier,by,status,baseline) "
              "VALUES(?,?,?,?,?,?,?,?,?,?)", (o["at"], o["batch"], o["op"], o["target"], o["params"],
                                               o["verification"], o["tier"], o["by"], o["status"], o["baseline"]))
    print(f"decisions copied: {len(decisions)}, operations copied: {len(ops)}")


if __name__ == "__main__":
    main()
