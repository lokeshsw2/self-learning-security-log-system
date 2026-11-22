"""Shadow mode: a new rule version runs beside live traffic without publishing.

A rule saved with status `shadow` is executed by the engine for every record
of the groups that use its rule id. Only counters are kept (lines seen, lines
that parsed and validated). Its output is never written to the events table.
`review` activates a shadow rule once it has held on enough real lines, and
rejects it if it has seen enough lines and failed too many.

  python -m logparser.shadow --db run.db status
  python -m logparser.shadow --db run.db review
"""
from __future__ import annotations

import argparse
import json

from . import registry
from .engine import Engine


def propose(store, rule_id: str, body: dict, meta: dict | None = None) -> int:
    """Store a rule version in shadow. It affects nothing until promoted."""
    return registry.save_rule(store, rule_id, body, {**(meta or {}), "shadow": True}, status="shadow")


def status(store) -> list:
    out = []
    for r in store.rules(status="shadow"):
        c = store.q("SELECT lines, ok, last_error FROM shadow WHERE rule_id=? AND version=?",
                    (r["rule_id"], r["version"]))
        lines, ok, err = (c[0]["lines"], c[0]["ok"], c[0]["last_error"]) if c else (0, 0, None)
        out.append({"rule_id": r["rule_id"], "version": r["version"], "lines": lines, "ok": ok,
                    "ok_rate": round(ok / lines, 4) if lines else None, "last_error": err})
    return out


def review(engine: Engine) -> list:
    """Promote or reject shadow rules that have seen enough traffic."""
    s = engine.settings
    decisions = []
    for row in status(engine.store):
        if row["lines"] < s.shadow_min_lines:
            decisions.append({**row, "decision": "waiting", "needs_lines": s.shadow_min_lines})
            continue
        if row["ok_rate"] >= s.shadow_min_ok:
            engine.store.set_rule_status(row["rule_id"], row["version"], "active")
            sigs = [g["signature"] for g in engine.store.groups(
                "(parser_rule=? OR mapping_rule=?) AND merged_into IS NULL", (row["rule_id"], row["rule_id"]))]
            engine.reload()
            for sig in sigs:
                g = engine.groups.get(sig)
                if g and g["parser_rule"] and g["status"] in ("new", "queued", "longtail"):
                    g["status"] = "parsed"
                    engine.store.upsert_group(g)
            replay = engine.replay_signatures(sigs)
            decisions.append({**row, "decision": "promoted", "replayed": replay["records"]})
        else:
            engine.store.set_rule_status(row["rule_id"], row["version"], "rejected")
            decisions.append({**row, "decision": "rejected"})
    return decisions


def main(argv=None) -> None:
    from .cli import open_engine
    ap = argparse.ArgumentParser(prog="logparser.shadow")
    ap.add_argument("--db", required=True)
    ap.add_argument("--settings")
    ap.add_argument("cmd", choices=["status", "review"])
    a = ap.parse_args(argv)
    eng = open_engine(a)
    print(json.dumps(status(eng.store) if a.cmd == "status" else review(eng), indent=1))


if __name__ == "__main__":
    main()
