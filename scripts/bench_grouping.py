"""Grouping accuracy on Loghub (16 datasets, 2,000 hand-labelled lines each).

Runs only the deterministic front of the pipeline (detect, mask, signature,
merge) with the builtin rules and no AI. Reports, per dataset:
  truth   number of hand-labelled templates
  groups  number of groups the engine formed
  GA      grouping accuracy: share of lines whose group holds exactly the same
          lines as their hand-labelled template (the standard Loghub metric)
"""
from __future__ import annotations

import csv
import json
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from logparser import registry  # noqa: E402
from logparser.config import Settings  # noqa: E402
from logparser.engine import Engine  # noqa: E402
from logparser.store import SqliteStore  # noqa: E402

LOGHUB = os.path.join(ROOT, "data", "raw", "loghub")


def run(name: str, schema=None):
    log = os.path.join(LOGHUB, name, f"{name}_2k.log")
    truth = [r["EventId"] for r in csv.DictReader(open(log + "_structured.csv", encoding="utf-8", errors="replace"))]
    with tempfile.TemporaryDirectory() as tmp:
        store = SqliteStore(os.path.join(tmp, "b.db"))
        registry.import_rules(store, os.path.join(ROOT, "registry", "builtin.json"))
        eng = Engine(store, Settings(signature_cap=10 ** 9, explosion_ratio=2.0), schema=schema)
        eng.run_file(log, label=name)
        rows = store.q("SELECT id, signature, status FROM raw ORDER BY id")
        pred = []
        for r in rows:
            g = eng.canonical(r["signature"]) if r["signature"] else None
            pred.append(g["signature"] if g else f"none:{r['status']}")
        schema = eng.schema
    if len(pred) != len(truth):
        return {"dataset": name, "error": f"{len(pred)} records for {len(truth)} labelled lines"}, schema
    by_t, by_p = {}, {}
    for i, (t, p) in enumerate(zip(truth, pred)):
        by_t.setdefault(t, set()).add(i)
        by_p.setdefault(p, set()).add(i)
    correct = sum(len(s) for s in by_p.values() if any(s == ts for ts in [by_t[truth[next(iter(s))]]]))
    return {"dataset": name, "lines": len(truth), "truth": len(by_t), "groups": len(by_p),
            "GA": round(correct / len(truth), 3)}, schema


def main():
    names = sorted(d for d in os.listdir(LOGHUB) if os.path.isdir(os.path.join(LOGHUB, d)) and not d.startswith("."))
    out, schema = [], None
    for n in names:
        res, schema = run(n, schema)
        out.append(res)
        print(f"{res['dataset']:12s} truth {res.get('truth', '-'):>4} groups {res.get('groups', '-'):>5} "
              f"GA {res.get('GA', res.get('error'))}")
    ga = [r["GA"] for r in out if "GA" in r]
    print(f"\nmean GA over {len(ga)} datasets: {sum(ga) / len(ga):.3f}")
    os.makedirs(os.path.join(ROOT, "work"), exist_ok=True)
    json.dump(out, open(os.path.join(ROOT, "work", "bench_grouping.json"), "w"), indent=1)


if __name__ == "__main__":
    main()
