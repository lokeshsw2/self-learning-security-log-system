"""Combine the per-file results of scripts/full_run.py into one table.

  python scripts/full_summary.py work/full
"""
import collections
import json
import os
import sys

d = sys.argv[1]
rows = [json.load(open(os.path.join(d, f))) for f in sorted(os.listdir(d))
        if f.endswith(".json") and f != "summary.json"]
tot = collections.Counter()
hints = collections.Counter()
print(f"{'source':26s} {'lines':>11s} {'parsed':>7s} {'mapped':>7s} {'specific':>8s} {'new pat.':>8s} {'checks':>7s}")
for r in sorted(rows, key=lambda r: (r.get("mapped", 0) / max(r.get("lines", 1), 1), r["file"])):
    n = r.get("lines", 0) or 1
    chk = sum(v for k, v in r.items() if k.startswith("check_"))
    for k, v in r.items():
        if isinstance(v, int):
            tot[k] += v
    for key, cls, st, c in r.get("hints", []):
        hints[(key, cls, st)] += c
    print(f"{r['file']:26s} {r.get('lines', 0):11,d} {r.get('parsed', 0) / n:7.1%} {r.get('mapped', 0) / n:7.1%} "
          f"{r.get('specific_class', 0) / n:8.1%} {r.get('new_pattern', 0):8,d} {chk:7,d}")
n = tot["lines"] or 1
print(f"{'TOTAL':26s} {tot['lines']:11,d} {tot['parsed'] / n:7.2%} {tot['mapped'] / n:7.2%} "
      f"{tot['specific_class'] / n:8.2%} {tot['new_pattern']:8,d} "
      f"{sum(v for k, v in tot.items() if k.startswith('check_')):7,d}")
print("files:", len(rows), "| valid events:", f"{tot['valid']:,d} of {tot['mapped']:,d}",
      "| parse failures:", f"{tot['parse_failed']:,d}", "| no parser:", f"{tot['no_parser']:,d}",
      "| meaning-check flags:", {k[6:]: v for k, v in tot.items() if k.startswith("check_")})
print("worker seconds:", round(sum(r["seconds"] for r in rows)), "->",
      round(tot["lines"] / max(sum(r["seconds"] for r in rows), 1)), "lines per second per worker")
