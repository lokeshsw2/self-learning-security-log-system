"""Grouping quality of a run against the true source of each line.

  python scripts/grouping_compare.py RUN.db [--origin data/owner_mixed/_origin.jsonl]

Without --origin the run is per-file and the source label is the truth.
Reports, per true source: lines, groups the engine used for them, share parsed,
share mapped; then groups that hold lines of more than one true source.
"""
import collections
import json
import sqlite3
import sys

db = sqlite3.connect(sys.argv[1])
origin = None
if "--origin" in sys.argv:
    origin = {}
    for ln in open(sys.argv[sys.argv.index("--origin") + 1]):
        d = json.loads(ln)
        origin[d["offset"]] = d["source"]
truth, grp, status = {}, {}, {}
mapped = {r[0] for r in db.execute("select raw_id from events where mapping_rule != 'mapping:default-base'")}
for rid, src, off, sig, st in db.execute("select id, source, offset, signature, status from raw"):
    truth[rid] = origin.get(off, "?") if origin else src.split("|", 1)[0]
    grp[rid] = sig or f"none:{st}"
    status[rid] = st
by_src = collections.defaultdict(list)
by_grp = collections.defaultdict(collections.Counter)
for rid, t in truth.items():
    by_src[t].append(rid)
    by_grp[grp[rid]][t] += 1
tot = collections.Counter()
print(f"{'true source':26s} {'lines':>6s} {'groups':>6s} {'parsed':>7s} {'mapped':>7s} {'in mixed groups':>16s}")
mixed_groups = {g for g, c in by_grp.items() if len(c) > 1 and not g.startswith("none:")}
for s in sorted(by_src):
    rids = by_src[s]
    n = len(rids)
    gs = {grp[r] for r in rids}
    p = sum(status[r] == "parsed" for r in rids)
    m = sum(r in mapped for r in rids)
    mx = sum(grp[r] in mixed_groups for r in rids)
    tot.update(lines=n, groups=len(gs), parsed=p, mapped=m, mixed=mx)
    print(f"{s:26s} {n:6d} {len(gs):6d} {p / n:7.1%} {m / n:7.1%} {mx / n:16.1%}")
print(f"{'TOTAL':26s} {tot['lines']:6d} {len({grp[r] for r in truth}):6d} {tot['parsed'] / tot['lines']:7.1%} "
      f"{tot['mapped'] / tot['lines']:7.1%} {tot['mixed'] / tot['lines']:16.1%}")
print(f"\ngroups holding more than one true source: {len(mixed_groups)}")
tpl = dict(db.execute("select signature, substr(template,1,110) from groups"))
for g in sorted(mixed_groups, key=lambda g: -sum(by_grp[g].values()))[:12]:
    print(f"  {sum(by_grp[g].values()):6d}  {dict(by_grp[g].most_common(4))}  {tpl.get(g, '')}")
q = [r[0] for r in db.execute("select source from sources where quarantined=1")]
print("quarantined:", q, "lines:", sum(status[r] == "quarantined" for r in truth))
