"""Per-source summary of a run: parsed share, mapped share, group counts, repair queue."""
import collections
import sqlite3
import sys

db = sqlite3.connect(sys.argv[1])
L = collections.defaultdict(collections.Counter)
for src, st, n in db.execute("select source,status,count(*) from raw group by 1,2"):
    L[src.split("|")[0]][st] += n
G, LT, F = collections.Counter(), collections.Counter(), collections.defaultdict(set)
for src, st, b in db.execute("select source,status,bucket from groups where merged_into is null and status!='split'"):
    lab = src.split("|")[0]
    G[lab] += 1
    LT[lab] += st == "longtail"
    F[lab].add(b.split("|")[0])
M = collections.Counter()
for src, n in db.execute("select r.source,count(*) from events e join raw r on r.id=e.raw_id "
                         "where e.mapping_rule!='mapping:default-base' group by 1"):
    M[src.split("|")[0]] += n
tot = collections.Counter()
print(f"{'source':26s} {'parsed':>7s} {'mapped':>7s} {'groups':>6s} {'tail':>5s}  format chain")
for lab, c in sorted(L.items(), key=lambda kv: (kv[1]["parsed"] / max(sum(kv[1].values()), 1), kv[0])):
    n = sum(c.values())
    tot.update(lines=n, parsed=c["parsed"], mapped=M[lab], groups=G[lab])
    if c["parsed"] < n or "-v" in sys.argv:
        print(f"{lab:26s} {c['parsed'] / n:7.0%} {M[lab] / n:7.0%} {G[lab]:6d} {LT[lab]:5d}  {', '.join(sorted(F[lab]))[:80]}")
print(f"{'TOTAL':26s} {tot['parsed'] / tot['lines']:7.1%} {tot['mapped'] / tot['lines']:7.1%} {tot['groups']:6d}"
      f"   ({sum(1 for c in L.values() if c['parsed'] == sum(c.values()))} of {len(L)} sources fully parsed)")
print("queues:", dict(db.execute("select name||'/'||status, count(*) from queue group by 1").fetchall()))
print("repair questions:", dict(collections.Counter(k.split(":")[0] for (k,) in db.execute(
    "select key from queue where name='grouping-repair' and status='open'"))))
print("operations:", dict(db.execute("select op||'/'||tier||'/'||status, count(*) from operations group by 1").fetchall()))
print("quarantined:", [r[0] for r in db.execute("select source from sources where quarantined=1")])
