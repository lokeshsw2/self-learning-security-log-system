"""Results of a run on the reduced test stream, projected to the full volume with the line weights.

  python scripts/cover_report.py RUN.db data/owner_cover/_origin.jsonl [--stream mixed.log]
"""
import collections
import json
import sqlite3
import sys

db = sqlite3.connect(sys.argv[1])
stream = sys.argv[sys.argv.index("--stream") + 1] if "--stream" in sys.argv else "mixed.log"
origin = {}
for l in open(sys.argv[2]):
    d = json.loads(l)
    origin[d["offset"]] = d
mapped = {r[0]: r[1] for r in db.execute("select raw_id, class_uid from events where mapping_rule != 'mapping:default-base'")}
S = collections.defaultdict(lambda: collections.Counter())
for rid, off, st in db.execute("select id, offset, status from raw where stream=?", (stream,)):
    o = origin.get(off)
    if not o or o["kind"] != "pattern":
        continue
    w = o["weight"]
    c = S[o["source"]]
    c["w"] += w
    c["lines"] += 1
    if st == "parsed":
        c["parsed"] += w
    if rid in mapped:
        c["mapped"] += w
        if mapped[rid] not in (0, None):
            c["class"] += w
tot = collections.Counter()
print(f"{'source':26s} {'full lines':>11s} {'parsed':>7s} {'mapped':>7s} {'specific class':>15s}")
for s, c in sorted(S.items(), key=lambda kv: kv[1]["mapped"] / kv[1]["w"]):
    tot.update(c)
    if c["mapped"] < 0.999 * c["w"] or "-v" in sys.argv:
        print(f"{s:26s} {c['w']:11,.0f} {c['parsed'] / c['w']:7.1%} {c['mapped'] / c['w']:7.1%} {c['class'] / c['w']:15.1%}")
print(f"{'TOTAL (projected)':26s} {tot['w']:11,.0f} {tot['parsed'] / tot['w']:7.1%} {tot['mapped'] / tot['w']:7.1%} {tot['class'] / tot['w']:15.1%}")
print("queues opened:", dict(db.execute("select name, count(*) from queue where status='open' group by 1").fetchall()))
