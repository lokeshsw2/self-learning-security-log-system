"""Interleave the per-source sample files into one unlabelled stream, the way a
Kafka topic fed by many producers delivers them: short bursts from one source at
a time, in a random but fixed order. The true source of every line is written to
a side file by byte offset, for evaluation only; the engine never sees it.

  python scripts/build_mixed.py data/owner_sample data/owner_mixed
"""
import json
import os
import random
import sys

src, dst = sys.argv[1], sys.argv[2]
os.makedirs(dst, exist_ok=True)
rng = random.Random(7)
queues = {}
for f in sorted(os.listdir(src)):
    if f.endswith(".log"):
        with open(os.path.join(src, f), "rb") as fh:
            queues[f[:-4]] = [ln.rstrip(b"\n") for ln in fh if ln.strip()]
pos = {k: 0 for k in queues}
off = 0
with open(os.path.join(dst, "mixed.log"), "wb") as out, open(os.path.join(dst, "_origin.jsonl"), "w") as orig:
    live = [k for k in queues if queues[k]]
    while live:
        # weight by lines left so all sources run out at about the same time
        k = rng.choices(live, [len(queues[x]) - pos[x] for x in live])[0]
        for _ in range(rng.randint(1, 8)):
            if pos[k] >= len(queues[k]):
                break
            ln = queues[k][pos[k]]
            pos[k] += 1
            out.write(ln + b"\n")
            orig.write(json.dumps({"offset": off, "source": k}) + "\n")
            off += len(ln) + 1
        live = [x for x in live if pos[x] < len(queues[x])]
print(off, "bytes,", sum(len(v) for v in queues.values()), "lines from", len(queues), "sources")
