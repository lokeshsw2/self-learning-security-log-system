"""Build a small mixed test stream that covers every pattern found by the scan.

Each pattern is written min(count, CAP) times, cycling through its diverse
example lines, so frequency thresholds still fire. Each line carries a weight
(real lines it stands for) so rates on this stream project to the full volume.
A random sample of every file is added as a check on the grouping itself.
Lines are interleaved in short bursts per source, like a multi-producer topic.

  python scripts/build_cover.py work/scan data/owner_cover --cap 60
"""
from __future__ import annotations

import argparse
import json
import os
import random


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("scan")
    ap.add_argument("out")
    ap.add_argument("--cap", type=int, default=60)
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    rng = random.Random(11)
    per_src: dict = {}
    stats = {"patterns": 0, "lines_full": 0, "lines_written": 0}
    for f in sorted(os.listdir(a.scan)):
        if not f.endswith(".json") or f == "summary.json":
            continue
        d = json.load(open(os.path.join(a.scan, f)))
        src = d["file"]
        out = []
        for sig, p in d["patterns"].items():
            copies = min(p["count"], a.cap)
            w = p["count"] / copies
            for i in range(copies):
                s = p["samples"][i % len(p["samples"])]
                out.append({"text": s["text"], "source": src, "line": s["line"], "pattern": sig, "weight": w,
                            "hints": s.get("hints"), "kind": "pattern"})
            stats["patterns"] += 1
        for s in d["random"]:
            out.append({"text": s["text"], "source": src, "line": s["line"], "pattern": None, "weight": 0,
                        "hints": s.get("hints"), "kind": "random"})
        rng.shuffle(out)
        per_src[src] = out
        stats["lines_full"] += d["lines"]
    pos = {k: 0 for k in per_src}
    off = 0
    with open(os.path.join(a.out, "mixed.log"), "wb") as fh, open(os.path.join(a.out, "_origin.jsonl"), "w") as oh:
        live = [k for k in per_src if per_src[k]]
        while live:
            k = rng.choices(live, [len(per_src[x]) - pos[x] for x in live])[0]
            for _ in range(rng.randint(1, 8)):
                if pos[k] >= len(per_src[k]):
                    break
                r = per_src[k][pos[k]]
                pos[k] += 1
                b = r["text"].encode("utf-8") + b"\n"
                fh.write(b)
                oh.write(json.dumps({"offset": off, **{x: r[x] for x in r if x != "text"}}) + "\n")
                off += len(b)
                stats["lines_written"] += 1
            live = [x for x in live if pos[x] < len(per_src[x])]
    json.dump(stats, open(os.path.join(a.out, "_stats.json"), "w"), indent=1)
    print(json.dumps(stats), f"{off / 1e6:.1f} MB")


if __name__ == "__main__":
    main()
