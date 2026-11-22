"""Take a small, spread-out sample of each file in the owner's log folder.

The generated logs carry annotations such as ` # AttackHint=PortScan TTP=T1046`
that real logs do not have. They are removed from the line and written to a
side file as labels, so parsing sees a realistic line and evaluation can still
use the hint.

  python scripts/sample_logs.py "/path/to/logs data" data/owner_sample --lines 5000
"""
from __future__ import annotations

import argparse
import json
import os
import re

# from ` # SomethingHint=` to the end of the line, or to the end of the JSON string that holds the line
HINT = re.compile(rb' ?# ?[A-Za-z]+Hint=.*?(?=","[A-Za-z_]+":|"\}$|$)')
HINT_KV = re.compile(rb'([A-Za-z]+)=((?:\\".*?\\")|[^\s"\\]+)')


def sample(path: str, out: str, labels, n: int) -> tuple[int, int]:
    size = os.path.getsize(path)
    name = os.path.splitext(os.path.basename(path))[0]
    wrote = hinted = 0
    # n lines from 10 regions spread over the file, so drift inside a file shows up
    regions = 10
    per = max(1, n // regions)
    with open(path, "rb") as fh, open(out, "wb") as oh:
        for r in range(regions):
            fh.seek(size * r // regions)
            if r:
                fh.readline()                      # skip the partial line
            for _ in range(per):
                line = fh.readline()
                if not line:
                    break
                line = line.rstrip(b"\r\n")
                m = HINT.search(line)
                if m:
                    hint = m.group(0)
                    line = line[:m.start()] + line[m.end():]
                    hinted += 1
                    labels.write(json.dumps({"source": name, "line": wrote,
                                             "hints": {k.decode(): v.decode("utf-8", "replace")
                                                       for k, v in HINT_KV.findall(hint)}}) + "\n")
                oh.write(line + b"\n")
                wrote += 1
    return wrote, hinted


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("src")
    ap.add_argument("dst")
    ap.add_argument("--lines", type=int, default=5000)
    a = ap.parse_args()
    os.makedirs(a.dst, exist_ok=True)
    with open(os.path.join(a.dst, "_hints.jsonl"), "w") as labels:
        for f in sorted(os.listdir(a.src)):
            if not f.endswith(".log"):
                continue
            w, h = sample(os.path.join(a.src, f), os.path.join(a.dst, f), labels, a.lines)
            print(f"{f:36s} {w:6d} lines, {h:5d} with hints")


if __name__ == "__main__":
    main()
