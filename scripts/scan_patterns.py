"""Scan full log files for distinct patterns, code only (detect + signature).

For every file, in parallel: count lines per signature, keep up to K diverse
example lines per signature (lines that add new words), a random sample of the
file, and a curve of distinct signatures against lines read. Hint annotations
are stripped as in sample_logs.py and kept as labels.

  python scripts/scan_patterns.py "/path/to/logs data" work/scan --rules registry/exports/scan-rules.json

Output: work/scan/<file>.json per file and work/scan/summary.json.
"""
from __future__ import annotations

import argparse
import json
import os
import random
import sys
import time
from multiprocessing import Pool

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "scripts"))

K = 20            # diverse example lines kept per signature
RANDOM_N = 300    # random lines kept per file
CURVE_EVERY = 50_000


def _snapshot(rules_files: list):
    from logparser import registry
    from logparser.store import SqliteStore
    st = SqliteStore(":memory:")
    for f in rules_files:
        registry.import_rules(st, f)
    return registry.Snapshot(st)


def strip_hints(line: bytes):
    """Same rules as sample_logs.py: returns (line, hints or None)."""
    import sample_logs as sl
    found = None
    if b'Hint"' in line and line.lstrip().startswith(b"{"):
        try:
            obj = json.loads(line)
            hits = {}

            def walk(o):
                if isinstance(o, dict):
                    for k in [k for k in o if k.endswith("Hint") or k == "TTP"]:
                        hits[k] = str(o.pop(k))
                    for v in o.values():
                        walk(v)
                elif isinstance(o, list):
                    for v in [v for v in o if isinstance(v, dict) and isinstance(v.get("key"), str)
                              and (v["key"].endswith("Hint") or v["key"] == "TTP")]:
                        hits[v["key"]] = str(v.get("value"))
                        o.remove(v)
                    for v in o:
                        walk(v)
            walk(obj)
            if hits:
                line = json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode()
                found = hits
        except ValueError:
            pass
    m = sl.HINT.search(line)
    if m:
        found = {**(found or {}), **{k.decode(): v.decode("utf-8", "replace") for k, v in sl.HINT_KV.findall(m.group(0))}}
        line = line[:m.start()] + line[m.end():]
    return line, found


def scan_file(args):
    path, rules_files, out_dir = args
    from logparser import signature
    from logparser.detect import detect
    snap = _snapshot(rules_files)
    name = os.path.splitext(os.path.basename(path))[0]
    rng = random.Random(name)
    sigs: dict = {}
    randoms, curve, hinted = [], [], 0
    t0 = time.time()
    n = 0
    with open(path, "rb") as fh:
        for raw in fh:
            raw = raw.rstrip(b"\r\n")
            if not raw.strip():
                continue
            line, hints = strip_hints(raw)
            hinted += hints is not None
            text = line.decode("utf-8", "replace")
            det = detect(snap, text)
            sg = signature.sign(snap, det, None)
            e = sigs.get(sg.signature)
            if e is None:
                e = sigs[sg.signature] = {"count": 0, "first": n, "bucket": det.bucket, "format": det.format,
                                          "template": sg.template[:300], "samples": [], "tokens": set()}
            e["count"] += 1
            if len(e["samples"]) < K:
                toks = set(text.split()[:200])
                if not e["samples"] or (toks - e["tokens"]):
                    e["samples"].append({"line": n, "text": text, "hints": hints})
                    e["tokens"] |= toks
            if len(randoms) < RANDOM_N:
                randoms.append({"line": n, "text": text, "hints": hints})
            else:
                j = rng.randint(0, n)
                if j < RANDOM_N:
                    randoms[j] = {"line": n, "text": text, "hints": hints}
            n += 1
            if n % CURVE_EVERY == 0:
                curve.append([n, len(sigs)])
    curve.append([n, len(sigs)])
    for e in sigs.values():
        del e["tokens"]
    res = {"file": name, "lines": n, "hinted": hinted, "signatures": len(sigs), "seconds": round(time.time() - t0, 1),
           "curve": curve, "patterns": sigs, "random": randoms}
    with open(os.path.join(out_dir, name + ".json"), "w") as fh:
        json.dump(res, fh)
    return {k: res[k] for k in ("file", "lines", "hinted", "signatures", "seconds")}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("src")
    ap.add_argument("out")
    ap.add_argument("--rules", action="append", required=True)
    ap.add_argument("--workers", type=int, default=max(1, (os.cpu_count() or 4) - 2))
    ap.add_argument("--only", nargs="*")
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    files = sorted(os.path.join(a.src, f) for f in os.listdir(a.src) if f.endswith(".log")
                   and (not a.only or os.path.splitext(f)[0] in a.only))
    files.sort(key=lambda p: -os.path.getsize(p))          # biggest first, so the pool stays busy
    t0 = time.time()
    rows = []
    with Pool(a.workers) as pool:
        for r in pool.imap_unordered(scan_file, [(f, a.rules, a.out) for f in files]):
            rows.append(r)
            print(f"{r['file']:28s} {r['lines']:>9,d} lines {r['signatures']:>6,d} patterns {r['seconds']:>7.1f}s", flush=True)
    summ = {"files": len(rows), "lines": sum(r["lines"] for r in rows),
            "patterns": sum(r["signatures"] for r in rows), "seconds": round(time.time() - t0, 1),
            "per_file": sorted(rows, key=lambda r: r["file"])}
    json.dump(summ, open(os.path.join(a.out, "summary.json"), "w"), indent=1)
    print(f"\n{summ['lines']:,d} lines, {summ['patterns']:,d} patterns, {summ['seconds']}s wall")


if __name__ == "__main__":
    main()
