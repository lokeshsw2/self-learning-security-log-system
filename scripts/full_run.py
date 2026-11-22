"""Run every line of the full log folder through the real pipeline, in parallel, read-only.

Each worker opens its own copy of a trained database and, per line: strips hint
annotations (kept as labels), detects, signs, finds the group, parses, maps and
validates against OCSF, and runs the meaning checks. Nothing is written back:
this measures exact full-volume outcomes and throughput without a database that
grows past the input.

  python scripts/full_run.py "/path/to/logs data" work/covC.db work/full --workers 8

Output: work/full/<file>.json and work/full/summary.json
"""
from __future__ import annotations

import argparse
import collections
import json
import os
import shutil
import sys
import time
from multiprocessing import Pool

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "scripts"))


def run_file(args):
    path, db_src, out_dir, tmp_dir = args
    from logparser import checks, ocsf
    from logparser.config import Settings
    from logparser.engine import Engine
    from logparser.reader import Record
    from logparser.store import SqliteStore
    from scan_patterns import strip_hints
    name = os.path.splitext(os.path.basename(path))[0]
    db = os.path.join(tmp_dir, name + ".db")
    shutil.copyfile(db_src, db)
    store = SqliteStore(db)
    saved = store.get_state("settings") or {}
    s = Settings()
    for k, v in saved.items():
        if hasattr(s, k):
            setattr(s, k, v)
    eng = Engine(store, s)
    c = collections.Counter()
    classes = collections.Counter()
    unknown = collections.Counter()
    hint_out = collections.Counter()
    t0 = time.time()
    with open(path, "rb") as fh:
        for raw in fh:
            raw = raw.rstrip(b"\r\n")
            if not raw.strip():
                continue
            line, hints = strip_hints(raw)
            rec = Record(name, 0, text=line.decode("utf-8", "replace"))
            c["lines"] += 1
            det, source, cols = eng.analyse(rec)
            sg = eng._sign(det, None, cols)
            if sg.error:
                c["undecodable"] += 1
                continue
            g = eng.canonical(sg.signature)
            if g is None:                       # a pattern no rule has seen: it would become a new group
                c["new_pattern"] += 1
                unknown[sg.template[:160]] += 1
                continue
            g = eng._subgroup(g, det)
            res = eng.parse_record(g, det, sg, rec)
            if res["status"] == "pending":
                c["no_parser"] += 1
                continue
            if res["status"] == "dlq":
                c["parse_failed"] += 1
                continue
            c["parsed"] += 1
            ev = res["event"]
            if not ev or res["mapping_rule"] == "mapping:default-base":
                c["no_mapping"] += 1
                continue
            c["mapped"] += 1
            classes[ev.get("class_uid")] += 1
            if res["valid"]:
                c["valid"] += 1
            if ev.get("class_uid") not in (0, None):
                c["specific_class"] += 1
            mean = checks.problems(det, res["fields"], ev, res["tags"],
                                   eng._mapping(g["mapping_rule"]) or {})
            for p in mean:
                c["check_" + p.split(":", 1)[0]] += 1
            if hints:
                key = ",".join(f"{k}={v}" for k, v in sorted(hints.items()) if k.endswith("Hint"))
                hint_out[(key, ev.get("class_uid"), ev.get("status_id"))] += 1
    store.close()
    os.remove(db)
    for ext in ("-wal", "-shm"):
        if os.path.exists(db + ext):
            os.remove(db + ext)
    res = {"file": name, "seconds": round(time.time() - t0, 1), **c,
           "classes": {str(k): v for k, v in classes.most_common()},
           "new_patterns": unknown.most_common(15),
           "hints": [[k[0], k[1], k[2], v] for k, v in hint_out.most_common(40)]}
    json.dump(res, open(os.path.join(out_dir, name + ".json"), "w"), indent=1)
    return res


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("src")
    ap.add_argument("db")
    ap.add_argument("out")
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--only", nargs="*")
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    tmp = os.path.join(a.out, "tmp")
    os.makedirs(tmp, exist_ok=True)
    files = sorted((os.path.join(a.src, f) for f in os.listdir(a.src)
                    if f.endswith(".log") and (not a.only or f[:-4] in a.only)), key=lambda p: -os.path.getsize(p))
    t0 = time.time()
    tot = collections.Counter()
    with Pool(a.workers) as pool:
        for r in pool.imap_unordered(run_file, [(f, a.db, a.out, tmp) for f in files]):
            for k, v in r.items():
                if isinstance(v, int):
                    tot[k] += v
            n = r.get("lines", 0) or 1
            print(f"{r['file']:28s} {r.get('lines', 0):>10,d} lines  parsed {r.get('parsed', 0) / n:6.1%}  "
                  f"mapped {r.get('mapped', 0) / n:6.1%}  new {r.get('new_pattern', 0):>6,d}  {r['seconds']:>6.0f}s", flush=True)
    wall = time.time() - t0
    summ = {"wall_seconds": round(wall, 1), "lines_per_second": round(tot["lines"] / wall), **tot}
    json.dump(summ, open(os.path.join(a.out, "summary.json"), "w"), indent=1)
    print(json.dumps(summ, indent=1))


if __name__ == "__main__":
    main()
