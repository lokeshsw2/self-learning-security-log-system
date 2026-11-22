"""Prove that the compiled Logstash pipelines give the engine's events, group by group.

  python scripts/ls_verify.py work/logstash/ls.db work/logstash/run1 [--mixed 3000] [--per-group 8]
                              [--deploy deploy/logstash/generated]

Loop: compile every group -> run ONE Logstash on the test lines -> compare, per line, the
`[ocsf]` Logstash produced with the event the engine's own parse_record/map_event gives for
the same line (in-process, same clock, same default time zone) -> exclude every group that
does not agree (disagrees, loses lines, or captures lines of another group) -> recompile with
the agreeing groups only -> run again, until nothing is excluded.  The last pass is the report.

Test set: stored samples of every group (up to --per-group each) plus --mixed lines of
data/owner_cover/mixed.log (hint annotations stripped, as scripts/full_run.py does).

Outputs in out_dir: generated/ (the verified production set: distributor.conf, src_*.conf,
sink.conf, pipelines.yml), pipeline.conf (verified filter section in one piece), report.json.
The database is never written: the script works on a copy (out_dir/engine.db).
"""
from __future__ import annotations

import argparse
import collections
import json
import os
import random
import shutil
import signal
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "scripts"))

NOW = 1795000000.0          # fixed clock for the engine and (LP_NOW) for Logstash


# ------------------------------------------------------------------ engine side
def open_engine(db: str):
    import argparse as ap
    from logparser.cli import open_engine as oe
    eng = oe(ap.Namespace(db=db, settings=None))
    eng.now = NOW
    return eng


def resolve_new(eng, det, sg):
    """Read-only copy of the two ways Engine._lookup attaches an unseen signature to an existing group:
    a merged wildcard template, a sibling template the group's parser already matches (unstructured), or
    key-set drift (json / kv / xml).  Returns the group or None (the engine would open a new group)."""
    if det.format == "unstructured":
        toks = sg.template.split()
        for mtoks, msig in eng.merged_index.get((det.bucket, len(toks)), ()):
            if all(a == "<*>" or a == b for a, b in zip(mtoks, toks)):
                return eng.groups[msig]
        return eng._sibling(det, sg)
    if sg.detail.get("sig_keys") and det.format in ("json", "kv", "xml"):
        keys = set(sg.detail["sig_keys"])
        disc = sg.detail.get("discriminators")
        best, best_j = None, 0.0
        for other in eng.by_bucket.get(det.bucket, ()):
            o = eng.groups[other]
            if o["format"] != det.format or o["detail"].get("discriminators") != disc \
                    or o["detail"].get("text", "") != sg.detail.get("text", ""):
                continue
            ok = set(o["detail"].get("sig_keys") or ())
            if not ok:
                continue
            j = len(keys & ok) / len(keys | ok)
            if j > best_j:
                best, best_j = o, j
        if best is not None and best_j >= eng.settings.drift_overlap:
            return best
    return None


def truth(eng, raw: str, base_events: bool = False) -> dict:
    """What the engine does with one line: its group and event, or why there is none. `base_events`: a
    Base Event from the default mapping counts as an event (the compiler's base_fallback deploys those)."""
    from logparser.reader import Record
    rec = Record("lsverify", 0, text=raw)
    try:
        det, _source, cols = eng.analyse(rec)
        sg = eng._sign(det, None, cols)
        if sg.error:
            return {"kind": "undecodable"}
        g = eng.canonical(sg.signature)
        via = None
        if g is None:
            g = resolve_new(eng, det, sg)          # what _lookup would do with a signature it has not seen
            via = "lookup"
            if g is None:
                return {"kind": "nogroup"}
        g = eng._subgroup(g, det)
        res = eng.parse_record(g, det, sg, rec)
    except Exception as exc:       # the engine itself fails on this line
        return {"kind": "engine_error", "error": repr(exc)[:200]}
    if res["status"] == "pending":
        return {"kind": "noparser", "gid": g["signature"]}
    if res["status"] == "dlq":
        return {"kind": "parse_fail", "gid": g["signature"]}
    if not res.get("event") or (res["mapping_rule"] == "mapping:default-base" and not base_events):
        return {"kind": "base", "gid": g["signature"]}
    return {"kind": "event", "gid": g["signature"], "event": res["event"], "source": g["source"], "via": via}


def norm(v):
    """Normalise for comparison: integral floats are ints, empty containers are kept."""
    if isinstance(v, dict):
        return {k: norm(x) for k, x in v.items()}
    if isinstance(v, list):
        return [norm(x) for x in v]
    if isinstance(v, float) and v == int(v) and abs(v) < 1e15:
        return int(v)
    return v


def diff(a, b, path="", out=None, limit=6):
    out = [] if out is None else out
    if len(out) >= limit:
        return out
    if isinstance(a, dict) and isinstance(b, dict):
        for k in sorted(set(a) | set(b)):
            if k not in a:
                out.append((f"{path}.{k}", "<missing>", b[k]))
            elif k not in b:
                out.append((f"{path}.{k}", a[k], "<missing>"))
            else:
                diff(a[k], b[k], f"{path}.{k}", out, limit)
    elif isinstance(a, list) and isinstance(b, list) and len(a) == len(b):
        for i, (x, y) in enumerate(zip(a, b)):
            diff(x, y, f"{path}[{i}]", out, limit)
    elif a != b or type(a) != type(b):
        out.append((path, a, b))
    return out


# ------------------------------------------------------------------ test set
def build_lines(eng, db: str, per_group: int, mixed: int, seed: int = 7, base_events: bool = False) -> list:
    import sqlite3
    con = sqlite3.connect(db)
    rnd = random.Random(seed)
    by_sig = collections.defaultdict(list)
    for sig, rid, raw, tag in con.execute("select signature, raw_id, raw, tag from samples order by signature, raw_id"):
        by_sig[sig].append((rid, raw, tag))
    con.close()
    lines, seen = [], set()
    for sig, rows in by_sig.items():
        rnd.shuffle(rows)
        # mixed tags: keep the value-tagged ones (they carry the discriminator variety) in the pick
        rows.sort(key=lambda r: (0 if r[2].startswith("value:") else 1 if r[2] == "diverse" else 2))
        for rid, raw, tag in rows[:per_group]:
            if raw in seen:
                continue
            seen.add(raw)
            lines.append({"id": len(lines), "raw": raw, "origin": "sample"})
    if mixed:
        from scan_patterns import strip_hints
        path = os.path.join(ROOT, "data", "owner_cover", "mixed.log")
        with open(path, "rb") as fh:
            allp = [ln.rstrip(b"\r\n") for ln in fh if ln.strip()]
        rnd.shuffle(allp)
        for b in allp[:mixed]:
            line, _h = strip_hints(b)
            raw = line.decode("utf-8", "replace")
            lines.append({"id": len(lines), "raw": raw, "origin": "mixed"})
    for ln in lines:
        ln["truth"] = truth(eng, ln["raw"], base_events)
    return lines


# ------------------------------------------------------------------ Logstash run
def run_logstash(gen, lines: list, work: str, root: str, timeout: float = 900.0) -> tuple[dict, dict]:
    """Write the test copy of the generated set, run ONE Logstash on it, return ({id: event}, timing)."""
    from logparser import logstash as L
    d = os.path.abspath(os.path.join(work, "testset"))
    shutil.rmtree(d, ignore_errors=True)
    os.makedirs(d)
    inp = os.path.join(d, "in.jsonl")
    outp = os.path.join(d, "out.jsonl")
    with open(inp, "w") as fh:
        for ln in lines:
            fh.write(json.dumps({"id": ln["id"], "message": ln["raw"]}) + "\n")
    L.write_set(gen, d, root=root, test={"input": inp, "output": outp})
    with open(os.path.join(d, "logstash.yml"), "w") as fh:
        fh.write(f'path.data: "{d}/data"\npath.logs: "{d}/logs"\nconfig.reload.automatic: false\napi.enabled: false\n')
    env = dict(os.environ, LP_NOW=str(NOW))
    log = open(os.path.join(d, "ls.log"), "w")
    t0 = time.time()
    proc = subprocess.Popen(["/opt/homebrew/bin/logstash", "--path.settings", d], stdout=log, stderr=subprocess.STDOUT,
                            env=env, start_new_session=True)
    n = len(lines)
    first = last = None
    count, stall_at, pos = 0, time.time(), 0
    try:
        while time.time() - t0 < timeout:
            time.sleep(0.5)
            if proc.poll() is not None:
                break
            c = count
            if os.path.exists(outp):
                with open(outp, "rb") as fh:
                    fh.seek(pos)
                    chunk = fh.read()
                cut = chunk.rfind(b"\n") + 1
                c = count + chunk[:cut].count(b"\n")
                pos += cut
            if c != count:
                count, stall_at = c, time.time()
                if first is None:
                    first = time.time()
                last = time.time()
            if count >= n:
                break
            if first is not None and time.time() - stall_at > 90:
                break
    finally:
        try:
            os.killpg(proc.pid, signal.SIGTERM)
            proc.wait(timeout=60)
        except Exception:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except Exception:
                pass
        log.close()
    events = {}
    if os.path.exists(outp):
        with open(outp) as fh:
            for ln in fh:
                try:
                    ev = json.loads(ln)
                except ValueError:
                    continue
                if "id" in ev:
                    events[ev["id"]] = ev
    timing = {"lines": n, "received": len(events), "startup_s": round((first or time.time()) - t0, 1),
              "run_s": round((last - first), 2) if first and last and last > first else None}
    if timing["run_s"]:
        timing["events_per_s"] = round(len(events) / timing["run_s"])
    return events, timing


# ------------------------------------------------------------------ comparison
def judge(lines: list, events: dict, included: set | None) -> list:
    """One verdict per line.  included=None means every compiled group may answer."""
    out = []
    for ln in lines:
        t = ln["truth"]
        ev = events.get(ln["id"])
        v = {"id": ln["id"], "origin": ln["origin"], "expect": t.get("gid"), "kind": t["kind"]}
        if ev is None:
            v["verdict"] = "lost"
            out.append(v)
            continue
        lp = ev.get("lp") or {}
        got = lp.get("group_id")
        unparsed = "lp_unparsed" in (ev.get("tags") or [])
        v["got"] = got
        v["reason"] = lp.get("reason")
        if t["kind"] == "event":
            expected_in = included is None or t["gid"] in included
            if unparsed or not got:
                v["verdict"] = ("ok_lookup" if t.get("via") else "unparsed") if expected_in else "ok_excluded"
            elif got != t["gid"]:
                v["verdict"] = "misrouted"
            else:
                d = diff(norm(t["event"]), norm(ev.get("ocsf") or {}))
                if d:
                    v["verdict"] = "disagree"
                    v["diff"] = [[p, str(a)[:80], str(b)[:80]] for p, a, b in d]
                else:
                    v["verdict"] = "agree"
        else:
            v["verdict"] = "ok_unparsed" if (unparsed or not got) else "overreach"
        out.append(v)
    return out


def exclusions(verdicts: list) -> dict:
    """Groups to drop, with the first cause seen for each."""
    bad: dict = {}
    for v in verdicts:
        if v["verdict"] in ("disagree", "unparsed", "misrouted", "lost") and v.get("expect"):
            if v["verdict"] == "disagree":
                cause = "disagree: " + "; ".join(f"{p} engine={a!r} logstash={b!r}" for p, a, b in v["diff"][:2])
            elif v["verdict"] == "unparsed":
                cause = f"lines lost in pipeline ({v.get('reason')})"
            elif v["verdict"] == "misrouted":
                cause = f"its lines landed in group {v.get('got')}"
            else:
                cause = "line lost"
            bad.setdefault(v["expect"], cause)
        if v["verdict"] in ("misrouted", "overreach") and v.get("got"):
            bad.setdefault(v["got"], "captured lines of another group" if v["verdict"] == "misrouted"
                           else "handles lines the engine has no group for")
    return bad


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("db")
    ap.add_argument("out")
    ap.add_argument("--mixed", type=int, default=3000)
    ap.add_argument("--per-group", type=int, default=8)
    ap.add_argument("--max-iter", type=int, default=5)
    ap.add_argument("--deploy", help="also write the verified production set here (deploy/logstash/generated)")
    ap.add_argument("--bench", type=int, default=0, help="after the last pass, time Logstash on this many lines")
    ap.add_argument("--keep-db", action="store_true", help="keep the engine.db copy in the output directory")
    ap.add_argument("--allow-overreach", action="store_true",
                    help="do not exclude groups that handle lines the engine has no group for")
    a = ap.parse_args()
    from logparser import logstash as L
    out = os.path.abspath(a.out)
    os.makedirs(out, exist_ok=True)
    dbcopy = os.path.join(out, "engine.db")
    if os.path.abspath(a.db) != dbcopy:
        shutil.copyfile(a.db, dbcopy)
    eng = open_engine(dbcopy)
    t0 = time.time()
    lines = build_lines(eng, dbcopy, a.per_group, a.mixed)
    print(f"test set: {len(lines)} lines ({sum(1 for x in lines if x['origin'] == 'sample')} samples, "
          f"{sum(1 for x in lines if x['origin'] == 'mixed')} mixed) in {time.time() - t0:.0f}s; engine event on "
          f"{sum(1 for x in lines if x['truth']['kind'] == 'event')}", flush=True)
    comp = L.Compiler(eng)
    include = None
    history = []
    causes: dict = {}
    for it in range(1, a.max_iter + 1):
        gen = comp.compile(include)
        used = {gid for gid, leaf in comp.leaves.items() if leaf.included}
        print(f"\n--- pass {it}: compiled {gen.stats['leaves']} groups in {gen.stats['sources']} source pipelines "
              f"(+distributor, sink)", flush=True)
        events, timing = run_logstash(gen, lines, out, ROOT)
        print("    logstash:", timing, flush=True)
        verdicts = judge(lines, events, used)
        counts = collections.Counter(v["verdict"] for v in verdicts)
        print("    verdicts:", dict(counts), flush=True)
        bad = exclusions([v for v in verdicts if not (a.allow_overreach and v["verdict"] == "overreach")])
        for gid, cause in bad.items():
            causes.setdefault(gid, cause)
        if it == 1:
            first_pass = collections.defaultdict(collections.Counter)
            for v in verdicts:
                if v.get("expect") and v["kind"] == "event":
                    first_pass[v["expect"]][v["verdict"]] += 1
            first_counts = {"verdicts": dict(counts), "by_group": first_pass,
                            "excluded": sorted(set(bad) & used)}
            first_reasons = collections.Counter()
            for v in verdicts:
                if v["verdict"] in ("disagree", "unparsed", "misrouted", "overreach", "lost"):
                    first_reasons[v["verdict"] + (":" + str(v.get("reason")) if v["verdict"] == "unparsed" else "")] += 1
            first_counts["reasons"] = dict(first_reasons)
        history.append({"pass": it, "groups": len(used), "timing": timing, "verdicts": dict(counts),
                        "excluded_now": len(set(bad) & used)})
        newly = set(bad) & used
        if not newly:
            break
        include = used - newly
        print(f"    excluding {len(newly)} groups; {len(include)} remain", flush=True)
        if it == a.max_iter:
            print("    NOT converged", flush=True)
    if a.bench:
        good = [ln for ln, v in zip(lines, verdicts) if v["verdict"] == "agree"]
        big = [{"id": i, "raw": good[i % len(good)]["raw"], "origin": "bench"} for i in range(a.bench)]
        print(f"\nthroughput run: {len(big)} lines through the verified set ...", flush=True)
        _ev, bt = run_logstash(gen, big, os.path.join(out, "bench"), ROOT, timeout=1800)
        print("    ", bt, flush=True)
        history.append({"bench": bt})
        shutil.rmtree(os.path.join(out, "bench"), ignore_errors=True)
    report(eng, comp, gen, lines, verdicts, used, history, out, a, first_counts, causes)
    if not a.keep_db:
        try:
            eng.store.close()
        except Exception:
            pass
        for ext in ("", "-wal", "-shm"):
            if os.path.exists(dbcopy + ext):
                os.remove(dbcopy + ext)


def report(eng, comp, gen, lines, verdicts, included, history, out, a, first, causes) -> None:
    from logparser import logstash as L
    vby_gid = collections.defaultdict(collections.Counter)      # expected gid -> verdict counts
    for v in verdicts:
        if v.get("expect") and v["kind"] == "event":
            vby_gid[v["expect"]][v["verdict"]] += 1
    captured = collections.Counter()
    for v in verdicts:
        if v["verdict"] in ("misrouted", "overreach") and v.get("got"):
            captured[v["got"]] += 1
    srcs = collections.defaultdict(lambda: {"groups": 0, "verified": 0, "excluded": 0, "unsupported": 0, "lines": 0,
                                            "agree": 0, "misrouted": 0, "p1_lines": 0, "p1_agree": 0,
                                            "reasons": collections.Counter()})
    groups = {}
    for gid, leaf in comp.leaves.items():
        s = srcs[leaf.slug]
        s["groups"] += 1
        c = vby_gid.get(gid, collections.Counter())
        n = sum(c.values())
        if leaf.status != "ok":
            s["unsupported"] += 1
            s["reasons"][leaf.reason[:60]] += 1
            status, why = "unsupported", leaf.reason
        elif gid in included:
            s["verified"] += 1
            status, why = "verified", ""
        else:
            s["excluded"] += 1
            status, why = "excluded", causes.get(gid, "verification")
        p1 = first["by_group"].get(gid, collections.Counter())
        s["p1_lines"] = s.get("p1_lines", 0) + sum(p1.values())
        s["p1_agree"] = s.get("p1_agree", 0) + p1.get("agree", 0)
        s["lines"] += n
        s["agree"] += c.get("agree", 0)
        s["misrouted"] += c.get("misrouted", 0) + captured.get(gid, 0)
        groups[gid] = {"source": leaf.slug, "bucket": leaf.bucket, "status": status, "reason": why,
                       "native_entries": leaf.native, "ruby_entries": leaf.ruby, "samples": dict(c),
                       "captured_foreign_lines": captured.get(gid, 0)}
    # first-pass reasons (why groups were dropped) from history are in the console; keep the last diffs
    diffs = collections.defaultdict(list)
    for v in verdicts:
        if v["verdict"] == "disagree" and len(diffs[v["expect"]]) < 2:
            diffs[v["expect"]].append({"id": v["id"], "diff": v["diff"]})
    mixed = [v for v in verdicts if v["origin"] == "mixed"]
    mc = collections.Counter(v["verdict"] for v in mixed)
    eng_event = sum(1 for v in mixed if v["kind"] == "event")
    n_mixed = len(mixed)
    ident = mc.get("agree", 0)
    weighted = {"mixed_lines": n_mixed, "engine_event_lines": eng_event,
                "logstash_identical": ident, "logstash_identical_share": round(ident / n_mixed, 4) if n_mixed else None,
                "engine_event_share": round(eng_event / n_mixed, 4) if n_mixed else None,
                "engine_event_lines_logstash_unparsed": mc.get("unparsed", 0) + mc.get("ok_excluded", 0) + mc.get("ok_lookup", 0),
                "of_which_engine_needed_lookup_or_drift": mc.get("ok_lookup", 0),
                "overreach": mc.get("overreach", 0), "misrouted": mc.get("misrouted", 0), "disagree": mc.get("disagree", 0)}
    rep = {"first_pass": {"verdicts": first["verdicts"], "reasons": first["reasons"],
                          "groups_excluded": len(first["excluded"])}, "passes": history, "weighted_mixed": weighted, "sources": {
        k: {**{kk: vv for kk, vv in v.items() if kk != "reasons"}, "unsupported_reasons": dict(v["reasons"])}
        for k, v in sorted(srcs.items())}, "groups": groups, "diffs": diffs,
        "sample_verdicts": dict(collections.Counter(v["verdict"] for v in verdicts if v["origin"] == "sample"))}
    json.dump(rep, open(os.path.join(out, "report.json"), "w"), indent=1, default=str)
    gdir = os.path.join(out, "generated")
    L.write_set(gen, gdir, root=ROOT)
    open(os.path.join(out, "pipeline.conf"), "w").write(L.compile_pipeline(eng, included) if False else
                                                        "\n".join(gen.files.values()))
    if a.deploy:
        L.write_set(gen, os.path.abspath(a.deploy), root=ROOT)
    print("\nsource                                   groups verified excluded unsupp  pass-1 agree      final agree     misrouted")
    tot = collections.Counter()
    for k, v in sorted(srcs.items(), key=lambda kv: -kv[1]["groups"]):
        pct = f"{100.0 * v['agree'] / v['lines']:5.1f}%" if v["lines"] else "   -  "
        p1 = f"{100.0 * v['p1_agree'] / v['p1_lines']:5.1f}%" if v["p1_lines"] else "   -  "
        print(f"{k[:40]:40s} {v['groups']:6d} {v['verified']:8d} {v['excluded']:8d} {v['unsupported']:6d}  "
              f"{p1:>7s} ({v['p1_agree']}/{v['p1_lines']})  {pct:>7s} ({v['agree']}/{v['lines']})  {v['misrouted']:5d}")
        for kk in ("groups", "verified", "excluded", "unsupported", "lines", "agree", "misrouted", "p1_lines", "p1_agree"):
            tot[kk] += v[kk]
    print(f"{'TOTAL':40s} {tot['groups']:6d} {tot['verified']:8d} {tot['excluded']:8d} {tot['unsupported']:6d}  "
          f"{100.0 * tot['p1_agree'] / max(1, tot['p1_lines']):5.1f}% ({tot['p1_agree']}/{tot['p1_lines']})  "
          f"{100.0 * tot['agree'] / max(1, tot['lines']):5.1f}% ({tot['agree']}/{tot['lines']})  {tot['misrouted']:5d}")
    print("\nexcluded / unsupported groups:")
    for gid, gi in groups.items():
        if gi["status"] != "verified":
            print(f"  {gi['source'][:28]:28s} {gid} {gi['status']}: {gi['reason'][:150]}")
    print("\nmixed sample:", json.dumps(weighted))


if __name__ == "__main__":
    main()
