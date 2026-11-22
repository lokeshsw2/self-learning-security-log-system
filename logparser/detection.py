"""Detection repair: the agents may add detection rules for lines that no rule can read.

Detection runs first for every line, so a detection rule is checked harder than any other:

  - it is new (`detect:ai_<name>`): agents never edit or replace a built-in or earlier rule
  - it is an anchored regex with a named `payload` and at least one of timestamp, host or app
  - it reads every sample line of the item it was written for
  - no regression: every stored line that some rule reads today is read exactly as before
    (same chain, format, header, app and payload). Only lines that fell through to plain
    `unstructured` may change.

After a rule is saved, the stored lines it now reads are processed again: they move to their
new source and groups, the groups they leave point to the groups that took them, and the
leftover queue items of those groups are closed so nobody pays for them twice. From there the
normal agents (naming, parsers, mappings, long tail) and the self-audit take over.

The trigger is code: `scan` looks at lines that fell through detection in sources with no
envelope at all, by the shape of their first token, and queues a shape only when at least
`min_lines` of its lines are still not handled well: waiting for a rule, or parsed with the
ingest time because no rule found the line's own time. Lines that later rules already handle
(a parser or long-tail rule for a format with no header at all, such as AWS VPC flow records)
are left alone: a new header rule would move them to new groups and their working rules would
have to be learned again.
"""
from __future__ import annotations

import copy
import re
from collections import Counter

from . import registry, rx
from .detect import detect
from .reader import Record

QUEUE = "needs-detection"
HEADED = re.compile(r"^(?:\d|<\d|\[|(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\b)")
NEED_ONE_OF = {"timestamp", "host", "app"}
MAX_SAMPLES = 30


class DetectRefused(Exception):
    pass


def weak(det) -> bool:
    """No rule read this line: it fell through to plain unstructured text."""
    return det.chain == ["unstructured"]


def shape(line: str) -> str:
    tok = line.lstrip().split(" ", 1)[0][:48]
    return re.sub(r"[A-Za-z]+", "a", re.sub(r"\d+", "0", tok))


def _weak_sources(e) -> list:
    return [s["source"] for s in e.store.sources()
            if s["source"].split("|", 1)[-1].split("#")[0] == "unstructured|-" and s["lines"]]


def scan(e, min_lines: int = 20, enqueue: bool = True) -> dict:
    """Queue detection work for lines no rule reads. Code only."""
    out = {"sources": 0, "shapes": 0, "queued": 0}
    for src in _weak_sources(e):
        out["sources"] += 1
        by: dict = {}
        for r in e.store.q("SELECT r.raw, r.status, e.tags FROM raw r LEFT JOIN events e ON e.raw_id = r.id "
                           "WHERE r.source = ? AND r.blob IS NULL", (src,)):
            if not r["raw"] or not HEADED.match(r["raw"].lstrip()):
                continue
            unwell = r["status"] != "parsed" or "time_from_ingest" in (r["tags"] or "")
            b = by.setdefault(shape(r["raw"]), {"all": 0, "unwell": []})
            b["all"] += 1
            if unwell:
                b["unwell"].append(r["raw"])
        for sh, b in by.items():
            lines = b["unwell"]
            if len(lines) < min_lines:
                continue                      # handled well already: leave the working rules alone
            out["shapes"] += 1
            step = max(1, len(lines) // MAX_SAMPLES)
            payload = {"source": src, "shape": sh, "count": b["all"], "not_handled": len(lines),
                       "why": "waiting for a rule, or parsed with the ingest time: no rule reads their header",
                       "samples": lines[::step][:MAX_SAMPLES]}
            if enqueue and e.store.enqueue(QUEUE, f"{src}#{sh}", payload):
                out["queued"] += 1
    return out


def stored_lines(e, limit: int = 40000) -> list:
    """Lines the regression check replays: every group's samples, then kept raw lines."""
    seen, out = set(), []
    for r in e.store.q("SELECT raw FROM samples"):
        if r["raw"] and r["raw"] not in seen:
            seen.add(r["raw"])
            out.append(r["raw"])
    for r in e.store.q("SELECT raw FROM raw WHERE raw IS NOT NULL AND blob IS NULL ORDER BY id DESC LIMIT ?", (limit,)):
        if r["raw"] not in seen:
            seen.add(r["raw"])
            out.append(r["raw"])
    return out


def _snap_with(snap, body: dict):
    s = copy.copy(snap)
    s.detect = sorted([b for b in snap.detect if b["name"] != body["name"]] + [body],
                      key=lambda b: (b["order"], b["name"]))
    return s


def _view(det) -> tuple:
    return (tuple(det.chain), det.format, tuple(sorted(det.header.items())), det.app, det.payload,
            det.dialect, det.delimiter)


def check_rule(e, body: dict) -> None:
    """Static checks; raises DetectRefused."""
    try:
        registry.validate_rule("detect", body)
    except registry.RuleError as exc:
        raise DetectRefused(f"rule is not valid: {exc}") from None
    name = body["name"]
    if not name.startswith("ai_"):
        raise DetectRefused("the rule name must start with `ai_`: agents add rules, they never replace one")
    if e.store.active_rule("detect:" + name) and not (e.store.active_rule("detect:" + name)["meta"] or {}).get(
            "created_by", "").startswith("harness:detection"):
        raise DetectRefused(f"detect:{name} exists and was not written by the detection agent; pick another name")
    t = body["test"]
    if t["kind"] != "regex":
        raise DetectRefused("only regex detection rules can be added")
    if not t["pattern"].startswith("^"):
        raise DetectRefused("the pattern must be anchored with ^ at the start of the line")
    groups = set(rx.compile(t["pattern"]).groupindex)
    if "payload" not in groups:
        raise DetectRefused("the pattern needs a named group `payload` for the message after the header")
    if not groups & NEED_ONE_OF:
        raise DetectRefused("the pattern must capture at least one of `timestamp`, `host` or `app`")
    if body["type"] != "envelope":
        raise DetectRefused("an added rule reads a header (type `envelope`); formats are detected after it")


def evaluate(e, samples: list, body: dict, lines: list | None = None) -> dict:
    """Test a candidate rule: does it read the item's samples, and does it change anything that is
    read today? Changes nothing."""
    check_rule(e, body)
    cand = _snap_with(e.snap, body)
    name = body["name"]
    target = {"lines": len(samples), "read": 0, "not_read": [], "first": None}
    for s in samples:
        d = detect(cand, s)
        if name in d.chain and not weak(d) and d.payload is not None:
            target["read"] += 1
            if target["first"] is None:
                target["first"] = {"line": s[:300], "chain": d.chain, "header": d.header, "app": d.app,
                                   "payload": d.payload[:200]}
        elif len(target["not_read"]) < 3:
            target["not_read"].append(s[:300])
    lines = stored_lines(e) if lines is None else lines
    regress, improved, examples = 0, Counter(), []
    for s in lines:
        old = detect(e.snap, s)
        new = detect(cand, s)
        if _view(old) == _view(new):
            continue
        if weak(old):
            improved[new.bucket] += 1
            continue
        regress += 1
        if len(examples) < 4:
            examples.append({"line": s[:240], "before": old.bucket, "after": new.bucket})
    ok = target["read"] == target["lines"] and target["lines"] > 0 and regress == 0
    return {"ok": ok, "target": target, "checked_lines": len(lines), "regressions": regress,
            "regression_examples": examples, "newly_read": dict(improved.most_common(10))}


def apply(e, key: str, samples: list, body: dict, agent: str, note: str = "") -> dict:
    """Save a rule that passed `evaluate` and process the lines it now reads again."""
    res = evaluate(e, samples, body)
    if not res["ok"]:
        why = []
        if res["target"]["read"] < res["target"]["lines"]:
            why.append(f"it reads {res['target']['read']} of {res['target']['lines']} sample lines; not read: "
                       f"{res['target']['not_read'][:2]}")
        if res["regressions"]:
            why.append(f"it changes how {res['regressions']} lines that other rules read today are read, e.g. "
                       f"{res['regression_examples'][:2]}")
        raise DetectRefused("; ".join(why) or "the check failed")
    rule_id = "detect:" + body["name"]
    v = registry.save_rule(e.store, rule_id, body, {
        "created_by": agent, "note": note,
        "check": f"reads {res['target']['read']}/{res['target']['lines']} samples; 0 of {res['checked_lines']} "
                 f"stored lines read differently; newly read: {res['newly_read']}"})
    e.reload()
    moved = reprocess(e)
    e.store.queue_done(QUEUE, key)
    return {"saved": rule_id, "version": v, "newly_read": res["newly_read"], "reprocessed": moved}


def reprocess(e) -> dict:
    """Process again the stored lines of sources no rule could read; lines the new rules read move
    to their new source and groups. Groups left without lines point to the group that took the
    most of them, and their open queue items are closed."""
    out = {"lines": 0, "moved": 0, "groups_superseded": 0}
    for src in _weak_sources(e):
        rows = e.store.raw_by_source(src)
        if not rows:
            continue
        label = src.split("|", 1)[0]
        old_sig = {r["id"]: r["signature"] for r in rows}
        recs = [Record(r["stream"], r["offset"], text=r["raw"], label=None if label == "-" else label) for r in rows]
        e.process(recs, raw_ids=[r["id"] for r in rows])
        out["lines"] += len(rows)
        now = {r["id"]: r for r in e.store.q(
            f"SELECT id, source, signature FROM raw WHERE id IN ({','.join('?' * len(rows))})", [r["id"] for r in rows])}
        took: dict = {}
        for rid, sig in old_sig.items():
            n = now.get(rid)
            if n is None or n["source"] == src:
                continue
            out["moved"] += 1
            took.setdefault(sig, Counter())[n["signature"]] += 1
        for sig, ctr in took.items():
            g = e.groups.get(sig)
            if g is None or g["merged_into"]:
                continue
            if e.store.q("SELECT 1 FROM raw WHERE signature=? AND source=? LIMIT 1", (sig, src)):
                continue                         # some of its lines are still unread: keep it
            to = ctr.most_common(1)[0][0]
            if to == sig or to not in e.groups:
                continue
            g["merged_into"] = to
            e.alias[sig] = to
            e.store.upsert_group(g)
            for q in ("needs-parser", "needs-mapping", "longtail", "grouping-repair"):
                e.store.queue_done(q, sig, "superseded")
            out["groups_superseded"] += 1
    if out["moved"]:
        e.finalize()          # the new groups enter the normal queues (parsers, mappings, long tail) now
    return out
