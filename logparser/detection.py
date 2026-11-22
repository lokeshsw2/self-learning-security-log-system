"""Detection repair: the agents may add detection rules for lines that no rule can read.

Detection runs first for every line, so an added rule is boxed in by construction, not only by
a test on stored lines:

  - it is new (`detect:ai_<name>`): agents never edit or replace a built-in or earlier rule
  - the hot path tries it only on a line that no other rule reads (detect.py), and only when the
    line's first token has the shape the rule was written for (`when_shape`, set by code). So it
    cannot change how any line that is read today is read, stored or not, and it cannot take
    lines of another unread format.
  - it is an anchored regex envelope with a named `payload` and at least one of timestamp, host
    or app; a captured timestamp must parse as a time on every sample
  - it reads every sample line of its item (samples are drawn from all unread lines of the shape)
  - as a second line of defence, every stored line is replayed: anything read today must come
    out identical

After a rule is saved, only the stored lines it now reads are processed again. They move to
their new source and groups; line counts move with them. What the agents had already learned for
the groups these lines leave is carried over by code and re-checked by the same gates: a
long-tail rule is rebuilt for the new group from the values it extracted (not their positions),
a parser and its mapping are tried on the new group. What does not carry over is learned again
by the normal agents; the result says how much. Groups left behind point to the group that took
most of their lines, and their open queue items are closed.

The trigger is code: `scan` looks at lines that fell through detection in sources with no
envelope at all, by the shape of their first token, and queues a shape only when its lines start
with something that looks like a time or a syslog priority, and at least `min_lines` of them are
not handled well: waiting for a rule, or parsed with the ingest time because no rule found the
line's own time. Lines that later rules already handle are left alone. A shape is queued again
after a rule was saved only if lines of it are still unread and handled badly; never after a
human flag.
"""
from __future__ import annotations

import copy
import json
import re
from collections import Counter

from . import registry, rx, transforms
from .detect import AI_PREFIX, detect, shape
from .reader import Record

QUEUE = "needs-detection"
# a header worth reading starts with a time or a syslog priority: an ISO or slashed date, a
# syslog month and day, an epoch of ten or more digits, <pri>, or a bracketed date
HEADED = re.compile(r"^(?:<\d{1,3}>|\d{4}[-/]\d\d[-/]\d\d|\d\d/[A-Za-z]{3}/\d{4}|\d{10,13}(?:\.\d+)?\s|"
                    r"\[\d{1,4}[-/:.]|(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s)")
NEED_ONE_OF = {"timestamp", "host", "app"}
MAX_SAMPLES = 30


class DetectRefused(Exception):
    pass


def weak(det) -> bool:
    """No rule read this line: it fell through to plain unstructured text."""
    return det.chain == ["unstructured"]


def _weak_sources(e) -> list:
    return [s["source"] for s in e.store.sources()
            if s["source"].split("|", 1)[-1].split("#")[0] == "unstructured|-" and s["lines"]]


def scan(e, min_lines: int = 20, enqueue: bool = True) -> dict:
    """Queue detection work for lines no rule reads and that are handled badly. Code only."""
    out = {"sources": 0, "shapes": 0, "queued": 0}
    for src in _weak_sources(e):
        out["sources"] += 1
        by: dict = {}
        for r in e.store.q("SELECT r.raw, r.status, e.tags FROM raw r LEFT JOIN events e ON e.raw_id = r.id "
                           "WHERE r.source = ? AND r.blob IS NULL", (src,)):
            if not r["raw"] or not HEADED.match(r["raw"].lstrip()):
                continue
            b = by.setdefault(shape(r["raw"]), {"lines": [], "unwell": 0})
            b["lines"].append(r["raw"])
            if r["status"] != "parsed" or "time_from_ingest" in (r["tags"] or ""):
                b["unwell"] += 1
        for sh, b in by.items():
            if b["unwell"] < min_lines:
                continue                      # handled well already: leave the working rules alone
            out["shapes"] += 1
            lines = b["lines"]
            step = max(1, len(lines) // MAX_SAMPLES)
            payload = {"source": src, "shape": sh, "count": len(lines), "not_handled": b["unwell"],
                       "why": "no rule reads their header: they wait for a rule or carry the ingest time",
                       "samples": lines[::step][:MAX_SAMPLES]}
            key = f"{src}#{sh}"
            if not enqueue:
                continue
            prev = e.store.q("SELECT status FROM queue WHERE name=? AND key=?", (QUEUE, key))
            if not prev:
                e.store.enqueue(QUEUE, key, payload)
                out["queued"] += 1
            elif prev[0]["status"] == "done":  # a rule was saved, yet lines of this shape are still unread
                e.store.reopen(QUEUE, key, {**payload, "again": "a saved rule did not read these lines"})
                out["queued"] += 1
    return out


def stored_lines(e, limit: int = 40000) -> list:
    """Lines the second-line regression check replays: every group's samples, then kept raw lines."""
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


def scoped(body: dict, item: dict) -> dict:
    """The rule as it is saved: code pins it to the shape of the lines it was written for."""
    return {**body, "when_shape": [item["shape"]]}


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
    if not name.startswith(AI_PREFIX):
        raise DetectRefused("the rule name must start with `ai_`: agents add rules, they never replace one")
    cur = e.store.active_rule("detect:" + name)
    if cur and not (cur["meta"] or {}).get("created_by", "").startswith("harness:detection"):
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


def evaluate(e, item: dict, body: dict, lines: list | None = None) -> dict:
    """Test a candidate rule on an item: does it read every sample, does a captured time parse,
    and (second line of defence) is every stored line that is read today read as before?"""
    check_rule(e, body)
    body = scoped(body, item)
    cand = _snap_with(e.snap, body)
    name = body["name"]
    ctx = {"default_tz": e.deployment_tz(), "now": e._clock()}
    samples = item["samples"]
    target = {"lines": len(samples), "read": 0, "not_read": [], "bad_time": [], "first": None}
    for s in samples:
        d = detect(cand, s)
        if name in d.chain and not weak(d) and d.payload is not None:
            ts = d.header.get("@timestamp")
            if ts is not None:
                try:
                    transforms.parse_timestamp(ts, {}, ctx)
                except transforms.TransformError:
                    if len(target["bad_time"]) < 3:
                        target["bad_time"].append(ts)
                    continue
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
    # what saving would cost: groups of this source whose learned parser will not fit once the
    # header is read (a parser was written for the whole line); long-tail rules are carried over
    relearn = {"parser_groups": 0, "lines": 0}
    for r in e.store.q("SELECT signature, count, parser_rule FROM groups WHERE source=? AND merged_into IS NULL "
                       "AND parser_rule IS NOT NULL", (item["source"],)):
        relearn["parser_groups"] += 1
        relearn["lines"] += r["count"]
    return {"ok": ok, "target": target, "checked_lines": len(lines), "regressions": regress,
            "regression_examples": examples, "newly_read": dict(improved.most_common(10)),
            "relearn_estimate": {**relearn, "note": "parsers written for the whole line usually have to be learned "
                                 "again after the header is read; long-tail rules are carried over by code"},
            "scope": f"only lines no other rule reads, whose first token has the shape {item['shape']!r}"}


def apply(e, key: str, item: dict, body: dict, agent: str, note: str = "") -> dict:
    """Save a rule that passed `evaluate`, process the lines it now reads again, and carry the
    rules learned for the groups they leave over to their new groups."""
    res = evaluate(e, item, body)
    if not res["ok"]:
        why = []
        t = res["target"]
        if t["read"] < t["lines"]:
            why.append(f"it reads {t['read']} of {t['lines']} sample lines; not read: {t['not_read'][:2]}"
                       + (f"; timestamps that do not parse: {t['bad_time']}" if t["bad_time"] else ""))
        if res["regressions"]:
            why.append(f"it changes how {res['regressions']} lines that other rules read today are read, e.g. "
                       f"{res['regression_examples'][:2]}")
        raise DetectRefused("; ".join(why) or "the check failed")
    body = scoped(body, item)
    learned = _learned_before(e, item["source"])
    rule_id = "detect:" + body["name"]
    v = registry.save_rule(e.store, rule_id, body, {
        "created_by": agent, "note": note,
        "check": f"reads {res['target']['read']}/{res['target']['lines']} samples; 0 of {res['checked_lines']} "
                 f"stored lines read differently; newly read: {res['newly_read']}"})
    e.reload()
    moved = reprocess(e, item["source"])
    carried = carry_over(e, learned, agent)
    e.store.queue_done(QUEUE, key)
    return {"saved": rule_id, "version": v, "scope": res["scope"], "newly_read": res["newly_read"],
            "reprocessed": moved, "carried_over": carried}


def _learned_before(e, src: str) -> list:
    """What the agents learned for the groups of a weak source, captured before its lines move:
    for each group with a rule, a sample line and what the rules made of it."""
    out = []
    for sig in [r["signature"] for r in e.store.q(
            "SELECT signature FROM groups WHERE source=? AND merged_into IS NULL", (src,))]:
        g = e.groups.get(sig)
        if g is None:
            continue
        lt = e.snap.rule("longtail:" + sig)
        if not (g["parser_rule"] or lt):
            continue
        samples = e.store.samples(sig)
        if not samples:
            continue
        raw = samples[0]["raw"]
        rec = Record("carry", 0, text=raw)
        det, _, cols = e.analyse(rec)
        sg = e._sign(det, None, cols)
        res = e.parse_record(e.groups[sig], det, sg, rec)
        fields = {k: v for k, v in (res.get("fields") or {}).items()
                  if not k.startswith("@") and k != "summary" and isinstance(v, str)}
        out.append({"from": sig, "raw": raw, "longtail": lt["body"] if lt else None, "fields": fields,
                    "parser": e.snap.rule(g["parser_rule"])["body"] if g["parser_rule"] else None,
                    "mapping": e.snap.rule(g["mapping_rule"])["body"] if g["mapping_rule"] else None,
                    "labels": g.get("labels") or {}})
    return out


def carry_over(e, learned: list, agent: str) -> dict:
    """Re-attach what was learned to the groups the lines moved to, through the normal gates."""
    from .tools import Refused, Tools
    t = Tools(e, agent)
    out = {"longtail": 0, "parser": 0, "mapping": 0, "to_learn_again": 0}
    for item in learned:
        rec = Record("carry", 0, text=item["raw"])
        det, _, cols = e.analyse(rec)
        g = e.canonical(e._sign(det, None, cols).signature)
        if g is None or g["signature"] == item["from"]:
            continue
        sig = g["signature"]
        try:
            if item["parser"] is not None:
                t.save_parser(sig, item["parser"], item["labels"], "carried over after a new detection rule")
                out["parser"] += 1
                if item["mapping"] is not None:
                    t.save_mapping(sig, item["mapping"], item["labels"], "carried over after a new detection rule")
                    out["mapping"] += 1
            elif item["longtail"] is not None and not e.snap.rule("longtail:" + sig):
                t.save_longtail(sig, item["fields"], item["longtail"].get("summary", ""))
                out["longtail"] += 1
        except Refused:
            out["to_learn_again"] += 1        # the gate says it no longer fits: the agents learn it again
    return out


def reprocess(e, src: str) -> dict:
    """Process again the stored lines of a weak source that a rule now reads. They move to their new
    source and groups, and their counts move with them. Groups left without lines point to the group
    that took most of them, and their open queue items are closed."""
    out = {"lines": 0, "moved": 0, "groups_superseded": 0}
    rows = [r for r in e.store.raw_by_source(src) if r["raw"] and not weak(detect(e.snap, r["raw"]))]
    if not rows:
        return out
    label = src.split("|", 1)[0]
    old_sig = {r["id"]: r["signature"] for r in rows}
    recs = [Record(r["stream"], r["offset"], text=r["raw"], label=None if label == "-" else label) for r in rows]
    e.process(recs, raw_ids=[r["id"] for r in rows])
    out["lines"] = out["moved"] = len(rows)
    # process() counted these lines in their new groups and source; take them off the old ones
    left = Counter(old_sig.values())
    for sig, n in left.items():
        g = e.groups.get(sig)
        if g is not None:
            g["count"] = max(0, g["count"] - n)
            e.store.upsert_group(g)
    s = e._source(src)
    s["lines"] = max(0, s["lines"] - len(rows))
    e.store.put_source(s)
    now = {r["id"]: r["signature"] for r in e.store.q(
        f"SELECT id, signature FROM raw WHERE id IN ({','.join('?' * len(rows))})", [r["id"] for r in rows])}
    took: dict = {}
    for rid, sig in old_sig.items():
        if now.get(rid):
            took.setdefault(sig, Counter())[now[rid]] += 1
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
    e.finalize()          # the new groups enter the normal queues (parsers, mappings, long tail) now
    return out
