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
# a header worth reading starts with a time or a syslog priority: a year-first or day-first date
# (any of - / . as separator), a syslog month and day, an epoch of ten to thirteen digits followed
# by a separator, a time of day, <pri>, or a bracketed date
HEADED = re.compile(r"^(?:<\d{1,3}>|\d{4}[-/.]\d\d[-/.]\d\d|\d{1,2}[-/.]\d{1,2}[-/.]\d{2,4}[\sT,]\d{1,2}:\d\d|"
                    r"\d\d/[A-Za-z]{3}/\d{4}|\d{10,13}(?:\.\d+)?(?:[\s|,;]|$)|\d{1,2}:\d\d:\d\d|"
                    r"\[\d{1,4}[-/:.]|(?:(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun),?\s+)?(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s)")
NEED_ONE_OF = {"timestamp", "host", "app"}
MIN_SUBSET = 5            # one item may hold several header formats: a rule reads at least this many samples
TIME_CODES = set("YmdbBjaAHIpMSfz%")            # strptime codes a time_format may use (no %y: century guessing)
ZONE_NAMES = ("UTC GMT UT Z IST CET CEST EET EEST WET WEST BST MSK EST EDT CST CDT MST MDT PST PDT AKST AKDT HST "
              "AST ADT NST NDT AEST AEDT ACST ACDT AWST NZST NZDT JST KST SGT HKT WIB WITA WIT PHT ICT SAST BRT "
              "ART CLT COT PET UYT").split()
# a zone written right after the time: an offset or Z (attached or not), or a real zone abbreviation
ZONE_AFTER = re.compile(r"^(?:\s*(?:[+-]\d\d:?\d\d\b|Z\b)|\s+(?:" + "|".join(ZONE_NAMES) + r")\b)")
PRI = re.compile(r"^<\d{1,3}>")
YEAR_MS = 365 * 86400 * 1000


def leads_with_time(line: str, ctx: dict) -> bool:
    """Does the line start (after a syslog <pri>) with a time? An epoch counts only if it is a plausible
    time near now, so "1234567890 order" does not."""
    s = PRI.sub("", line.lstrip(), count=1)
    if not HEADED.match(s) or s.startswith("<"):
        return False
    tok = re.split(r"[\s|,;]", s, maxsplit=1)[0]
    if tok.isdigit():
        try:
            t = transforms.parse_timestamp(tok, {}, ctx)
        except transforms.TransformError:
            return False
        return abs(t - ctx["now"] * 1000) < 10 * YEAR_MS
    return True
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
    fmt = body.get("time_format")
    if fmt is not None:
        if "timestamp" not in groups:
            raise DetectRefused("`time_format` describes the `timestamp` group, which the pattern does not have")
        codes = set(re.findall(r"%(.)", fmt))
        if not codes <= TIME_CODES or "H" not in codes and "I" not in codes or "M" not in codes:
            raise DetectRefused("`time_format` is a strptime format using only %Y %m %d %b %B %j %a %A %H %I %p %M "
                                "%S %f %z, with at least the hour and minute (a two-digit year %y is not accepted)")
        if "I" in codes and "p" not in codes:
            raise DetectRefused("a 12-hour clock (%I) needs AM/PM (%p)")
        if codes & set("mbB") and "d" not in codes:
            raise DetectRefused("a month (%m %b %B) needs the day (%d)")
        if "d" in codes and not codes & set("mbB"):
            raise DetectRefused("a day (%d) needs the month (%m %b %B)")
        if codes & set("mdbBj") and "Y" not in codes:
            raise DetectRefused("a `time_format` with a date needs the four-digit year (%Y); for a date with no "
                                "year, leave `time_format` out")
        if "Y" in codes and not codes & set("mdbBj"):
            raise DetectRefused("a year (%Y) needs the month and day (or %j)")


def evaluate(e, item: dict, body: dict, lines: list | None = None) -> dict:
    """Test a candidate rule on an item. One item may hold several header formats with the same first
    token shape, so a rule may read a subset of the samples (at least MIN_SUBSET); every sample it
    matches must come out right (time parses, is plausible, zone captured), and (second line of
    defence) every stored line that is read today must be read as before. Samples it does not match
    are `remaining`: the next rule's work, or a human's."""
    check_rule(e, body)
    body = scoped(body, item)
    cand = _snap_with(e.snap, body)
    name = body["name"]
    ctx = {"default_tz": e.deployment_tz(), "now": e._clock(), "tz_names": e.settings.tz_names}
    samples = item["samples"]
    groups = set(rx.compile(body["test"]["pattern"]).groupindex)
    matched = [s for s in samples if name in detect(cand, s).chain]
    timed = [s for s in matched if leads_with_time(s, ctx)]
    if timed and "timestamp" not in groups:
        raise DetectRefused(f"{len(timed)} of the {len(matched)} sample lines it matches start with a time, e.g. "
                            f"{timed[0][:60]!r}: capture it as `timestamp`, and add `time_format` if the engine "
                            "cannot read it as it is; if it cannot be described, flag the item for a human")
    target = {"lines": len(samples), "matched": len(matched), "read": 0, "bad": 0, "not_read": [], "bad_time": [],
              "first": None}
    for s in samples:
        d = detect(cand, s)
        if name in d.chain and not weak(d) and d.payload is not None:
            target["bad"] += 1            # undone below once the line comes out right
            ts = d.header.get("@timestamp")
            raw_ts = d.header.get("@timestamp_raw", ts)
            if raw_ts and "tz" not in groups and "%z" not in (body.get("time_format") or ""):
                after = s[s.find(raw_ts) + len(raw_ts):] if raw_ts in s else ""
                if ZONE_AFTER.match(after):
                    if len(target["bad_time"]) < 3:
                        target["bad_time"].append(f"{raw_ts} (a zone follows the time in the line: capture it as `tz`)")
                    continue
            if ts is not None:
                try:
                    t_ms = transforms.parse_timestamp(ts, {}, dict(ctx))
                except (transforms.TransformError, ValueError) as exc:
                    if len(target["bad_time"]) < 3:
                        target["bad_time"].append(f"{ts} ({str(exc)[:140]})")     # the reason tells the agent what to do
                    continue
                if t_ms > ctx["now"] * 1000 + 86400 * 1000 or t_ms < ctx["now"] * 1000 - 20 * YEAR_MS:
                    if len(target["bad_time"]) < 3:
                        target["bad_time"].append(f"{raw_ts} (read as {t_ms}: more than a day in the future or "
                                                  f"20 years in the past)")
                    continue
            target["bad"] -= 1
            target["read"] += 1
            if target["first"] is None:
                target["first"] = {"line": s[:300], "chain": d.chain, "header": d.header, "app": d.app,
                                   "payload": d.payload[:200]}
        elif len(target["not_read"]) < 3:
            target["not_read"].append(s[:300])
    target["remaining"] = len(samples) - len(matched)
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
    # a capital word right after the time on every sample, always the same and not captured: most
    # likely a zone that is not in ZONE_NAMES (PKT, EAT, NPT...); refuse rather than drop it
    if "tz" not in groups and "%z" not in (body.get("time_format") or "") and target["read"]:
        words = set()
        for s in matched:
            d = detect(cand, s)
            raw_ts = d.header.get("@timestamp_raw", d.header.get("@timestamp"))
            m = re.match(r"^\s+([A-Z]{2,5})\b", s[s.find(raw_ts) + len(raw_ts):]) if raw_ts and raw_ts in s else None
            words.add(m.group(1) if m else None)
        if len(words) == 1 and None not in words:
            target["bad_time"].append(f"the same word {next(iter(words))!r} follows the time on every line: if it "
                                      f"is a zone, capture it as `tz`; if it is not, flag the item")
            target["bad"] += target["read"]
            target["read"] = 0
    ambiguous = _day_month_ambiguous(body, matched)
    if ambiguous:
        target["ambiguous"] = ambiguous
    need = min(MIN_SUBSET, len(samples))
    target["needed"] = need
    ok = target["read"] >= need and target["bad"] == 0 and regress == 0 and not ambiguous
    # what saving would cost: groups of this source whose learned parser will not fit once the
    # header is read (a parser was written for the whole line); long-tail rules are carried over
    relearn = {"groups_with_rules": 0, "lines": 0, "stored_events_with_a_class": 0}
    for r in e.store.q("SELECT signature, count, parser_rule, mapping_rule FROM groups WHERE source=? AND "
                       "merged_into IS NULL", (item["source"],)):
        if r["parser_rule"] or r["mapping_rule"]:
            relearn["groups_with_rules"] += 1
            relearn["lines"] += r["count"]
            relearn["stored_events_with_a_class"] += e.store.q(
                "SELECT COUNT(*) n FROM events WHERE signature=? AND class_uid > 0", (r["signature"],))[0]["n"]
    return {"ok": ok, "target": target, "checked_lines": len(lines), "regressions": regress,
            "regression_examples": examples, "newly_read": dict(improved.most_common(10)),
            "relearn_estimate": {**relearn, "note": "parsers written for the whole line and their mappings usually "
                                 "have to be learned again once the header is read, and their events fall back to "
                                 "Base Event until then; long-tail rules (and mappings where a built-in parser reads "
                                 "the payload) are carried over by code"},
            "scope": f"only lines no other rule reads, whose first token has the shape {item['shape']!r}"}


def _day_month_ambiguous(body: dict, samples: list) -> str | None:
    """With %d and %m in the format, could every sample be read the other way round? Then the samples
    cannot tell which is the day, and the rule could be wrong on every line."""
    from .detect import normal_time
    fmt = body.get("time_format") or ""
    if "%d" not in fmt or "%m" not in fmt:
        return None
    swapped = fmt.replace("%d", "\0").replace("%m", "%d").replace("\0", "%m")
    pat = rx.compile(body["test"]["pattern"])
    differ = False
    for s in samples:
        m = pat.search(s)
        raw = m.group("timestamp") if m and "timestamp" in pat.groupindex else None
        if not raw:
            continue
        a, b = normal_time(raw, fmt), normal_time(raw, swapped)
        if a is None:
            continue
        if b is None:
            return None                   # some sample has a day above 12: the order is settled
        differ = differ or a != b
    return ("no sample has a day above 12, so day and month could be either way round; flag the item so a "
            "human decides, or wait for more lines") if differ else None


def apply(e, key: str, item: dict, body: dict, agent: str, note: str = "") -> dict:
    """Save a rule that passed `evaluate`, process the lines it now reads again, and carry the
    rules learned for the groups they leave over to their new groups."""
    res = evaluate(e, item, body)
    if not res["ok"]:
        why = []
        t = res["target"]
        if t["bad"]:
            why.append(f"it matches {t['bad']} sample lines but does not read them right: {t['bad_time']}")
        if t["read"] < t["needed"]:
            why.append(f"it reads {t['read']} of {t['lines']} sample lines; a rule must read at least "
                       f"{t['needed']}; not read: {t['not_read'][:2]}")
        if t.get("ambiguous"):
            why.append(t["ambiguous"])
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
    left = [s for s in item["samples"] if weak(detect(e.snap, s))]
    if left:              # other header formats in the same item: they stay, for the next rule or a human
        e.store.reopen(QUEUE, key, {**item, "samples": left, "rules_saved": item.get("rules_saved", []) + [rule_id]})
    else:
        e.store.queue_done(QUEUE, key)
    out = {"saved": rule_id, "version": v, "scope": res["scope"], "newly_read": res["newly_read"],
           "reprocessed": moved, "carried_over": carried, "remaining": len(left)}
    if left:
        out["next"] = (f"{len(left)} sample lines of this item are still unread (another header format); "
                       f"get_samples shows them: write the next rule, or flag them with the reason")
    return out


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
        label = src.split("|", 1)[0]
        rec = Record("carry", 0, text=raw, label=None if label == "-" else label)
        det, _, cols = e.analyse(rec)
        sg = e._sign(det, None, cols)
        res = e.parse_record(e.groups[sig], det, sg, rec)
        fields = {k: v for k, v in (res.get("fields") or {}).items()
                  if not k.startswith("@") and k != "summary" and isinstance(v, str)}
        out.append({"from": sig, "raw": raw, "label": None if label == "-" else label,
                    "longtail": lt["body"] if lt else None, "fields": fields,
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
        rec = Record("carry", 0, text=item["raw"], label=item["label"])
        det, _, cols = e.analyse(rec)
        g = e.canonical(e._sign(det, rec.label, cols).signature)
        if g is not None and g["status"] == "split":
            g = e._subgroup(g, det)
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
            elif g.get("parser_rule") and item["mapping"] is not None:
                # a built-in parser reads the new payload (key=value, JSON): the old mapping may still fit
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
