"""Meaning checks that code can do: does the mapped event agree with the line?

Schema validation proves types fit. These checks catch two kinds of meaning
error that need no judgement:

  time     the mapped `time` disagrees by an hour or more with every zoned
           timestamp found in the line (header or field), or fell back to the
           ingest time although the line carries a timestamp
  outcome  a field such as `action` or `result` holds a block or failure word,
           but the event has no outcome at all, or states the opposite

They run in the mapping gate (a rule that fails them is refused) and in the
audit over saved mappings.
"""
from __future__ import annotations

from . import rx, transforms

OUTCOME_KEYS = {"action", "act", "result", "outcome", "status", "verdict", "disposition", "decision",
                "pattern_action", "proxy_act", "reason", "log_subtype", "subtype", "fw_action", "event_outcome", "eventoutcome"}
FAIL_WORDS = {"denied", "deny", "blocked", "block", "dropped", "drop", "rejected", "reject", "refused", "failed",
              "failure", "quarantined", "prevented", "terminated", "reset-both", "reset-client", "reset-server"}
OK_WORDS = {"allowed", "allow", "accepted", "accept", "permitted", "permit", "success", "succeeded", "successful",
            "passed", "pass"}
_ZONED = rx.compile(r"^\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d(?:[.,]\d+)?\s*(?:Z|[+-]\d\d:?\d\d)$")
_WORD = rx.compile(r"[A-Za-z]+")          # "user_rejected" -> user, rejected
# event-name fields: only their last part states an outcome ("mfa.challenge.denied" -> denied)
EVENT_KEYS = {"event", "event_type", "eventtype", "event_name", "eventname", "type", "name", "operation", "activity"}
_LAST = rx.compile(r"[A-Za-z]+$")
_DATEISH = rx.compile(r"\b(?:\d{4}[-/]\d\d[-/]\d\d|(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) +\d{1,2} )")
_EPOCH_KEYS = {"ts", "time", "timestamp", "eventtime", "event_time", "epoch", "created", "start", "end", "rt"}
NEGATIONS = {"not", "no", "un", "non"}
HOUR_MS = 3_600_000


def _epoch(v) -> int | None:
    s = str(v).strip()
    if not s.isdigit():
        return None
    n = int(s)
    if len(s) == 18 and s.startswith(("13", "12")):          # Windows FILETIME, 100 ns since 1601 (UTC)
        return (n - 116444736000000000) // 10000
    return {10: n * 1000, 13: n, 16: n // 1000, 19: n // 1000000}.get(len(s))


def _zoned_times(det, fields: dict) -> list:
    out = []
    for k, v in fields.items():           # epoch numbers carry no zone problem: they are UTC by definition
        if k.split(".")[-1].lower() in _EPOCH_KEYS:
            ms = _epoch(v)
            if ms and 1_000_000_000_000 < ms < 4_000_000_000_000:
                out.append((k, ms))
    for k, v in list(det.header.items()) + list(fields.items()):
        if isinstance(v, str) and 19 <= len(v) <= 40 and _ZONED.match(v.strip()):
            try:
                out.append((k, transforms.parse_timestamp(v.strip(), {}, {"default_tz": "UTC"})))
            except transforms.TransformError:
                pass
    return out


def _outcome_words(fields: dict) -> tuple[set, set, str | None]:
    fail, ok, where = set(), set(), None
    for k, v in fields.items():
        if not isinstance(v, str) or len(v) > 60:
            continue
        key = k.split(".")[-1].split("#")[0].lower()
        if key in OUTCOME_KEYS:
            words = {w.lower() for w in _WORD.findall(v)}
        elif key in EVENT_KEYS and any(ch in v for ch in "._:/-"):
            last = _LAST.search(v.strip())
            words = {last.group(0).lower()} if last else set()
        else:
            continue
        if words & NEGATIONS:                # "not blocked", "no action": not an outcome word here
            continue
        f, o = words & FAIL_WORDS, words & OK_WORDS
        if f or o:
            fail |= f
            ok |= o
            where = where or f"{k}={v!r}"
    return fail, ok, where


def problems(det, fields: dict, event: dict, tags: list, mapping: dict) -> list:
    out = []
    if not event:
        return out
    t = event.get("time")
    zoned = _zoned_times(det, fields)
    if "time_from_ingest" in tags and not mapping.get("time_from_ingest_ok"):
        texts = [v for v in list(det.header.values()) + list(fields.values()) if isinstance(v, str)]
        if zoned or det.header.get("@timestamp") or any(_DATEISH.search(v) for v in texts):
            out.append("time: the event got the ingest time, but the line has a timestamp; map `time` from it")
    elif isinstance(t, int) and zoned and all(abs(t - z) >= HOUR_MS for _, z in zoned):
        k, z = min(zoned, key=lambda kz: abs(t - kz[1]))
        out.append(f"time: mapped time is {round((t - z) / HOUR_MS, 2)} h away from the line's own timestamp "
                   f"`{k}`; a time without a zone was probably read as UTC")
    fail, ok, where = _outcome_words(fields)
    if fail and not ok:
        has = any(isinstance(event.get(a), int) and event.get(a) not in (0,)
                  for a in ("status_id", "action_id", "disposition_id"))
        if not has:
            out.append(f"outcome: {where} says the event was blocked or failed, but it has no status_id, "
                       f"action_id or disposition_id")
        elif event.get("status_id") == 1 and event.get("action_id") in (None, 1) and event.get("disposition_id") in (None, 1):
            out.append(f"outcome: {where} says blocked or failed, but the event says Success/Allowed")
    elif ok and not fail and (event.get("action_id") == 2 or event.get("status_id") == 2) \
            and event.get("disposition_id") in (None, 1):
        out.append(f"outcome: {where} says allowed or succeeded, but the event says Failure/Denied")
    return out
