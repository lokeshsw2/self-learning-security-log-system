"""Format detection: cheap ordered checks loaded from the registry.

An envelope check (a syslog header, a vendor tag) strips its header and
detection runs again on the payload, so hybrids such as
syslog -> CEF or syslog -> JSON resolve to a chain of names.

Rules the detection agent added (names starting `ai_`) are fallbacks: they are tried only on
a line that no other rule reads at all. So an added rule can never change how a line that is
read today is read, whether or not that line was ever stored.
"""
from __future__ import annotations

import datetime as _dt
import re
from dataclasses import dataclass, field

from . import formats, rx
from .registry import Snapshot

MAX_DEPTH = 4


@dataclass
class Detection:
    chain: list = field(default_factory=list)
    format: str = "unstructured"
    payload: str = ""
    header: dict = field(default_factory=dict)   # envelope fields, keys start with "@"
    app: str | None = None
    dialect: str | None = None
    delimiter: str | None = None

    @property
    def bucket(self) -> str:
        return ">".join(self.chain) + "|" + (self.app or "-")


def _clean_app(app: str) -> str:
    return app.strip()[:80]


_DATE_CODES = ("%d", "%m", "%b", "%B", "%j")


def normal_time(raw: str, fmt: str) -> str | None:
    """A time read with the rule's `time_format`, written the way the time parser reads everything:
    "2026-11-22T10:15:03.456000" (with a date), "10:15:03.456000" (time of day), offset if the format
    has %z. None when the text does not fit the format."""
    try:
        d = _dt.datetime.strptime(raw, fmt)
    except ValueError:
        return None
    out = d.strftime("%Y-%m-%dT%H:%M:%S" if any(c in fmt for c in _DATE_CODES) else "%H:%M:%S")
    if d.microsecond:
        out += f".{d.microsecond:06d}"
    if d.tzinfo is not None:
        off = d.utcoffset()
        mins = int(off.total_seconds() // 60)
        out += f"{'+' if mins >= 0 else '-'}{abs(mins) // 60:02d}:{abs(mins) % 60:02d}"
    return out


def _test(test: dict, text: str, snap: Snapshot):
    """Return (matched, named captures or None, extra)."""
    kind = test["kind"]
    if kind == "always":
        return True, None, None
    if kind == "prefix":
        return text.startswith(test["value"]), None, None
    if kind == "json":
        s = text.strip()
        # real JSON objects open with a quoted key (or are empty); `{key:'v'}` is not JSON
        return s.startswith("{") and s.endswith("}") and s[1:].lstrip()[:1] in ('"', "}"), None, None
    if kind == "xml":
        s = text.lstrip()
        return (len(s) > 2 and s[0] == "<" and (s[1].isalpha() or s[1] in "?!") and s.rstrip().endswith(">")), None, None
    if kind == "regex":
        gd = rx.search_dict(test["pattern"], text)
        if gd is None:
            return False, None, None
        # "-" is the syslog NILVALUE: treat it as absent
        return True, {k: v for k, v in gd.items()
                      if v is not None and (v != "-" or k == "payload")}, None
    if kind == "json_wrap":
        # a small JSON object whose one field holds the real log line (an agent or forwarder wrapper)
        s = text.strip()
        if not (s.startswith("{") and s.endswith("}")):
            return False, None, None
        try:
            obj = formats.parse_json(s)
        except formats.ParseError:
            return False, None, None
        if len(obj) > test.get("max_keys", 6):
            return False, None, None
        for f in test["fields"]:
            v = obj.get(f)
            if isinstance(v, str) and len(v) > 20:
                caps = {k: str(x) for k, x in obj.items() if k != f and isinstance(x, (str, int, float))}
                caps["payload"] = v
                return True, caps, None
        return False, None, None
    if kind == "kv":
        dialect = snap.dialects.get(test["dialect"])
        if not dialect:
            return False, None, None
        fields, _, covered, _ = formats.kv_pairs(text, dialect)
        ok = (len(fields) >= test.get("min_pairs", 3)
              and covered / max(1, len(text)) >= test.get("min_coverage", 0.5))
        return ok, None, test["dialect"]
    if kind == "delimited":
        d = test["delimiter"]
        if text.count(d) + 1 < test.get("min_fields", 5):
            return False, None, None
        parts = formats.split_delimited(text, d)
        if "max_first_share" in test and len(parts[0]) > test["max_first_share"] * len(text):
            return False, None, None      # one long text field with a few commas at the end is not a table
        return len(parts) >= test.get("min_fields", 5), None, d
    return False, None, None


AI_PREFIX = "ai_"


def shape(line: str) -> str:
    """The shape of a line's first token: digits -> 0, letters -> a ("2026-09-20T14:11:02" -> "0-0-0a0:0:0").
    In a header with no spaces ("1795322103123|edge-fw-02|vpnd|...") only the first field counts, with
    its delimiter, so a varying host or program name does not split one format into several shapes."""
    tok = line.lstrip().split(" ", 1)[0][:48]
    cut = min((i for i in (tok.find("|"), tok.find(";")) if i >= 0), default=-1)
    if cut >= 0:
        tok = tok[:cut + 1]
    return re.sub(r"[A-Za-z]+", "a", re.sub(r"\d+", "0", tok))


def detect(snap: Snapshot, text: str) -> Detection:
    det = _detect(snap, text, set(), skip_ai=True)
    if det.chain == ["unstructured"]:
        sh = None
        for chk in snap.detect:                      # added rules: only for lines nothing else reads
            if not chk["name"].startswith(AI_PREFIX):
                continue
            if chk.get("when_shape"):                # and only for the line shape they were written for
                sh = sh or shape(text)
                if sh not in chk["when_shape"]:
                    continue
            ok, caps, _ = _test(chk["test"], text, snap)
            if ok and caps is not None and caps.get("payload") is not None:
                return _detect(snap, text, set(), skip_ai=True, first=chk)
    return det


def _detect(snap: Snapshot, text: str, used: set, skip_ai: bool, first: dict | None = None) -> Detection:
    det = Detection(payload=text)
    for _ in range(MAX_DEPTH + 1):
        advanced = False
        for chk in ([first] if first is not None and not det.chain else snap.detect):
            name = chk["name"]
            if name in used or chk["test"]["kind"] == "binary":
                continue
            if skip_ai and name.startswith(AI_PREFIX) and chk is not first:
                continue
            ok, caps, extra = _test(chk["test"], det.payload, snap)
            if not ok:
                continue
            caps = caps or {}
            if caps.get("timestamp") and chk.get("time_format"):
                norm = normal_time(caps["timestamp"], chk["time_format"])
                if norm is not None:
                    caps["timestamp_raw"], caps["timestamp"] = caps["timestamp"], norm
            if caps.get("timestamp") and caps.get("tz"):          # a zone written next to the time travels with it
                caps["timestamp"] = f"{caps['timestamp']} {caps['tz']}"
            payload = caps.pop("payload", None)
            if payload is None and chk.get("payload_fallback"):
                payload = caps.get(chk["payload_fallback"])
            if payload == "" and chk.get("payload_fallback") and caps.get(chk["payload_fallback"]):
                payload = caps[chk["payload_fallback"]]
            for fld, pats in (chk.get("header_patterns") or {}).items():
                src = caps.get(fld)
                if src:
                    for p in pats:
                        m = rx.compile(p).search(src)
                        if m:
                            caps.update({k: v for k, v in m.groupdict().items() if v is not None})
                            break
            for k, v in caps.items():
                det.header.setdefault("@" + k, v)
            app = "-".join(caps[k] for k in chk.get("app", []) if caps.get(k))
            if app:
                det.app = _clean_app(app)
            det.chain.append(name)
            used.add(name)
            if chk["type"] == "envelope":
                if payload is None:
                    payload = ""
                det.payload = payload
                advanced = len(det.chain) <= MAX_DEPTH
            else:
                if payload is not None:
                    det.payload = payload
                det.format = chk["format"]
                if chk["test"]["kind"] == "kv":
                    det.dialect = extra
                if chk["test"]["kind"] == "delimited":
                    det.delimiter = extra
                return det
            break
        if not advanced:
            break
    det.chain.append("unstructured")
    det.format = "unstructured"
    return det
