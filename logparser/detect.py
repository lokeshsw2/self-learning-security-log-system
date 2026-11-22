"""Format detection: cheap ordered checks loaded from the registry.

An envelope check (a syslog header, a vendor tag) strips its header and
detection runs again on the payload, so hybrids such as
syslog -> CEF or syslog -> JSON resolve to a chain of names.
"""
from __future__ import annotations

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


def _test(test: dict, text: str, snap: Snapshot):
    """Return (matched, named captures or None, extra)."""
    kind = test["kind"]
    if kind == "always":
        return True, None, None
    if kind == "prefix":
        return text.startswith(test["value"]), None, None
    if kind == "json":
        s = text.strip()
        return s.startswith("{") and s.endswith("}"), None, None
    if kind == "xml":
        s = text.lstrip()
        return (len(s) > 2 and s[0] == "<" and (s[1].isalpha() or s[1] in "?!") and s.rstrip().endswith(">")), None, None
    if kind == "regex":
        m = rx.compile(test["pattern"]).search(text)
        if not m:
            return False, None, None
        # "-" is the syslog NILVALUE: treat it as absent
        return True, {k: v for k, v in m.groupdict().items()
                      if v is not None and (v != "-" or k == "payload")}, None
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
        n = len(formats.split_delimited(text, d))
        return n >= test.get("min_fields", 5), None, d
    return False, None, None


def detect(snap: Snapshot, text: str) -> Detection:
    det = Detection(payload=text)
    used: set = set()
    for _ in range(MAX_DEPTH + 1):
        advanced = False
        for chk in snap.detect:
            name = chk["name"]
            if name in used or chk["test"]["kind"] == "binary":
                continue
            ok, caps, extra = _test(chk["test"], det.payload, snap)
            if not ok:
                continue
            caps = caps or {}
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
