"""Parser runner: executes one parser rule on one record. No format knowledge
lives here beyond the fixed decoders in formats.py."""
from __future__ import annotations

import json

from . import formats, rx
from .detect import Detection
from .formats import ParseError
from .registry import Snapshot


def auto_parser(det: Detection, columns: list | None = None) -> dict | None:
    """The parser rule the engine can write by itself for a structured format."""
    f = det.format
    if f in ("json", "cef", "leef", "xml"):
        return {"kind": f}
    if f == "kv":
        return {"kind": "kv", "dialect": det.dialect}
    if f == "delimited":
        body = {"kind": "delimited", "delimiter": det.delimiter or ","}
        if columns:
            body["columns"] = list(columns)
        return body
    return None


def run(snap: Snapshot, body: dict, det: Detection, base: dict | None = None) -> dict:
    """Return the extracted fields, or raise ParseError."""
    kind = body["kind"]
    text = det.payload
    if kind == "regex":
        m = rx.compile(body["pattern"]).search(text)
        if not m:
            raise ParseError("pattern did not match")
        fields = {k: v for k, v in m.groupdict().items() if v is not None and v != ""}
    elif kind == "json":
        fields = formats.flatten(formats.parse_json(text))
    elif kind == "kv":
        dialect = snap.dialects.get(body["dialect"])
        if not dialect:
            raise ParseError(f"unknown dialect {body['dialect']}")
        fields, leftover, _, _ = formats.kv_pairs(text, dialect)
        if not fields:
            raise ParseError("no key=value pairs")
        if leftover:
            fields["_text"] = leftover
    elif kind == "cef":
        fields = formats.parse_cef(text)
    elif kind == "leef":
        fields = formats.parse_leef(text)
    elif kind == "delimited":
        fields = formats.parse_delimited(text, body["delimiter"], body.get("columns"), body.get("quote", '"'),
                                         body.get("strip", True))
    elif kind == "xml":
        fields = formats.parse_xml(text)
    else:
        raise ParseError(f"unknown parser kind {kind}")

    for n in body.get("nested") or []:
        v = fields.get(n["field"])
        if not isinstance(v, str) or not v.strip():
            continue
        prefix = n.get("prefix", n["field"] + ".")
        try:
            if n["kind"] == "json":
                sub = formats.flatten(formats.parse_json(v.strip()))
            else:
                dialect = snap.dialects.get(n.get("dialect", "kv_eq"))
                sub = formats.kv_pairs(v, dialect)[0] if dialect else {}
        except ParseError:
            continue
        for k, sv in sub.items():
            fields.setdefault(prefix + k, sv)
    for e in body.get("extract") or []:
        v = fields.get(e["field"])
        if isinstance(v, str):
            m = rx.compile(e["pattern"]).search(v)
            if m:
                for k, sv in m.groupdict().items():
                    if sv is not None and sv != "":
                        fields.setdefault(k, sv)
    for k, v in det.header.items():
        fields.setdefault(k, v)
    return fields


def not_literal(fields: dict, raw: str) -> list:
    """Field names whose value does not appear literally in the raw record.

    Decoded escapes are tolerated: a value also passes when it matches the raw
    text with backslash escapes removed, or in its JSON-encoded form.
    """
    bad = []
    loose = None
    for k, v in fields.items():
        if isinstance(v, bool):
            s = "true" if v else "false"
        elif isinstance(v, float) and v == int(v) and str(int(v)) in raw:
            continue
        else:
            s = str(v)
        if s == "" or s in raw:
            continue
        enc = json.dumps(s, ensure_ascii=False)[1:-1]
        if enc in raw or json.dumps(s)[1:-1] in raw:
            continue
        if loose is None:
            loose = raw.replace("\\", "")
        if s.replace("\\", "") in loose or " ".join(s.split()) in " ".join(loose.split()):
            continue
        if isinstance(v, float):
            try:
                if any(float(tok) == v for tok in rx.compile(r"-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?").findall(raw)):
                    continue
            except ValueError:
                pass
        bad.append(k)
    return bad
