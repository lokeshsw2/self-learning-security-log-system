"""Template signatures.

Unstructured text: mask variables with placeholders, keep the punctuation,
hash the result. Structured records: hash the key set plus the values of a few
discriminator keys. Both are stateless per record.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from . import formats
from .detect import Detection
from .registry import Snapshot


@dataclass
class Signed:
    signature: str
    template: str                       # masked text, or a readable key list
    variables: list = field(default_factory=list)   # [(placeholder, original value)] in template order
    detail: dict = field(default_factory=dict)      # keys, discriminators, columns
    parsed: dict | None = None          # decoded record, reused by the parser stage
    error: str | None = None
    family: str | None = None           # source family for structured records without a producer name


_EDGE = "\"'[](){}<>.,;:!"


def mask(text: str, patterns: list, protected=frozenset()) -> tuple[str, list]:
    """Apply ordered mask patterns. Later patterns never see masked spans.
    A match that is a protected word (failed, denied, accepted, ...) is left as
    fixed text, so different outcomes never share a signature."""
    segs: list = [(text, None)]            # (text, placeholder or None)
    for _name, pat, placeholder, group in patterns:
        nxt: list = []
        for seg, ph in segs:
            if ph is not None or not seg:
                nxt.append((seg, ph))
                continue
            pos = 0
            for m in pat.finditer(seg):
                s, e = m.span(group)
                if s < 0 or e <= s:
                    continue
                if s < pos:
                    continue
                if protected and seg[s:e].strip(_EDGE).lower() in protected:
                    continue
                if s > pos:
                    nxt.append((seg[pos:s], None))
                nxt.append((seg[s:e], placeholder))
                pos = e
            if pos < len(seg):
                nxt.append((seg[pos:], None))
        segs = nxt
    out, variables = [], []
    for seg, ph in segs:
        if ph is None:
            out.append(seg)
        else:
            out.append(ph)
            variables.append((ph, seg))
    return "".join(out), variables


def _h(*parts: str) -> str:
    h = hashlib.blake2b(digest_size=10)
    for p in parts:
        h.update(p.encode("utf-8", "replace"))
        h.update(b"\x1f")
    return h.hexdigest()


def _disc_values(fields: dict, header: dict, discriminators: list) -> list:
    out = []
    for d in discriminators:
        v = fields.get(d, header.get(d))
        if v is not None and not isinstance(v, (dict, list)):
            out.append(f"{d}={str(v)[:120]}")
    return out


def sign(snap: Snapshot, det: Detection, stream: str | None, columns: list | None = None,
         family_of=None) -> Signed:
    bucket = det.bucket
    fmt = det.format
    if fmt == "unstructured":
        template, variables = mask(det.payload, snap.mask_patterns(bucket, stream), snap.protected)
        template = " ".join(template.split())
        return Signed(_h(bucket, "u", template), template, variables)

    rule = snap.sign_rule(bucket, stream)
    try:
        if fmt == "json":
            obj = formats.parse_json(det.payload)
            keys = formats.json_shape(obj, rule.get("depth", 1))
            flat = formats.flatten(obj)
            text = ""
        elif fmt == "kv":
            dialect = snap.dialects[det.dialect]
            flat, leftover, _, prefix = formats.kv_pairs(det.payload, dialect)
            keys = sorted(k.split("#", 1)[0] for k in flat)
            keys = sorted(set(keys))
            text = ""
            if prefix and rule.get("text", True):
                # only the words before the first pair: trailing flags must not split the group
                text, _ = mask(prefix, snap.mask_patterns(bucket, stream), snap.protected)
                text = " ".join(text.split())
            if leftover:
                flat = dict(flat)
                flat["_text"] = leftover
        elif fmt == "cef":
            flat = formats.parse_cef(det.payload)
            keys = [f"cef|{flat['cef.vendor']}|{flat['cef.product']}|{flat['cef.signature_id'][:80]}"]
            text = ""
        elif fmt == "leef":
            flat = formats.parse_leef(det.payload)
            keys = [f"leef|{flat['leef.vendor']}|{flat['leef.product']}|{flat['leef.event_id'][:80]}"]
            text = ""
        elif fmt == "delimited":
            vals = formats.split_delimited(det.payload, det.delimiter or ",")
            if columns and len(columns) == len(vals):
                flat = {c: v for c, v in zip(columns, vals)}
                keys = [f"cols={','.join(columns)}"]
            else:
                flat = {f"c{i}": v for i, v in enumerate(vals)}
                keys = [f"n={len(vals)}"]
            text = ""
        elif fmt == "xml":
            flat = formats.parse_xml(det.payload)
            keys = sorted({k.split("#", 1)[0] for k in flat})
            text = ""
        else:
            template, variables = mask(det.payload, snap.mask_patterns(bucket, stream), snap.protected)
            return Signed(_h(bucket, "u", template), template, variables)
    except formats.ParseError as exc:
        # Looked structured but does not decode (truncated JSON, broken CEF header).
        template, variables = mask(det.payload[:400], snap.mask_patterns(bucket, stream), snap.protected)
        return Signed(_h(bucket, "broken", fmt), f"<undecodable {fmt}>", variables, error=str(exc))

    family = family_of(det, flat) if family_of else None
    if family:
        rule = snap.sign_rule(bucket, stream, family)
    mode = rule.get("keys", "auto")
    disc = _disc_values(flat, det.header, rule.get("discriminators") or [])
    if fmt in ("cef", "leef", "delimited"):
        sig_keys = keys
    elif mode == "auto":
        # The record names its own event type: optional keys must not split the group.
        sig_keys = [] if disc else keys
    elif mode == "core":
        core = set(rule.get("core_keys") or [])
        sig_keys = [k for k in keys if k in core]
    elif mode == "none":
        sig_keys = []
    else:
        sig_keys = keys
    # A field whose value is an outcome or action word marks the event type.
    prot = []
    if snap.protected and fmt in ("json", "kv", "cef", "leef", "xml"):
        for k, v in flat.items():
            if isinstance(v, str) and 2 < len(v) <= 24 and k.count(".") <= 1 and v.lower() in snap.protected:
                prot.append(f"{k}={v.lower()}")
        prot = sorted(prot)[:4]
    disc = disc + prot
    template = " ".join(sig_keys)
    if disc:
        template += " :: " + " ".join(disc)
    if text:
        template += " :: " + text
    detail = {"keys": keys[:400], "sig_keys": sig_keys[:400], "discriminators": disc, "text": text}
    return Signed(_h(bucket, fmt, "\x1e".join(sig_keys), "\x1e".join(disc), text), template[:4000], [], detail, flat,
                  family=family)
