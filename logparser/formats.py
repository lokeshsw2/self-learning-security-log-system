"""Decoders for the structured formats. Fixed engine code, configured by rules.

Every decoder returns a flat dict of field name -> value. Nested structures use
dotted keys. None of them guesses: a record that does not decode raises
ParseError and goes to the dead-letter queue.
"""
from __future__ import annotations

import csv
import io
import json
import xml.etree.ElementTree as ET

from . import rx

MAX_FIELDS = 3000


class ParseError(ValueError):
    pass


# ---------------------------------------------------------------- JSON
def flatten(obj, depth: int = 8, prefix: str = "", out: dict | None = None) -> dict:
    out = {} if out is None else out
    if len(out) >= MAX_FIELDS:
        return out
    if isinstance(obj, dict) and depth > 0:
        if not obj and prefix:
            out[prefix[:-1]] = "{}"
        for k, v in obj.items():
            flatten(v, depth - 1, f"{prefix}{k}.", out)
    elif isinstance(obj, list) and depth > 0:
        if not obj and prefix:
            out[prefix[:-1]] = "[]"
        for i, v in enumerate(obj[:200]):
            flatten(v, depth - 1, f"{prefix}{i}.", out)
    elif isinstance(obj, (dict, list)):
        out[prefix[:-1]] = json.dumps(obj, ensure_ascii=False, separators=(",", ":"))
    elif obj is not None:
        out[prefix[:-1]] = obj
    return out


def parse_json(text: str) -> dict:
    try:
        obj = json.loads(text)
    except ValueError as exc:
        raise ParseError(f"invalid JSON: {str(exc)[:80]}") from None
    if not isinstance(obj, dict):
        raise ParseError("JSON record is not an object")
    return obj


def json_shape(obj: dict, depth: int) -> list[str]:
    """Key paths down to `depth`, used for signatures (values are ignored)."""
    out = []

    def walk(o, d, prefix):
        for k, v in o.items():
            if isinstance(v, dict) and d > 1 and v:
                walk(v, d - 1, f"{prefix}{k}.")
            else:
                out.append(f"{prefix}{k}")
    walk(obj, depth, "")
    return sorted(out)


# ---------------------------------------------------------------- key=value
def kv_pairs(text: str, dialect: dict) -> tuple[dict, str, int, str]:
    """Return (fields, leftover text, characters covered by pairs, text before the first pair)."""
    fields: dict = {}
    covered = 0
    if dialect["mode"] == "pair":
        pat = rx.compile(dialect["pair_pattern"])
        gi = pat.groupindex
        left, pos, first = [], 0, None
        for m in pat.finditer(text):
            if first is None:
                first = m.start()
            k = m.group("k")
            v = None
            for qg in ("q", "s"):
                if qg in gi and m.group(qg) is not None:
                    v = m.group(qg)
                    if dialect.get("unescape", True) and "\\" in v:
                        v = v.replace('\\"', '"').replace("\\\\", "\\")
                    break
            if v is None and "v" in gi:
                v = m.group("v")
            if v is None:
                v = ""
            if k not in fields:
                fields[k] = v
            else:
                n = 2
                while f"{k}#{n}" in fields:
                    n += 1
                fields[f"{k}#{n}"] = v
            left.append(text[pos:m.start()])
            pos = m.end()
            covered += m.end() - m.start()
            if len(fields) >= MAX_FIELDS:
                break
        left.append(text[pos:])
        leftover = " ".join(" ".join(left).split())
        return fields, leftover, covered, text[: first or 0].strip()
    pat = rx.compile(dialect["key_pattern"])
    ki = pat.groupindex["k"]
    ms = list(pat.finditer(text))
    if not ms:
        return {}, text.strip(), 0, text.strip()
    strip = dialect.get("strip", " \t")
    for i, m in enumerate(ms):
        end = ms[i + 1].start() if i + 1 < len(ms) else len(text)
        v = text[m.end():end].strip(strip)
        if dialect.get("unescape", True) and "\\" in v:
            v = v.replace("\\=", "=").replace("\\|", "|").replace("\\\\", "\\")
        k = m.group(ki)
        if k not in fields:
            fields[k] = v
        if len(fields) >= MAX_FIELDS:
            break
    leftover = text[: ms[0].start()].strip()
    return fields, leftover, len(text) - ms[0].start(), leftover


# ---------------------------------------------------------------- CEF / LEEF
def _split_header(text: str, n: int) -> list[str]:
    parts, cur, i = [], [], 0
    while i < len(text) and len(parts) < n:
        ch = text[i]
        if ch == "\\" and i + 1 < len(text) and text[i + 1] in "|\\":
            cur.append(text[i + 1])
            i += 2
            continue
        if ch == "|":
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
        i += 1
    if len(parts) < n:
        raise ParseError(f"header has {len(parts)} of {n} fields")
    parts.append(text[i:])
    return parts


CEF_EXT = {"mode": "span", "key_pattern": r"(?:^|\s)(?P<k>[A-Za-z_][\w.\-]*)=", "strip": " \t"}
LEEF_EXT = {"mode": "span", "key_pattern": r"(?:^|[\t ])(?P<k>[A-Za-z_][\w.\-]*)=", "strip": " \t"}


def _labels(fields: dict) -> None:
    for k in [k for k in fields if k.endswith("Label")]:
        base = k[:-5]
        name = str(fields[k]).strip()
        if base in fields and name and f"label.{name}" not in fields:
            fields[f"label.{name}"] = fields[base]


def parse_cef(text: str) -> dict:
    i = text.find("CEF:")
    if i < 0:
        raise ParseError("no CEF: marker")
    h = _split_header(text[i + 4:], 7)
    fields = {"cef.version": h[0].strip(), "cef.vendor": h[1], "cef.product": h[2], "cef.device_version": h[3],
              "cef.signature_id": h[4], "cef.name": h[5], "cef.severity": h[6]}
    ext = kv_pairs(h[7], CEF_EXT)[0]
    _labels(ext)
    for k, v in ext.items():
        fields.setdefault(k, v)
    return fields


def parse_leef(text: str) -> dict:
    i = text.find("LEEF:")
    if i < 0:
        raise ParseError("no LEEF: marker")
    h = _split_header(text[i + 5:], 5)
    fields = {"leef.version": h[0].strip(), "leef.vendor": h[1], "leef.product": h[2],
              "leef.product_version": h[3], "leef.event_id": h[4]}
    rest = h[5]
    delim = None
    if h[0].strip().startswith("2") and "|" in rest:
        head, tail = rest.split("|", 1)
        if len(head) == 1 or (head.lower().startswith(("x", "0x")) and len(head) <= 6):
            delim = head if len(head) == 1 else chr(int(head.lower().lstrip("0x") or "9", 16))
            rest = tail
    if delim and delim not in "\t ":
        ext = {}
        for part in rest.split(delim):
            if "=" in part:
                k, v = part.split("=", 1)
                ext.setdefault(k.strip(), v.strip())
    else:
        ext = kv_pairs(rest, LEEF_EXT)[0]
    _labels(ext)
    for k, v in ext.items():
        fields.setdefault(k, v)
    return fields


# ---------------------------------------------------------------- delimited
def split_delimited(text: str, delimiter: str, quote: str = '"') -> list[str]:
    if quote and quote in text:
        try:
            return next(csv.reader(io.StringIO(text), delimiter=delimiter, quotechar=quote))
        except (csv.Error, StopIteration):
            pass
    return text.split(delimiter)


def parse_delimited(text: str, delimiter: str, columns: list[str] | None, quote: str = '"',
                    strip: bool = True) -> dict:
    vals = split_delimited(text, delimiter, quote)
    if columns and len(vals) != len(columns):
        raise ParseError(f"expected {len(columns)} columns, got {len(vals)}")
    names = columns or [f"c{i}" for i in range(len(vals))]
    out = {}
    for n, v in zip(names, vals):
        v = v.strip() if strip else v
        if v != "":
            out[n] = v
    return out


# ---------------------------------------------------------------- XML
def parse_xml(text: str) -> dict:
    if "<!DOCTYPE" in text or "<!ENTITY" in text:
        raise ParseError("XML with DOCTYPE or ENTITY declarations is refused")
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        raise ParseError(f"invalid XML: {str(exc)[:80]}") from None
    out: dict = {}

    def tag(el) -> str:
        return el.tag.split("}", 1)[-1]

    def put(key: str, val: str) -> None:
        if len(out) >= MAX_FIELDS:
            return
        if key in out:
            n = 2
            while f"{key}#{n}" in out:
                n += 1
            key = f"{key}#{n}"
        out[key] = val

    def walk(el, path: str) -> None:
        named = el.attrib.get("Name") or el.attrib.get("name")
        here = f"{path}.{named}" if named and not len(el) else path
        for a, v in el.attrib.items():
            if named and not len(el) and a in ("Name", "name"):
                continue
            put(f"{here}.@{a.split('}', 1)[-1]}", v)
        txt = (el.text or "").strip()
        if txt:
            put(here, txt)
        for child in el:
            walk(child, f"{path}.{tag(child)}")

    walk(root, tag(root))
    return out


def xml_shape(text: str) -> tuple[str, list[str]]:
    fields = parse_xml(text)
    keys = sorted({k.split("#", 1)[0] for k in fields})
    root = keys[0].split(".", 1)[0] if keys else ""
    return root, keys
