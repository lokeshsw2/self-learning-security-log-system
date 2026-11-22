"""The rule registry: every format-specific decision is a rule stored as data.

Rule kinds
  framing    how a stream is cut into records (multiline, octet counting)
  directive  in-band header lines such as `#Fields:` that name columns
  detect     ordered format checks and envelopes (syslog headers and the like)
  dialect    a key-value tokenizer (pair pattern or key pattern)
  mask       variable masks for unstructured text, scoped to a bucket
  sign       how structured records are signed (keys, discriminators)
  parser     regex / json / kv / cef / leef / delimited / xml extraction
  mapping    OCSF class, constants and field mappings with transforms
  longtail   positional extraction for one rare signature

Rules are a restricted config language: patterns (RE2), key lists, field paths
and transforms from the fixed library in transforms.py. Every rule is checked
against a JSON Schema plus semantic checks on save and on load, stored as a new
version, and can be rolled back. Nothing here executes rule-supplied code.
"""
from __future__ import annotations

import json
import os
from typing import Any

import jsonschema

from . import rx, transforms
from .store import SqliteStore

SCOPE = {"type": "object", "additionalProperties": False,
         "properties": {"bucket": {"type": "string"}, "stream": {"type": ["string", "null"]}}}
STR_LIST = {"type": "array", "items": {"type": "string"}}
TRANSFORM = {"type": "object", "required": ["fn"], "additionalProperties": False,
             "properties": {"fn": {"type": "string"}, "args": {"type": "object"}}}
TRANSFORMS = {"oneOf": [TRANSFORM, {"type": "array", "items": TRANSFORM, "maxItems": 6}]}
WHEN = {"type": "object", "required": ["field"], "additionalProperties": False,
        "properties": {"field": {"type": "string"}, "equals": {"type": "string"}, "in": STR_LIST,
                       "matches": {"type": "string"}, "exists": {"type": "boolean"}}}
NESTED = {"type": "array", "maxItems": 8, "items": {
    "type": "object", "required": ["field", "kind"], "additionalProperties": False,
    "properties": {"field": {"type": "string"}, "kind": {"enum": ["json", "kv"]},
                   "dialect": {"type": "string"}, "prefix": {"type": "string"}}}}
MATCH = {"type": "object", "additionalProperties": False,
         "properties": {"requires": STR_LIST, "absent": STR_LIST, "equals": {"type": "object"}}}
EXTRACT = {"type": "array", "maxItems": 12, "items": {
    "type": "object", "required": ["field", "pattern"], "additionalProperties": False,
    "properties": {"field": {"type": "string"}, "pattern": {"type": "string"}}}}

SCHEMAS: dict[str, dict] = {
    "framing": {"type": "object", "additionalProperties": False, "properties": {
        "continuation": STR_LIST, "multiline_json": {"type": "boolean"}, "multiline_xml": {"type": "boolean"},
        "octet_counting": {"type": "boolean"}, "max_record_lines": {"type": "integer", "minimum": 1}}},
    "directive": {"type": "object", "required": ["pattern", "field_sep", "delimiter"], "additionalProperties": False,
                  "properties": {"pattern": {"type": "string"}, "field_sep": {"type": "string"},
                                 "delimiter": {"type": "string"}, "drop_pattern": {"type": "string"},
                                 "delimiter_pattern": {"type": "string"}}},
    "detect": {"type": "object", "required": ["order", "type", "name", "test"], "additionalProperties": False,
               "properties": {
                   "order": {"type": "number"}, "type": {"enum": ["envelope", "format"]},
                   "name": {"type": "string", "pattern": "^[a-z0-9_]+$"}, "format": {"type": "string"},
                   "app": STR_LIST, "payload_fallback": {"type": "string"}, "header_patterns": {"type": "object", "additionalProperties": STR_LIST},
                   "test": {"type": "object", "required": ["kind"], "additionalProperties": False, "properties": {
                       "kind": {"enum": ["regex", "prefix", "json", "xml", "kv", "delimited", "binary", "always",
                                         "json_wrap"]},
                       "fields": STR_LIST, "max_keys": {"type": "integer"},
                       "pattern": {"type": "string"}, "value": {"type": "string"}, "dialect": {"type": "string"},
                       "min_pairs": {"type": "integer"}, "min_coverage": {"type": "number"},
                       "delimiter": {"type": "string"}, "min_fields": {"type": "integer"},
                       "max_first_share": {"type": "number"},
                       "max_nonprintable": {"type": "number"}}}}},
    "dialect": {"type": "object", "required": ["mode"], "additionalProperties": False, "properties": {
        "mode": {"enum": ["pair", "span"]}, "pair_pattern": {"type": "string"}, "key_pattern": {"type": "string"},
        "strip": {"type": "string"}, "unescape": {"type": "boolean"}}},
    "mask": {"type": "object", "required": ["scope", "patterns"], "additionalProperties": False, "properties": {
        "scope": SCOPE, "priority": {"type": "integer"}, "mode": {"enum": ["replace", "extend"]},
        "patterns": {"type": "array", "maxItems": 40, "items": {
            "type": "object", "required": ["name", "pattern", "placeholder"], "additionalProperties": False,
            "properties": {"name": {"type": "string"}, "pattern": {"type": "string"},
                           "placeholder": {"type": "string", "pattern": "^<[A-Z_*]+>$"},
                           "group": {"type": "integer", "minimum": 0}}}}}},
    "sign": {"type": "object", "required": ["scope"], "additionalProperties": False, "properties": {
        "scope": SCOPE, "priority": {"type": "integer"}, "keys": {"enum": ["auto", "all", "core", "none"]},
        "core_keys": STR_LIST, "discriminators": STR_LIST, "text": {"type": "boolean"}, "depth": {"type": "integer", "minimum": 1, "maximum": 4}}},
    "parser": {"type": "object", "required": ["kind"], "additionalProperties": False, "properties": {
        "kind": {"enum": ["regex", "json", "kv", "cef", "leef", "delimited", "xml"]},
        "pattern": {"type": "string"}, "dialect": {"type": "string"}, "delimiter": {"type": "string"},
        "quote": {"type": "string"}, "columns": STR_LIST, "strip": {"type": "boolean"},
        "nested": NESTED, "extract": EXTRACT, "scope": SCOPE, "mapping": {"type": "string"}, "match": MATCH,
        "labels": {"type": "object"}}},
    "mapping": {"type": "object", "required": ["class"], "additionalProperties": False, "properties": {
        "class": {"type": "string"}, "extends": {"type": "string"}, "profiles": STR_LIST,
        "constants": {"type": "object"}, "unmapped": {"enum": ["rest", "none"]}, "scope": SCOPE,
        "exclude": STR_LIST, "drop": STR_LIST,
        "switch": {"type": "array", "maxItems": 8, "items": {
            "type": "object", "required": ["when", "use"], "additionalProperties": False,
            "properties": {"when": WHEN, "use": {"type": "string", "pattern": "^mapping:"}}}}, "labels": {"type": "object"}, "match": MATCH,
        "fields": {"type": "array", "maxItems": 200, "items": {
            "type": "object", "required": ["to"], "additionalProperties": False, "properties": {
                "to": {"type": "string"}, "from": {"oneOf": [{"type": "string"}, STR_LIST]},
                "value": {}, "transform": TRANSFORMS, "when": WHEN, "join": {"type": "string", "maxLength": 8},
                "confidence": {"enum": ["high", "medium", "low"]}, "note": {"type": "string"}}}}}},
    "words": {"type": "object", "required": ["words"], "additionalProperties": False, "properties": {
        "words": {"type": "array", "items": {"type": "string", "pattern": "^[a-z][a-z_\\- ]*$"}, "maxItems": 400}}},
    "split": {"type": "object", "additionalProperties": False, "properties": {
        "fields": {"type": "array", "items": {"type": "string"}, "maxItems": 3},
        "presence": {"type": "array", "items": {"type": "string"}, "maxItems": 4}}},
    "longtail": {"type": "object", "required": ["fields"], "additionalProperties": False, "properties": {
        "summary": {"type": "string"},
        "fields": {"type": "object", "additionalProperties": {
            "type": "object", "additionalProperties": False,
            "properties": {"var": {"type": "integer", "minimum": 0}, "const": {"type": "string"},
                           "trim": {"type": "string", "maxLength": 8}}}}}},
}
LONGTAIL_FIELDS = ("timestamp", "host", "user", "src_ip", "dst_ip", "action", "outcome", "severity")


class RuleError(ValueError):
    pass


_VALIDATORS: dict = {}


def _patterns_in(kind: str, body: dict) -> list[tuple[str, str]]:
    out = []
    if kind == "framing":
        out += [("continuation", p) for p in body.get("continuation", [])]
    elif kind == "directive":
        out += [(k, body[k]) for k in ("pattern", "drop_pattern", "delimiter_pattern") if k in body]
    elif kind == "detect":
        if "pattern" in body["test"]:
            out.append(("test.pattern", body["test"]["pattern"]))
        for fld, pats in body.get("header_patterns", {}).items():
            out += [(f"header_patterns.{fld}", p) for p in pats]
    elif kind == "dialect":
        out += [(k, body[k]) for k in ("pair_pattern", "key_pattern") if k in body]
    elif kind == "mask":
        out += [(f"patterns.{p['name']}", p["pattern"]) for p in body["patterns"]]
    elif kind == "parser":
        if "pattern" in body:
            out.append(("pattern", body["pattern"]))
        out += [(f"extract.{e['field']}", e["pattern"]) for e in body.get("extract", [])]
    elif kind == "mapping":
        for f in body.get("fields", []):
            if "when" in f and "matches" in f["when"]:
                out.append((f"when.{f['to']}", f["when"]["matches"]))
        for sw in body.get("switch", []):
            if "matches" in sw["when"]:
                out.append(("switch.when", sw["when"]["matches"]))
    for sc in (body.get("scope") or {},):
        if sc.get("bucket") and sc["bucket"] != "*":
            out.append(("scope.bucket", sc["bucket"]))
    return out


def validate_rule(kind: str, body: Any) -> None:
    """Raise RuleError unless the rule is well formed. Pure function, no I/O."""
    if kind not in SCHEMAS:
        raise RuleError(f"unknown rule kind: {kind}")
    v = _VALIDATORS.get(kind)
    if v is None:       # compiling the validator once per kind makes loading a registry fast
        v = _VALIDATORS[kind] = jsonschema.Draft202012Validator(SCHEMAS[kind])
    exc = next(iter(v.iter_errors(body)), None)
    if exc is not None:
        where = "/".join(str(p) for p in exc.absolute_path)
        raise RuleError(f"schema: {where or '(root)'}: {exc.message[:300]}") from None
    for where, pat in _patterns_in(kind, body):
        err = rx.check(pat)
        if err:
            raise RuleError(f"{where}: {err}")
    if kind == "detect":
        t = body["test"]
        if body["type"] == "envelope":
            if t["kind"] == "json_wrap":
                if not t.get("fields"):
                    raise RuleError("json_wrap needs `fields`")
            elif t["kind"] != "regex" or "payload" not in rx.compile(t["pattern"]).groupindex:
                raise RuleError("an envelope needs a regex test with a named group `payload`")
        elif "format" not in body:
            raise RuleError("a format check needs `format`")
        need = {"regex": ["pattern"], "prefix": ["value"], "kv": ["dialect"], "delimited": ["delimiter"]}
        for k in need.get(t["kind"], []):
            if k not in t:
                raise RuleError(f"test kind {t['kind']} needs `{k}`")
    if kind == "dialect":
        if body["mode"] == "pair":
            gi = rx.compile(body.get("pair_pattern") or "x").groupindex
            if "k" not in gi or not ({"v", "q", "s"} & set(gi)):
                raise RuleError("pair dialect needs pair_pattern with groups k and v and/or q")
        elif "k" not in rx.compile(body.get("key_pattern") or "x").groupindex:
            raise RuleError("span dialect needs key_pattern with group k")
    if kind == "mask":
        for p in body["patterns"]:
            if p.get("group", 0) > rx.compile(p["pattern"]).groups:
                raise RuleError(f"patterns.{p['name']}: group {p['group']} does not exist")
            if rx.compile(p["pattern"]).search("") is not None:
                raise RuleError(f"patterns.{p['name']}: pattern matches the empty string")
    if kind == "parser":
        k = body["kind"]
        if k == "regex":
            if "pattern" not in body:
                raise RuleError("regex parser needs `pattern`")
            pat = body["pattern"]
            if not pat.startswith("^") or not pat.endswith("$"):
                raise RuleError("regex parser pattern must be anchored with ^ and $")
            names = list(rx.compile(pat).groupindex)
            bad = [n for n in names if n.startswith("_") or not n.replace("_", "").isalnum()]
            if bad:
                raise RuleError(f"bad group names: {bad}")
        if k == "kv" and "dialect" not in body:
            raise RuleError("kv parser needs `dialect`")
        if k == "delimited" and "delimiter" not in body:
            raise RuleError("delimited parser needs `delimiter`")
    if kind == "mapping":
        for f in body.get("fields", []):
            if ("from" in f) == ("value" in f):
                raise RuleError(f"field {f['to']}: give exactly one of `from` or `value`")
            steps = f.get("transform") or []
            for st in ([steps] if isinstance(steps, dict) else steps):
                err = transforms.check(st["fn"], st.get("args") or {})
                if err:
                    raise RuleError(f"field {f['to']}: {err}")
    if kind == "split" and not (body.get("fields") or body.get("presence")):
        raise RuleError("a split rule needs `fields` and/or `presence`")
    if kind == "longtail":
        bad = [k for k in body["fields"] if k not in LONGTAIL_FIELDS]
        if bad:
            raise RuleError(f"long-tail fields are limited to {LONGTAIL_FIELDS}; got {bad}")
        for k, v in body["fields"].items():
            if ("var" in v) == ("const" in v):
                raise RuleError(f"long-tail field {k}: give exactly one of var or const")


def kind_of(rule_id: str) -> str:
    return rule_id.split(":", 1)[0]


def save_rule(store: SqliteStore, rule_id: str, body: dict, meta: dict | None = None,
              status: str = "active") -> int:
    """Validate and store a new version. Returns the version number."""
    kind = kind_of(rule_id)
    validate_rule(kind, body)
    meta = dict(meta or {})
    meta.setdefault("created_by", "unknown")
    cur = store.active_rule(rule_id)
    if cur and cur["body"] == body and status == "active":
        return cur["version"]
    return store.insert_rule(rule_id, kind, body, meta, status)


def rollback(store: SqliteStore, rule_id: str, version: int | None = None) -> int:
    """Re-activate an earlier version (default: the one before the active one)."""
    versions = store.rule_versions(rule_id)
    if not versions:
        raise RuleError(f"no such rule: {rule_id}")
    active = next((v for v in versions if v["status"] == "active"), None)
    if version is None:
        older = [v for v in versions if active is None or v["version"] < active["version"]]
        older = [v for v in older if v["status"] in ("retired", "active")]
        if not older:
            raise RuleError("no earlier version to roll back to")
        version = older[-1]["version"]
    target = next((v for v in versions if v["version"] == version), None)
    if target is None:
        raise RuleError(f"{rule_id} has no version {version}")
    validate_rule(target["kind"], target["body"])
    store.set_rule_status(rule_id, version, "active")
    return version


def export_rules(store: SqliteStore, path: str, history: bool = False) -> int:
    rows = []
    statuses = ("active", "shadow", "retired", "rejected") if history else ("active",)
    for st in statuses:
        for r in store.rules(status=st):
            rows.append({"rule_id": r["rule_id"], "version": r["version"], "status": r["status"],
                         "body": r["body"], "meta": r["meta"]})
    rows.sort(key=lambda r: (r["rule_id"], r["version"]))
    with open(path, "w") as fh:
        json.dump({"format": "logparser-registry/1", "rules": rows}, fh, indent=1, ensure_ascii=False, sort_keys=True)
    return len(rows)


def import_rules(store: SqliteStore, path: str, created_by: str | None = None) -> tuple[int, int]:
    """Load rules from a JSON export. Returns (saved, unchanged). All-or-nothing."""
    with open(path) as fh:
        data = json.load(fh)
    rules = data["rules"] if isinstance(data, dict) else data
    for r in rules:  # validate everything before writing anything
        try:
            validate_rule(kind_of(r["rule_id"]), r["body"])
        except RuleError as exc:
            raise RuleError(f"{path}: {r['rule_id']}: {exc}") from None
    saved = same = 0
    store.begin()
    try:
        for r in rules:
            if r.get("status", "active") != "active":
                continue
            meta = dict(r.get("meta") or {})
            if created_by:
                meta.setdefault("created_by", created_by)
            cur = store.active_rule(r["rule_id"])
            if cur and cur["body"] == r["body"]:
                same += 1
                continue
            store.insert_rule(r["rule_id"], kind_of(r["rule_id"]), r["body"], meta, "active")
            saved += 1
        store.commit()
    except Exception:
        store.rollback()
        raise
    return saved, same


def load_dir(store: SqliteStore, directory: str) -> dict:
    out = {}
    for name in sorted(os.listdir(directory)):
        if name.endswith(".json"):
            out[name] = import_rules(store, os.path.join(directory, name))
    return out


# ---------------------------------------------------------------- compiled snapshot
class Snapshot:
    """Active rules, compiled once. The engine swaps in a new snapshot when the
    registry generation changes (hot reload)."""

    def __init__(self, store: SqliteStore):
        self.generation = int(store.get_state("registry_generation", 0))
        by_kind: dict[str, list[dict]] = {}
        self.by_id: dict[str, dict] = {}
        for r in store.rules():
            try:
                validate_rule(r["kind"], r["body"])
            except RuleError:
                continue  # a rule that no longer validates is ignored, never executed
            by_kind.setdefault(r["kind"], []).append(r)
            self.by_id[r["rule_id"]] = r
        self.shadow = {}
        for r in store.rules(status="shadow"):
            try:
                validate_rule(r["kind"], r["body"])
                self.shadow[r["rule_id"]] = r
            except RuleError:
                pass
        fr = by_kind.get("framing", [])
        self.framing = fr[0]["body"] if fr else {}
        self.directives = [r["body"] for r in by_kind.get("directive", [])]
        self.detect = sorted((r["body"] for r in by_kind.get("detect", [])), key=lambda b: (b["order"], b["name"]))
        self.dialects = {r["rule_id"].split(":", 1)[1]: r["body"] for r in by_kind.get("dialect", [])}
        # outcome and action words that are never masked and never merged away
        self.protected = frozenset(w for r in by_kind.get("words", []) for w in r["body"]["words"])
        self.masks = sorted(by_kind.get("mask", []), key=lambda r: (-r["body"].get("priority", 0), r["rule_id"]))
        self.signs = sorted(by_kind.get("sign", []), key=lambda r: (-r["body"].get("priority", 0), r["rule_id"]))
        self.seed_parsers = [r for r in by_kind.get("parser", []) if r["body"].get("scope")]
        self.scoped_mappings = [r for r in by_kind.get("mapping", []) if r["body"].get("scope")]
        self._mask_cache: dict[tuple, list] = {}
        self._sign_cache: dict[tuple, dict] = {}

    @staticmethod
    def _in_scope(scope: dict, bucket: str, stream: str | None) -> bool:
        if scope.get("stream") and scope["stream"] != stream:
            return False
        b = scope.get("bucket", "*")
        return b == "*" or rx.compile(b).search(bucket) is not None

    def mask_patterns(self, bucket: str, stream: str | None) -> list[dict]:
        key = (bucket, stream)
        if key not in self._mask_cache:
            pats: list[dict] = []
            for r in self.masks:  # highest priority first
                if self._in_scope(r["body"]["scope"], bucket, stream):
                    pats += r["body"]["patterns"]
                    if r["body"].get("mode", "extend") == "replace":
                        break
            self._mask_cache[key] = [(p["name"], rx.compile(p["pattern"]), p["placeholder"], p.get("group", 0))
                                     for p in pats]
        return self._mask_cache[key]

    def sign_rule(self, bucket: str, stream: str | None) -> dict:
        key = (bucket, stream)
        if key not in self._sign_cache:
            body = {"keys": "auto", "discriminators": [], "depth": 1}
            for r in self.signs:
                if self._in_scope(r["body"]["scope"], bucket, stream):
                    body = {**body, **{k: v for k, v in r["body"].items() if k not in ("scope", "priority")}}
                    break
            self._sign_cache[key] = body
        return self._sign_cache[key]

    def rule(self, rule_id: str | None) -> dict | None:
        return self.by_id.get(rule_id) if rule_id else None
