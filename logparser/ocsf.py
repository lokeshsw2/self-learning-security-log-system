"""OCSF schema access, the mapper that runs mapping rules, and the validator.

The schema is the compiled export from schema.ocsf.io for one pinned version.
The mapper is deterministic: it only moves, casts and looks up values as the
mapping rule says. The validator checks structure, types, enums, required
attributes and constraints. It cannot check that the meaning is right.
"""
from __future__ import annotations

import json
import os
import time

from . import rx, transforms

DEFAULT_SCHEMA = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                              "data", "raw", "ocsf-schema", "schema-1.10.0.json")
_INDEX = rx.compile(r"^(.*)\[(\d+)\]$")
_STR_BASE = {"string_t"}
_INT_BASE = {"integer_t", "long_t"}


class Schema:
    def __init__(self, path: str | None = None):
        with open(path or DEFAULT_SCHEMA) as fh:
            raw = json.load(fh)
        self.version = raw["version"]
        self.types = raw["types"]
        self.objects = raw["objects"]
        self.classes = dict(raw["classes"])
        self.classes.setdefault("base_event", raw["base_event"])
        self.by_uid = {c["uid"]: n for n, c in self.classes.items()}
        self._rx_cache: dict = {}

    # ------------------------------------------------------------ lookup
    def cls(self, name_or_uid) -> dict | None:
        if isinstance(name_or_uid, int) or str(name_or_uid).isdigit():
            name_or_uid = self.by_uid.get(int(name_or_uid))
        return self.classes.get(name_or_uid) if name_or_uid else None

    def base_type(self, t: str) -> str:
        seen = 0
        while t in self.types and "type" in self.types[t] and seen < 5:
            t = self.types[t]["type"]
            seen += 1
        return t

    def attr_at(self, class_name: str, path: str) -> dict | None:
        """Attribute definition for a dotted path inside a class, or None."""
        attrs = self.classes[class_name]["attributes"]
        parts = path.split(".")
        for i, part in enumerate(parts):
            m = _INDEX.match(part)
            if m:
                part = m.group(1)
            a = attrs.get(part)
            if a is None:
                return None
            if i == len(parts) - 1:
                return a
            if a.get("type") != "object_t":
                return None
            ot = a.get("object_type")
            if ot == "object" or ot not in self.objects:
                return {"type": "json_t"}
            attrs = self.objects[ot]["attributes"]
        return None

    def describe_attr(self, name: str, a: dict, enum_limit: int = 40) -> dict:
        d = {"name": name, "type": a.get("type"), "requirement": a.get("requirement")}
        if a.get("object_type"):
            d["object"] = a["object_type"]
        if a.get("is_array"):
            d["is_array"] = True
        if a.get("profile"):
            d["needs_profile"] = a["profile"]
        if a.get("enum"):
            items = sorted(a["enum"].items(), key=lambda kv: int(kv[0]) if kv[0].lstrip("-").isdigit() else 0)
            d["enum"] = {k: v.get("caption") for k, v in items[:enum_limit]}
        if a.get("@deprecated"):
            d["deprecated"] = True
        desc = (a.get("description") or "").replace("<code>", "`").replace("</code>", "`")
        d["description"] = desc[:220]
        return d

    def describe_class(self, name_or_uid, optional: bool = True) -> dict | None:
        c = self.cls(name_or_uid)
        if not c:
            return None
        attrs = []
        for n, a in sorted(c["attributes"].items(), key=lambda kv: ({"required": 0, "recommended": 1}.get(
                kv[1].get("requirement"), 2), kv[0])):
            if not optional and a.get("requirement") == "optional":
                continue
            attrs.append(self.describe_attr(n, a))
        return {"name": c["name"], "uid": c["uid"], "caption": c.get("caption"), "category": c.get("category"),
                "category_uid": c.get("category_uid"), "description": (c.get("description") or "")[:500],
                "constraints": c.get("constraints"), "profiles": c.get("profiles"), "attributes": attrs}

    def describe_object(self, name: str) -> dict | None:
        o = self.objects.get(name)
        if not o:
            return None
        attrs = [self.describe_attr(n, a, 25) for n, a in sorted(
            o["attributes"].items(), key=lambda kv: ({"required": 0, "recommended": 1}.get(
                kv[1].get("requirement"), 2), kv[0]))]
        return {"name": name, "caption": o.get("caption"), "description": (o.get("description") or "")[:400],
                "constraints": o.get("constraints"), "attributes": attrs}

    def search(self, query: str, limit: int = 8) -> dict:
        words = [w for w in rx.compile(r"[A-Za-z0-9]+").findall(query.lower()) if len(w) > 1]

        def score(name, caption, desc, attrs):
            s = 0.0
            hay_name = f"{name} {caption}".lower()
            desc = (desc or "").lower()
            for w in words:
                if w in hay_name:
                    s += 5
                if w in desc:
                    s += 1.5
                s += 0.5 * sum(1 for a in attrs if w in a)
            return s
        classes = sorted(((score(n, c.get("caption", ""), c.get("description"), c["attributes"]), n)
                          for n, c in self.classes.items()), reverse=True)
        objects = sorted(((score(n, o.get("caption", ""), o.get("description"), o["attributes"]), n)
                          for n, o in self.objects.items()), reverse=True)
        return {
            "classes": [{"name": n, "uid": self.classes[n]["uid"], "caption": self.classes[n].get("caption"),
                         "description": (self.classes[n].get("description") or "")[:200]}
                        for s, n in classes[:limit] if s > 0],
            "objects": [{"name": n, "caption": self.objects[n].get("caption"),
                         "description": (self.objects[n].get("description") or "")[:160]}
                        for s, n in objects[:limit] if s > 0],
        }

    # ------------------------------------------------------------ validation
    def _check_scalar(self, t: str, v, path: str, errors: list) -> None:
        base = self.base_type(t)
        td = self.types.get(t, {})
        if base in _STR_BASE:
            if not isinstance(v, str):
                errors.append(f"{path}: expected string ({t}), got {type(v).__name__}")
                return
            if td.get("max_len") and len(v) > td["max_len"]:
                errors.append(f"{path}: longer than {td['max_len']} characters for {t}")
            if td.get("regex"):
                pat = self._rx_cache.get(t)
                if pat is None:
                    try:
                        pat = rx.compile(td["regex"])
                    except rx.PatternError:
                        pat = False
                    self._rx_cache[t] = pat
                if pat and not pat.search(v):
                    errors.append(f"{path}: `{v[:60]}` is not a valid {t}")
        elif base in _INT_BASE:
            if isinstance(v, bool) or not isinstance(v, int):
                errors.append(f"{path}: expected integer ({t}), got {type(v).__name__}")
                return
            if td.get("range") and not (td["range"][0] <= v <= td["range"][1]):
                errors.append(f"{path}: {v} is outside {td['range']} for {t}")
        elif base == "float_t":
            if isinstance(v, bool) or not isinstance(v, (int, float)):
                errors.append(f"{path}: expected number, got {type(v).__name__}")
        elif base == "boolean_t":
            if not isinstance(v, bool):
                errors.append(f"{path}: expected boolean, got {type(v).__name__}")

    def _walk(self, obj: dict, attrs: dict, constraints: dict | None, path: str, profiles: set,
              errors: list, warnings: list, depth: int = 0) -> None:
        if depth > 12:
            errors.append(f"{path}: nested too deep")
            return
        for k, v in obj.items():
            p = f"{path}.{k}" if path else k
            a = attrs.get(k)
            if a is None:
                errors.append(f"{p}: not an attribute here")
                continue
            if a.get("profile") and a["profile"] not in profiles:
                errors.append(f"{p}: belongs to profile `{a['profile']}`, which the mapping does not declare")
                continue
            if a.get("@deprecated"):
                warnings.append(f"{p}: deprecated")
            if v is None:
                errors.append(f"{p}: null value")
                continue
            items = v if a.get("is_array") else [v]
            if a.get("is_array") and not isinstance(v, list):
                errors.append(f"{p}: expected an array")
                continue
            if not a.get("is_array") and isinstance(v, list):
                errors.append(f"{p}: expected a single value, got an array")
                continue
            for i, item in enumerate(items):
                ip = f"{p}[{i}]" if a.get("is_array") else p
                if a.get("type") == "object_t":
                    if not isinstance(item, dict):
                        errors.append(f"{ip}: expected object `{a.get('object_type')}`")
                        continue
                    ot = a.get("object_type")
                    if ot == "object" or ot not in self.objects:
                        continue
                    o = self.objects[ot]
                    self._walk(item, o["attributes"], o.get("constraints"), ip, profiles, errors, warnings, depth + 1)
                elif a.get("type") == "json_t":
                    continue
                else:
                    self._check_scalar(a["type"], item, ip, errors)
                    if a.get("enum") and str(item) not in a["enum"] and not isinstance(item, bool):
                        errors.append(f"{ip}: {item!r} is not in the enum {sorted(a['enum'])[:25]}")
        for k, a in attrs.items():
            if a.get("requirement") == "required" and k not in obj:
                if a.get("profile") and a["profile"] not in profiles:
                    continue
                errors.append(f"{(path + '.') if path else ''}{k}: required attribute is missing")
            elif a.get("requirement") == "recommended" and k not in obj and depth == 0 and not a.get("profile"):
                warnings.append(f"{k}: recommended attribute is missing")
        for kind, names in (constraints or {}).items():
            present = [n for n in names if n in obj]
            if kind == "at_least_one" and not present:
                errors.append(f"{path or 'event'}: needs at least one of {names}")
            if kind == "just_one" and len(present) != 1:
                errors.append(f"{path or 'event'}: needs exactly one of {names}")

    def validate(self, event: dict) -> tuple[list, list]:
        """Return (errors, warnings). An empty error list means schema-valid."""
        errors: list = []
        warnings: list = []
        if not isinstance(event, dict):
            return ["event is not an object"], []
        c = self.cls(event.get("class_uid")) if isinstance(event.get("class_uid"), int) else None
        if c is None:
            return [f"class_uid {event.get('class_uid')!r} is not an OCSF {self.version} class"], []
        md = event.get("metadata") if isinstance(event.get("metadata"), dict) else {}
        profiles = set(md.get("profiles") or [])
        bad = [p for p in profiles if p not in (c.get("profiles") or [])]
        if bad:
            errors.append(f"metadata.profiles: {bad} not available on class {c['name']}")
        self._walk(event, c["attributes"], c.get("constraints"), "", profiles, errors, warnings)
        if event.get("category_uid") != c.get("category_uid"):
            errors.append(f"category_uid: must be {c.get('category_uid')} for class {c['name']}")
        act = event.get("activity_id")
        if isinstance(act, int) and event.get("type_uid") != c["uid"] * 100 + act:
            errors.append(f"type_uid: must be class_uid*100 + activity_id = {c['uid'] * 100 + act}")
        if md.get("version") and md["version"] != self.version:
            warnings.append(f"metadata.version {md['version']} differs from schema {self.version}")
        return errors, warnings


# ---------------------------------------------------------------- mapper
def _set_path(event: dict, path: str, value) -> None:
    cur = event
    parts = path.split(".")
    for i, part in enumerate(parts):
        m = _INDEX.match(part)
        last = i == len(parts) - 1
        if m:
            name, idx = m.group(1), int(m.group(2))
            lst = cur.setdefault(name, [])
            if not isinstance(lst, list):
                raise transforms.TransformError(f"{path}: {name} is not an array")
            while len(lst) <= idx:
                lst.append({} if not last else None)
            if last:
                lst[idx] = value
            else:
                if not isinstance(lst[idx], dict):
                    lst[idx] = {}
                cur = lst[idx]
        elif last:
            cur[part] = value
        else:
            nxt = cur.setdefault(part, {})
            if not isinstance(nxt, dict):
                raise transforms.TransformError(f"{path}: {part} is not an object")
            cur = nxt


def _get_path(event: dict, path: str):
    cur = event
    for part in path.split("."):
        m = _INDEX.match(part)
        if m:
            cur = cur.get(m.group(1)) if isinstance(cur, dict) else None
            if not isinstance(cur, list) or len(cur) <= int(m.group(2)):
                return None
            cur = cur[int(m.group(2))]
        else:
            if not isinstance(cur, dict) or part not in cur:
                return None
            cur = cur[part]
    return cur


def _when(cond: dict, fields: dict) -> bool:
    v = fields.get(cond["field"])
    if "exists" in cond:
        return (v is not None and v != "") == cond["exists"]
    if v is None:
        return False
    s = str(v)
    if "equals" in cond:
        return s == cond["equals"]
    if "in" in cond:
        return s in cond["in"]
    if "matches" in cond:
        return rx.compile(cond["matches"]).search(s) is not None
    return True


def _coerce(schema: Schema, attr: dict | None, value):
    """Cast to the type the schema asks for. Deterministic, never guesses."""
    if attr is None or value is None:
        return value
    t = attr.get("type")
    if t in ("object_t", "json_t"):
        return value
    base = schema.base_type(t)

    def one(v):
        if base in _INT_BASE and not isinstance(v, bool):
            if isinstance(v, int):
                return v
            if isinstance(v, float) and v == int(v):
                return int(v)
            m = transforms._INT.match(str(v))
            if m:
                return int(m.group(1))
            raise transforms.TransformError(f"`{str(v)[:40]}` is not an integer")
        if base == "float_t" and not isinstance(v, bool):
            return v if isinstance(v, (int, float)) else transforms.to_float(v, {}, {})
        if base == "boolean_t":
            return v if isinstance(v, bool) else transforms.to_bool(v, {}, {})
        if base in _STR_BASE:
            if isinstance(v, bool):
                return "true" if v else "false"
            return v if isinstance(v, str) else str(v)
        return v
    if attr.get("is_array"):
        vals = value if isinstance(value, list) else [value]
        return [one(v) for v in vals]
    if isinstance(value, list):
        raise transforms.TransformError("got a list for a single-valued attribute")
    return one(value)


def resolve_mapping(body: dict, get_rule, depth: int = 0) -> dict:
    """Merge a mapping with the chain it extends (base first, overrides last)."""
    chain, seen, cur = [body], set(), body
    while cur.get("extends") and cur["extends"] not in seen and len(chain) < 5:
        seen.add(cur["extends"])
        base = get_rule(cur["extends"])
        if not base:
            break
        cur = base["body"]
        chain.append(cur)
    merged = {"class": body["class"], "constants": {}, "fields": [], "profiles": [], "unmapped": "rest", "drop": []}
    exclude = set(body.get("exclude") or [])
    for b in reversed(chain):
        merged["constants"].update(b.get("constants") or {})
        tos = {f["to"] for f in b.get("fields") or [] if "when" not in f}
        merged["fields"] = [f for f in merged["fields"] if f["to"] not in tos] + list(b.get("fields") or [])
        for p in b.get("profiles") or []:
            if p not in merged["profiles"]:
                merged["profiles"].append(p)
        if "unmapped" in b:
            merged["unmapped"] = b["unmapped"]
        merged["drop"] += [d for d in b.get("drop") or [] if d not in merged["drop"]]
    merged["switch"] = []
    if depth == 0:
        for sw in body.get("switch") or []:
            target = get_rule(sw["use"])
            if target:
                merged["switch"].append((sw["when"], resolve_mapping(target["body"], get_rule, 1), sw["use"]))
    merged["fields"] = [f for f in merged["fields"] if f["to"] not in exclude]
    for k in list(merged["constants"]):
        if k in exclude:
            del merged["constants"][k]
    return merged


def map_event(schema: Schema, mapping: dict, fields: dict, ctx: dict) -> tuple[dict, list, set]:
    """Run a resolved mapping. Returns (event, problems, flags)."""
    problems: list = []
    for cond, sub, _name in mapping.get("switch") or ():     # per-line class choice
        if _when(cond, fields):
            mapping = sub
            break
    c = schema.cls(mapping["class"])
    if c is None:
        return {}, [f"unknown OCSF class `{mapping['class']}`"], set()
    cname = c["name"]
    event: dict = {}
    used: set = set()
    ctx = dict(ctx)
    ctx["flags"] = set()
    for path, value in (mapping.get("constants") or {}).items():
        try:
            _set_path(event, path, _coerce(schema, schema.attr_at(cname, path), value))
        except transforms.TransformError as exc:
            problems.append(f"{path}: {exc}")
    for f in mapping.get("fields") or []:
        if "when" in f and not _when(f["when"], fields):
            continue
        if "value" in f:
            value = f["value"]
        else:
            value = None
            srcs = f["from"] if isinstance(f["from"], list) else [f["from"]]
            if "join" in f:
                # every listed field must be present; they are joined in order
                parts = [fields.get(s) for s in srcs]
                if any(p is None or p == "" for p in parts):
                    continue
                value = f["join"].join(str(p) for p in parts)
                used.update(srcs)
            else:
                for s in srcs:
                    v = fields.get(s)
                    if v is not None and v != "":
                        value = v
                        used.add(s)
                        break
            if value is None:
                continue
        try:
            value = transforms.apply(f.get("transform"), value, ctx)
            if value is None:
                continue
            value = _coerce(schema, schema.attr_at(cname, f["to"]), value)
            _set_path(event, f["to"], value)
        except transforms.TransformError as exc:
            problems.append(f"{f['to']}: {exc}")
        except (IndexError, KeyError, TypeError, ValueError, OverflowError) as exc:
            problems.append(f"{f['to']}: transform failed ({type(exc).__name__}: {exc})")
    event["class_uid"] = c["uid"]
    event["category_uid"] = c.get("category_uid", 0)
    if not isinstance(event.get("activity_id"), int) or isinstance(event.get("activity_id"), bool):
        event["activity_id"] = 0
    event["type_uid"] = c["uid"] * 100 + event["activity_id"]
    if not isinstance(event.get("severity_id"), int):
        event["severity_id"] = 0
    if "time" not in event:
        ts = fields.get("@timestamp")
        if ts:
            try:
                event["time"] = transforms.parse_timestamp(ts, {}, ctx)
                used.add("@timestamp")
            except transforms.TransformError:
                pass
        if "time" not in event:
            event["time"] = int(ctx.get("now", time.time()) * 1000)
            ctx["flags"].add("time_from_ingest")
    md = event.setdefault("metadata", {})
    md["version"] = schema.version
    prod = md.setdefault("product", {})
    labels = ctx.get("labels") or {}
    if "name" not in prod and "uid" not in prod:
        prod["name"] = labels.get("product") or "unknown"
    if "vendor_name" not in prod and labels.get("vendor"):
        prod["vendor_name"] = labels["vendor"]
    if mapping.get("profiles"):
        md["profiles"] = list(mapping["profiles"])
    attrs = c["attributes"]
    for k in list(event):
        a = attrs.get(k)
        if a and a.get("enum") and a.get("sibling") and a["sibling"] not in event and a["sibling"] in attrs:
            cap = a["enum"].get(str(event[k]), {}).get("caption")
            if cap and not isinstance(event[k], (list, dict)):
                event[a["sibling"]] = cap
    if mapping.get("unmapped", "rest") == "rest":
        drop = set(mapping.get("drop") or ())
        rest = {k: (v if isinstance(v, (str, int, float, bool)) else str(v))
                for k, v in fields.items() if k not in used and k not in drop and v != "" and v is not None}
        if rest:
            event["unmapped"] = rest
    if ctx.get("raw_data") is not None:
        event["raw_data"] = ctx["raw_data"]
    return event, problems, ctx["flags"]
