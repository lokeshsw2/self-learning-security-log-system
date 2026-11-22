"""Variant B: agents write Logstash filters directly, as structured steps that code renders to .conf.

A rule (`lsfilter:<group id>`) is data:

  {"class": "authentication",
   "extract": [{"grok": {"field": "payload",
                         "patterns": ["Failed password for %{USERNAME:user} from %{IP:src_ip} port %{INT:src_port}"]}}],
   "time":    {"field": "@timestamp", "formats": ["ISO8601"]},
   "map":     [{"to": "user.name", "from": "user"},
               {"to": "src_endpoint.ip", "from": "src_ip"},
               {"to": "src_endpoint.port", "from": "src_port", "convert": "integer"},
               {"to": "status_id", "value": 2},
               {"to": "activity_id", "from": "action", "translate": {"login": 1, "logout": 2}, "fallback": 99}]}

  extract  grok | dissect | kv | json | xml | csv on the payload or on a field an earlier step made; every
           field they make lands in the parsed fields ([@metadata][s][f]), next to the header fields
           (@timestamp, @host, @app, ...) the router found
  time     a Logstash `date` match on one field (Joda formats or ISO8601 / UNIX / UNIX_MS)
  map      OCSF attribute paths of the declared class: copied from a field, a constant, or translated
           through an inline dictionary; `convert` integer | float | string
  when     any step may carry {"field": f, "exists": true} | {"field": f, "equals": v} | {"field": f, "matches": re}

Code renders the steps between fixed harness code: the route condition, LP.finish (header merge) before,
LP.fin (class ids, type_uid, captions, metadata, unmapped) after. Agents cannot write ruby, exec, file or
network plugins, or config syntax: only these steps, checked here before anything is rendered.
"""
from __future__ import annotations

import json
import re

from .logstash import rb

PLUGINS = {"grok", "dissect", "kv", "json", "xml", "csv"}
OPTIONS = {
    "grok": {"field", "patterns", "pattern_definitions", "when"},
    "dissect": {"field", "mapping", "when"},
    "kv": {"field", "field_split", "value_split", "include_keys", "trim_value", "trim_key", "prefix", "when"},
    "json": {"field", "when"},
    "xml": {"field", "xpath", "when"},
    "csv": {"field", "columns", "separator", "quote_char", "when"},
}
NAME = re.compile(r"^@?[A-Za-z_][A-Za-z0-9_.\-]{0,63}$")          # a parsed field name, header fields start with @
OCSF_PATH = re.compile(r"^[a-z_][a-z0-9_]*(\.[a-z_][a-z0-9_]*){0,6}$")
CONVERT = {"integer", "float", "string"}
MAX_STEPS = 12
MAP_MARK = "#--map--"
F = "[@metadata][s][f]"


class FilterError(ValueError):
    pass


def ref(name: str) -> str:
    """Logstash field reference for a parsed field (or `payload`). Dots nest: `actor.user` is the `user`
    key inside `actor`, as json and xml produce them."""
    if name == "payload":
        return "[@metadata][s][payload]"
    if not NAME.match(name) or ".." in name or name.endswith("."):
        raise FilterError(f"field name {name!r}: letters, digits, _ . - (header fields start with @)")
    return F + "".join(f"[{p}]" for p in name.split("."))


def lit(s) -> str:
    """A Logstash string literal. Logstash processes no escapes by default, so a value may hold one kind of
    quote but not both (use \\x22 / \\x27 inside regular expressions)."""
    s = str(s)
    if "${" in s:
        raise FilterError(f"a value may not contain '${{' (Logstash substitutes environment variables): {s[:60]!r}")
    if any(c in s for c in "\n\r\x00"):
        raise FilterError(f"a value may not contain line breaks or NUL: {s[:60]!r}")
    if s.endswith("\\"):
        raise FilterError(f"a value may not end with a backslash: {s[:60]!r}")
    if '"' not in s:
        return f'"{s}"'
    if "'" not in s:
        return f"'{s}'"
    raise FilterError(f"a value holds both quote kinds: {s[:60]!r}; use \\x22 or \\x27 in patterns")


def _cond(w: dict | None) -> str | None:
    if not w:
        return None
    if set(w) - {"field", "exists", "equals", "matches"} or "field" not in w:
        raise FilterError("`when` takes field and one of exists / equals / matches")
    r = ref(w["field"])
    if w.get("exists"):
        return r
    if "equals" in w:
        return f"{r} == {lit(w['equals'])}"
    if "matches" in w:
        m = str(w["matches"])
        if "/" in m or m.endswith("\\") or "${" in m or any(c in m for c in "\n\r\x00"):
            raise FilterError("`matches`: no /, line break, ${ or trailing backslash (use \\x2f for /)")
        return f"{r} =~ /{w['matches']}/"
    raise FilterError("`when` needs exists, equals or matches")


def validate(body: dict, schema) -> None:
    """Static checks before rendering: shape, plugins, options, names, OCSF paths of the class."""
    if not isinstance(body, dict) or set(body) - {"class", "profiles", "extract", "time", "map", "labels"}:
        raise FilterError("a rule has class, profiles, extract, time, map (and labels)")
    prof = body.get("profiles") or []
    if not isinstance(prof, list) or not all(isinstance(p, str) and re.fullmatch(r"[a-z_]{1,40}", p) for p in prof):
        raise FilterError("profiles: a list of OCSF profile names, e.g. [\"security_control\"]")
    cls = schema.classes.get(body.get("class", ""))
    if cls is None:
        raise FilterError(f"unknown OCSF class {body.get('class')!r}")
    steps = body.get("extract") or []
    if not isinstance(steps, list) or not 1 <= len(steps) <= MAX_STEPS:
        raise FilterError(f"extract: a list of 1 to {MAX_STEPS} steps")
    if isinstance(steps[0], dict) and isinstance(next(iter(steps[0].values()), None), dict) \
            and next(iter(steps[0].values())).get("when"):
        raise FilterError("the first extract step runs on every line: no `when` on it")
    for i, st in enumerate(steps):
        if isinstance(st, dict) and len(st) == 1 and next(iter(st)) in ("json", "xml") and i > 0:
            raise FilterError("json and xml replace the parsed fields: put them first")
        if not isinstance(st, dict) or len(st) != 1 or next(iter(st)) not in PLUGINS:
            raise FilterError(f"extract step {st!r}: one of {sorted(PLUGINS)}")
        (plugin, opts), = st.items()
        if not isinstance(opts, dict):
            raise FilterError(f"{plugin}: options are an object")
        for k in ("patterns", "include_keys", "columns"):
            if k in opts and not (isinstance(opts[k], list) and all(isinstance(x, str) for x in opts[k])):
                raise FilterError(f"{plugin}.{k}: a list of strings")
        for k in ("pattern_definitions", "xpath"):
            if k in opts and not (isinstance(opts[k], dict) and all(isinstance(x, str) for x in opts[k].values())):
                raise FilterError(f"{plugin}.{k}: an object of strings")
        bad = set(opts) - OPTIONS[plugin]
        if bad:
            raise FilterError(f"{plugin}: options {sorted(bad)} are not allowed; allowed: {sorted(OPTIONS[plugin])}")
        ref(opts.get("field", "payload"))
        _cond(opts.get("when"))
        if plugin == "grok" and not opts.get("patterns"):
            raise FilterError("grok needs patterns")
        if plugin == "dissect":
            if not isinstance(opts.get("mapping"), str) or not opts["mapping"]:
                raise FilterError("dissect needs mapping (a string)")
            for k in re.findall(r"%\{([^}]*)\}", opts["mapping"]):
                if k and not NAME.match(k):
                    raise FilterError(f"dissect key %{{{k}}}: plain field names only (no modifiers, brackets "
                                      f"or ->); use %{{}} to skip text")
        if plugin == "csv" and not opts.get("columns"):
            raise FilterError("csv needs columns")
    t = body.get("time")
    if t is not None:
        if not isinstance(t, dict) or set(t) - {"field", "formats", "timezone"} or not t.get("formats"):
            raise FilterError("time: {field, formats, timezone?}")
        ref(t["field"])
    maps = body.get("map") or []
    if not isinstance(maps, list) or not maps:
        raise FilterError("map: at least one OCSF attribute")
    for m in maps:
        if not isinstance(m, dict) or set(m) - {"to", "from", "value", "convert", "translate", "fallback", "when"}:
            raise FilterError(f"map entry {m!r}: to, from | value, convert, translate, fallback, when")
        to = m.get("to", "")
        if not OCSF_PATH.match(to) or to in ("time", "class_uid", "category_uid", "type_uid"):
            raise FilterError(f"map.to {to!r}: an OCSF path of the class (time, class, category and type are set by code)")
        if schema.attr_at(body["class"], to) is None:
            raise FilterError(f"map.to {to!r} is not an attribute of {body['class']}")
        if ("from" in m) == ("value" in m):
            raise FilterError(f"map.to {to!r}: give one of from or value")
        if "from" in m:
            ref(m["from"])
        if m.get("convert") is not None and m["convert"] not in CONVERT:
            raise FilterError(f"map.to {to!r}: convert is one of {sorted(CONVERT)}")
        if "translate" in m and (not isinstance(m["translate"], dict) or "from" not in m or not all(
                isinstance(v, (str, int, float)) and not isinstance(v, bool) for v in m["translate"].values())):
            raise FilterError(f"map.to {to!r}: translate is an inline dictionary on a `from` field")
        _cond(m.get("when"))


def _wrap(cond: str | None, text: str) -> str:
    if not cond:
        return text
    inner = "\n".join("  " + l for l in text.splitlines())
    return f"if {cond} {{\n{inner}\n}}"


def _hash(d: dict) -> str:
    return "{ " + " ".join(f"{lit(k)} => {lit(v)}" for k, v in d.items()) + " }"


def render_steps(body: dict, default_tz: str | None = None) -> str:
    """The agent's part of a group's filter, as Logstash config (between LP.finish and LP.fin)."""
    out = []
    for st in body.get("extract") or []:
        (plugin, o), = st.items()
        src = ref(o.get("field", "payload"))
        if plugin == "grok":
            pats = "[" + ", ".join(lit(p) for p in o["patterns"]) + "]"
            extra = f"\n  pattern_definitions => {_hash(o['pattern_definitions'])}" if o.get("pattern_definitions") else ""
            text = (f"grok {{\n  match => {{ {lit(src)} => {pats} }}\n  target => {lit(F)}{extra}\n  timeout_millis => 1000\n"
                    f"  tag_on_failure => [\"_lp_grokfail\"]\n}}")
        elif plugin == "dissect":
            # dissect writes plain names; they become parsed fields through the %{[...]} form
            mapping = re.sub(r"%\{([^}?&+*/]+)\}", lambda mm: "%{" + ref(mm.group(1).strip()) + "}", o["mapping"])
            text = (f"dissect {{\n  mapping => {{ {lit(src)} => {lit(mapping)} }}\n"
                    f"  tag_on_failure => [\"_lp_dissectfail\"]\n}}")
        elif plugin == "kv":
            opts = "".join(f"\n  {k} => {lit(o[k])}" for k in ("field_split", "value_split", "trim_value", "trim_key", "prefix") if k in o)
            if o.get("include_keys"):
                opts += "\n  include_keys => [" + ", ".join(lit(k) for k in o["include_keys"]) + "]"
            text = f"kv {{\n  source => {lit(src)}\n  target => {lit(F)}{opts}\n  tag_on_failure => [\"_lp_kvfail\"]\n}}"
        elif plugin == "json":
            text = f"json {{\n  source => {lit(src)}\n  target => {lit(F)}\n  tag_on_failure => [\"_lp_jsonfail\"]\n}}"
        elif plugin == "xml":
            xp = ""
            if o.get("xpath"):
                xp = "\n  xpath => " + _hash({k: ref(v) for k, v in o["xpath"].items()})
            text = (f"xml {{\n  source => {lit(src)}\n  target => {lit(F + '[xml]')}\n  store_xml => {'false' if xp else 'true'}"
                    f"\n  force_array => false{xp}\n}}")
        else:   # csv
            cols = "[" + ", ".join(lit(c) for c in o["columns"]) + "]"
            sep = f"\n  separator => {lit(o['separator'])}" if "separator" in o else ""
            q = f"\n  quote_char => {lit(o['quote_char'])}" if "quote_char" in o else ""
            text = f"csv {{\n  source => {lit(src)}\n  target => {lit(F)}\n  columns => {cols}{sep}{q}\n}}"   # csv tags _csvparsefailure itself
        if src != "[@metadata][s][payload]":
            text = f"if ![{src[1:-1]}] {{\n  mutate {{ add_tag => [\"_lp_nofield\"] }}\n}} else {{\n" + \
                   "\n".join("  " + l for l in text.splitlines()) + "\n}"
        out.append(_wrap(_cond(o.get("when")), text))
    # an extraction that made no field (steps skipped, nothing matched) fails too
    out.append("ruby { code => 'f = event.get(\"[@metadata][s][f]\"); event.tag(\"_lp_noextract\") if !f.is_a?(Hash) || f.empty?' }")
    out.append(MAP_MARK)
    t = body.get("time")
    if t:
        zone = t.get("timezone") or default_tz      # a time without a zone is in the deployment's zone
        tz = f"\n  timezone => {lit(zone)}" if zone else ""
        fm = ", ".join(lit(f) for f in t["formats"])
        out.append(f"if {ref(t['field'])} {{\n  date {{\n    match => [{lit(ref(t['field']))}, {fm}]\n"
                   f"    target => \"[@metadata][s][t]\"{tz}\n    tag_on_failure => [\"_lp_datefail\"]\n  }}\n}}")
    for m in body.get("map") or []:
        dst = "[ocsf]" + "".join(f"[{p}]" for p in m["to"].split("."))
        if "value" in m:
            text = f"mutate {{ add_field => {{ {lit(dst)} => {lit(m['value'])} }} }}"
        elif "translate" in m:
            fb = f"\n  fallback => {lit(m['fallback'])}" if "fallback" in m else ""
            text = (f"translate {{\n  source => {lit(ref(m['from']))}\n  target => {lit(dst)}\n"
                    f"  dictionary => {_hash({str(k): v for k, v in m['translate'].items()})}{fb}\n}}")
            text = f"if {ref(m['from'])} {{\n" + "\n".join("  " + l for l in text.splitlines()) + "\n}"
        else:
            text = f"if {ref(m['from'])} {{\n  mutate {{ copy => {{ {lit(ref(m['from']))} => {lit(dst)} }} }}\n}}"
        conv = m.get("convert")
        if conv is None and "value" in m and isinstance(m["value"], (int, float)) and not isinstance(m["value"], bool):
            conv = "integer" if isinstance(m["value"], int) else "float"
        if conv is None and "translate" in m and all(isinstance(v, int) for v in m["translate"].values()):
            conv = "integer"
        if conv:
            text += f"\nif {dst} {{\n  mutate {{ convert => {{ {lit(dst)} => {lit(conv)} }} }}\n}}"
        out.append(_wrap(_cond(m.get("when")), text))
    return "\n".join(out)


def used_fields(body: dict) -> list:
    """Parsed fields the rule maps (so `unmapped` holds only the rest)."""
    u = {m["from"] for m in body.get("map") or [] if "from" in m}
    if body.get("time"):
        u.add(body["time"]["field"])
    return sorted(u)


def finisher_cfg(body: dict, schema, labels: dict) -> dict:
    c = schema.classes[body["class"]]
    return {"cls": c["uid"], "cat": c.get("category_uid", c["uid"] // 1000), "ver": schema.version,
            "pname": labels.get("product") or "unknown", "vendor": labels.get("vendor"),
            "profiles": list(body.get("profiles") or []),
            "unmapped": "rest", "drop": [], "cname": body["class"]}


_FAILS = ("_lp_grokfail", "_lp_dissectfail", "_lp_kvfail", "_lp_jsonfail", "_lp_csvfail", "_xmlparsefailure",
          "_lp_nofield", "_lp_noextract", "_grokparsefailure", "_dissectfailure", "_csvparsefailure")
FAIL_COND = " or ".join(f'"{t}" in [tags]' for t in _FAILS)
FAIL_TAG_LIST = "[" + ", ".join(f'"{t}"' for t in _FAILS) + "]"


def array_paths(body: dict, schema) -> list:
    """Prefixes of mapped paths that are list attributes in OCSF (e.g. finding_info_list), deepest first: the
    agent writes them as one element (finding_info_list.title) and code turns them into lists."""
    out = set()
    for m in body.get("map") or []:
        parts = m["to"].split(".")
        for i in range(1, len(parts) + 1):
            a = schema.attr_at(body["class"], ".".join(parts[:i]))
            if a and a.get("is_array"):
                out.add(tuple(parts[:i]))
    return [list(p) for p in sorted(out, key=lambda p: (-len(p), p))]


WRAP_RB = ("{w}.each {{ |p| par = p[0..-2].inject(o) {{ |h, k| h.is_a?(Hash) ? h[k] : nil }}; "
           "next unless par.is_a?(Hash) && par.key?(p[-1]); v = par[p[-1]]; par[p[-1]] = [v] unless v.is_a?(Array) }}\n")


def render_parts(body: dict, schema, labels: dict, gid: str, table_var: str, versions: tuple = (1, 1),
                 tz: str | None = None, source: str = "-") -> tuple:
    """(extraction, rest): the agent's extract steps; then the header merge (LP.finish), time, mapping,
    LP.fin (class ids, type_uid, captions, metadata, unmapped) and the lp metadata."""
    cfg = finisher_cfg(body, schema, labels)
    used = {k: True for k in used_fields(body)}
    fin = ("f = event.get(\"[@metadata][s][f]\").to_h\n"
           "o = (event.get(\"[ocsf]\") || {}).to_h\n"
           "t = event.get(\"[@metadata][s][t]\")\n"
           "o[\"time\"] = (t.to_f * 1000).round if t\n"
           + (WRAP_RB.format(w=rb(array_paths(body, schema))) if array_paths(body, schema) else "") +
           f"LP.fin(event, o, f, {rb(used)}, {rb(cfg)}, {table_var})\n"
           "if event.get(\"tags\").to_a.include?(\"_lp_datefail\") then event.tag(\"lp_unparsed\"); "
           "event.set(\"[lp][reason]\", \"time_failed\") end\n"
           f"event.set(\"[lp][group_id]\", {rb(gid)}); event.set(\"[lp][source]\", {rb(source)}); "
           f"event.set(\"[lp][parser_version]\", {int(versions[0])}); "
           f"event.set(\"[lp][mapping_version]\", {int(versions[1])}); event.set(\"[lp][writer]\", \"direct\")")
    steps = render_steps(body, tz)
    extract_part, _, rest = steps.partition(MAP_MARK)
    rest = "ruby { code => 'LP.finish(event)' }\n" + rest.strip("\n") + "\nruby {\n  code => '" + fin + "'\n}"
    return extract_part.strip("\n"), rest


def render_group(body: dict, schema, labels: dict, gid: str, table_var: str, versions: tuple = (1, 1),
                 tz: str | None = None) -> str:
    """A group's whole filter (the sandbox runs this): extraction, then the rest."""
    ex, rest = render_parts(body, schema, labels, gid, table_var, versions, tz)
    return (ex + "\n" if ex else "") + rest


# ======================================================================= gate
FAIL_TAGS = {"_lp_nofield": "source-field", "_lp_noextract": "extraction (no field was made)",
             "_grokparsefailure": "grok", "_dissectfailure": "dissect", "_csvparsefailure": "csv", "_lp_grokfail": "grok", "_lp_dissectfail": "dissect", "_lp_kvfail": "kv", "_lp_jsonfail": "json",
             "_lp_csvfail": "csv", "_lp_datefail": "date", "_xmlparsefailure": "xml", "_rubyexception": "ruby"}


def const_paths(body: dict) -> set:
    """Event paths whose value the rule sets itself (constants, dictionary results): exempt from the
    'value is in the line' check."""
    return {m["to"] for m in body.get("map") or [] if "value" in m or "translate" in m}


def judge(schema, det, raw: str, out: dict, body: dict) -> list:
    """Problems of one sandbox event: failed steps, schema errors, values not in the line, ingest time
    although the line has a timestamp, outcome words that contradict the event."""
    from . import audit, checks
    probs = []
    tags = out.get("tags") or []
    for t in tags:
        if t in FAIL_TAGS:
            probs.append(f"extract: the {FAIL_TAGS[t]} step failed on this line")
    ev = out.get("ocsf") or {}
    if not ev:
        return probs + ["event: no OCSF event was produced"]
    errs, _ = schema.validate(ev)
    probs += [f"schema: {e}" for e in errs[:4]]
    consts = const_paths(body)
    for p, v in audit._event_strings(ev):
        if re.sub(r"\[\d+\]", "", p) in consts:
            continue
        if not audit._present(v, raw):
            probs.append(f"value: event `{p}` = {v!r} is not in this line")
    sb = out.get("sb") or {}
    fields = {k: v for k, v in (sb.get("f") or {}).items() if isinstance(v, (str, int, float))}
    if sb.get("f") is not None:            # the sandbox shows the parsed fields; the deploy check does not
        allf = sb.get("f") or {}

        def has(name):
            cur = allf
            for p in name.split("."):
                if not isinstance(cur, dict) or p not in cur:
                    return False
                cur = cur[p]
            return cur not in (None, "")
        for m in body.get("map") or []:
            if "from" in m and not m.get("when") and "fallback" not in m and not has(m["from"]):
                probs.append(f"map: `{m['from']}` (for {m['to']}) is missing on this line; give `when` if it is "
                             f"optional")
        for k, v in fields.items():
            if not k.startswith("@") and isinstance(v, str) and not audit._present(v, raw):
                probs.append(f"value: parsed field `{k}` = {v!r} is not in this line")
    ctags = [] if sb.get("t") else ["time_from_ingest"]
    probs += checks.problems(det, {k: v for k, v in fields.items() if isinstance(v, str)}, ev, ctags, {})
    return probs


# ======================================================================= agent tools
SAMPLES, HOLDOUT = 8, 32


def records(tools, g: dict, holdout: int = HOLDOUT) -> tuple:
    """(sample records, holdout records): each {id, raw, payload, h, det} for the sandbox."""
    samples, rest = tools._group_rows(g, 2000)
    out = []
    for i, r in enumerate(samples[:SAMPLES] + rest[:holdout]):
        det, _, _cols = tools.e.analyse(tools._rec(r))
        h = {k: v for k, v in (det.header or {}).items() if isinstance(v, (str, int, float))}
        out.append({"id": i, "raw": r["raw"], "payload": det.payload, "h": h, "det": det})
    n = min(len(samples), SAMPLES)
    return out[:n], out[n:]


FOREIGN_PER_GROUP, FOREIGN_MAX = 2, 60


def _is_json_object(text: str) -> bool:
    try:
        return isinstance(json.loads(text), dict)
    except (ValueError, TypeError):
        return False


def foreign_records(tools, g: dict, start: int) -> list:
    """Lines of other groups in the same bucket (unstructured formats share one route, so the filters of a
    bucket are tried in turn): a filter must not read them."""
    if g["format"] != "unstructured":
        return []
    from .reader import Record
    e, out = tools.e, []
    others = sorted((x for x in e.groups.values() if x["bucket"] == g["bucket"] and not x["merged_into"]
                     and x["signature"] != g["signature"] and not x["detail"].get("parent")), key=lambda x: -x["count"])
    for x in others:
        for smp in e.store.samples(x["signature"])[:FOREIGN_PER_GROUP]:
            if len(out) >= FOREIGN_MAX:
                return out
            det, _, _c = e.analyse(Record("lsforeign", 0, text=smp["raw"]))
            h = {k: v for k, v in (det.header or {}).items() if isinstance(v, (str, int, float))}
            out.append({"id": start + len(out), "raw": smp["raw"], "payload": det.payload, "h": h, "det": det,
                        "group": x["signature"]})
    return out


def labels_of(e, g: dict) -> dict:
    src = e.sources.get(g["source"]) or {}
    lab = {**{k: src.get(k) for k in ("vendor", "product") if src.get(k)}, **(g.get("labels") or {})}
    return lab


def run_test(tools, sandbox, group: str, body: dict, labels: dict | None = None) -> dict:
    e = tools.e
    g = tools._group(group)
    try:
        validate(body, e.schema)
        lab = {**labels_of(e, g), **(labels or {}), **(body.get("labels") or {})}
        text = render_group(body, e.schema, lab, g["signature"], "T_sb", tz=e.deployment_tz())
    except FilterError as exc:
        return {"ok": False, "error": str(exc)}
    except Exception as exc:              # a malformed shape the checks did not foresee
        return {"ok": False, "error": f"rule is not well formed: {exc!r}"[:400]}
    from .sandbox import tables_for
    samples, hold = records(tools, g)
    first = next(iter((body.get("extract") or [{}])[0]), None)
    if samples and first != "json" and all(_is_json_object(r["payload"]) for r in samples + hold):
        return {"ok": False, "error": "the payload of every line is a JSON object: start the extract with "
                                      "{\"json\": {}} and map the keys (dots reach nested keys), not grok over JSON text"}
    foreign = foreign_records(tools, g, len(samples) + len(hold))
    recs = samples + hold + foreign
    if not samples + hold:
        return {"ok": False, "error": "this group has no stored lines to test on"}
    res = sandbox.run(text, [{"id": r["id"], "payload": r["payload"], "h": r["h"]} for r in recs],
                      tables_for(e.schema, body["class"]),
                      tz=e.deployment_tz() or "UTC")
    if "error" in res:
        return {"ok": False, "error": "Logstash refused the filter: " + res["error"], "config": text[:3000]}
    evs = res["events"]
    errors: dict = {}
    good = {"samples": 0, "holdout": 0}
    taken = []
    for r in foreign:
        out = evs.get(r["id"]) or evs.get(str(r["id"]))
        if out is not None and not any(t in FAIL_TAGS for t in (out.get("tags") or [])):
            taken.append({"error": f"the filter also reads lines of another group ({r['group']}); make the "
                                   f"extraction specific to this group's lines", "line": r["raw"][:300],
                          "where": "other groups", "count": 1})
    for r in samples + hold:
        part = "samples" if r in samples else "holdout"
        out = evs.get(r["id"]) or evs.get(str(r["id"]))
        probs = ["event: Logstash returned nothing for this line"] if out is None else judge(e.schema, r["det"], r["raw"], out, body)
        if probs:
            for p in probs[:5]:
                errors.setdefault(p, {"error": p, "line": r["raw"][:300], "where": part, "count": 0})["count"] += 1
        else:
            good[part] += 1
    first = evs.get(samples[0]["id"]) if samples else None
    first = first or (evs.get(str(samples[0]["id"])) if samples else None)
    return {"ok": True, "samples": len(samples), "samples_valid": good["samples"], "holdout_lines": len(hold),
            "holdout_valid": good["holdout"],
            "other_group_lines": len(foreign), "other_group_lines_read": len(taken),
            "would_save": bool(samples) and good["samples"] == len(samples) and good["holdout"] == len(hold)
                          and not taken,
            "errors": (taken[:3] + sorted(errors.values(), key=lambda x: -x["count"]))[:12],
            "ruby_error": res.get("ruby_error"),
            "first_line": samples[0]["raw"][:500] if samples else None,
            "first_parsed_fields": ((first or {}).get("sb") or {}).get("f"),
            "first_event": (first or {}).get("ocsf")}


def save(tools, sandbox, group: str, body: dict, labels: dict | None = None, note: str = "") -> dict:
    from . import registry
    from .tools import Refused
    t = run_test(tools, sandbox, group, body, labels)
    if not t.get("ok"):
        raise Refused(t["error"])
    if not t["would_save"]:
        raise Refused(f"samples {t['samples_valid']}/{t['samples']}, holdout {t['holdout_valid']}/{t['holdout_lines']} "
                      f"pass, {t['other_group_lines_read']} lines of other groups read; every tested line must pass "
                      f"and no other group's line may be read. First problems: {json.dumps(t['errors'][:3])[:900]}")
    g = tools._group(group)
    rule_id = f"lsfilter:{g['signature']}"
    if labels:
        body = {**body, "labels": {k: str(v)[:80] for k, v in labels.items() if k in ("vendor", "product", "event_type")}}
    meta = {"created_by": tools.agent, "note": note,
            "check": f"sandbox: samples {t['samples_valid']}/{t['samples']}, holdout {t['holdout_valid']}/{t['holdout_lines']}"}
    v = registry.save_rule(tools.store, rule_id, body, meta)
    tools.e.reload()
    tools.store.queue_done("needs-lsfilter", g["signature"])
    tools._log("save_lsfilter", group, True, f"{rule_id} v{v}")
    return {"saved": rule_id, "version": v, "check": meta["check"]}


def samples_for_agent(tools, group: str) -> dict:
    g = tools._group(group)
    samples, hold = records(tools, g, holdout=0)
    return {"group": g["signature"], "format": g["format"], "bucket": g["bucket"], "source": g["source"],
            "template": g["template"][:600], "lines_stored": g["count"], "labels": labels_of(tools.e, g),
            "deployment_timezone": tools.e.deployment_tz(),
            "samples": [{"raw": r["raw"][:1500], "payload": r["payload"][:1500], "header_fields": r["h"]}
                        for r in samples]}


def enqueue(e, limit: int | None = None) -> int:
    """Queue every top-level group that has no Logstash filter yet (split groups are left to Variant A)."""
    n = 0
    for g in sorted(e.groups.values(), key=lambda g: -g["count"]):
        if g["merged_into"] or g["detail"].get("parent") or g["status"] in ("split", "ignored"):
            continue
        if e.snap.rule("lsfilter:" + g["signature"]) or e.snap.rule("split:" + g["signature"]):
            continue
        if g["count"] < 2:
            continue
        if e.store.enqueue("needs-lsfilter", g["signature"], {"signature": g["signature"], "bucket": g["bucket"],
                                                               "format": g["format"], "source": g["source"],
                                                               "count": g["count"]}):
            n += 1
        if limit and n >= limit:
            break
    return n


# ======================================================================= deploy check
def verify_lines(e, included: set, per_group: int = 8, others: int = 2) -> list:
    """Stored lines to send through the compiled set: `per_group` of each included group, `others` of every
    other group (a Variant B filter must not take lines of a group it was not written for)."""
    from .reader import Record
    lines = []
    for g in e.groups.values():
        if g["merged_into"]:
            continue
        n = per_group if g["signature"] in included else others
        for s in e.store.samples(g["signature"])[:n]:
            raw = s["raw"]
            if not raw:
                continue
            try:
                det, _, cols = e.analyse(Record("lsverify", 0, text=raw))
                sg = e._sign(det, None, cols)
                cg = e.canonical(sg.signature)
            except Exception:
                continue
            lines.append({"id": len(lines), "raw": raw, "det": det,
                          "expect": cg["signature"] if cg else None})
    return lines


def verify_judge(e, lines: list, events: dict, included: set, now_ms: int) -> dict:
    """Groups to exclude, with a cause: lines lost or misrouted, a failed check, or a filter taking lines
    of another group."""
    bad: dict = {}
    counts = {"ok": 0, "problem": 0, "misrouted": 0, "lost": 0, "overreach": 0, "ok_not_ours": 0}
    for ln in lines:
        ev = events.get(ln["id"])
        exp = ln["expect"]
        got = ((ev or {}).get("lp") or {}).get("group_id")
        if exp in included:
            if ev is None or not got:
                counts["lost"] += 1
                bad.setdefault(exp, f"line not parsed in the pipeline ({((ev or {}).get('lp') or {}).get('reason')})")
            elif got != exp:
                counts["misrouted"] += 1
                bad.setdefault(exp, f"its lines were taken by group {got}")
                bad.setdefault(got, "its filter takes lines of another group")
            else:
                rule = e.snap.rule("lsfilter:" + exp)
                ocsf = ev.get("ocsf") or {}
                out = {"tags": ev.get("tags"), "ocsf": ocsf, "sb": {"t": ocsf.get("time") != now_ms, "f": None}}   # no parsed fields at deploy
                probs = judge(e.schema, ln["det"], ln["raw"], out, rule["body"] if rule else {})
                if probs:
                    counts["problem"] += 1
                    bad.setdefault(exp, probs[0])
                else:
                    counts["ok"] += 1
        elif got:
            counts["overreach"] += 1
            bad.setdefault(got, "its filter takes lines of a group it was not written for")
        else:
            counts["ok_not_ours"] += 1
    return {"exclude": bad, "counts": counts}
