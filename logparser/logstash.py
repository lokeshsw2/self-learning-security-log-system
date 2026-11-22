"""Compile the learned rules into Logstash pipelines.

The engine stays the learner and the verifier; Logstash does the parsing and the OCSF
mapping in production.  Layout (one set of files per compile):

  distributor.conf   http input (one raw line per event), envelope / format detection
                     (grok, unrolled to the engine's detect depth), decoding and signature
                     of structured records, route key -> source pipeline
  src_<slug>.conf    one pipeline per identified source: parsers and OCSF mappings of the
                     verified groups of that source (grok / json / mutate / translate; a
                     small `ruby` block per group for what has no native filter)
  sink.conf          shared output: the existing ClickHouse template
  pipelines.yml      all of them, absolute paths

Everything the engine would not emit is tagged `lp_unparsed` with `[lp][reason]`.
`ls_verify.py` proves, per group, that the compiled pipeline gives the engine's event;
only groups that agree are compiled into the production set (`include_groups`).
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass, field

from . import ocsf, signature, transforms
from .logstash_rb import RUBY_LIB

S = "[@metadata][s]"
SAFE_FIELD = re.compile(r"^[A-Za-z0-9_@.\-:]+$")
INT_BASE = {"integer_t", "long_t"}


class Unsupported(Exception):
    """A rule this compiler cannot express faithfully; the group is excluded with the reason."""


# =================================================================== pattern conversion
def re2_to_onig(p: str, cap=None, grok: bool = False) -> str:
    """Convert an RE2 pattern to Oniguruma (Ruby / grok) syntax.

    `^` and `$` become `\\A` and `\\z` (RE2 anchors the whole text; Ruby anchors lines),
    `(?P<n>` becomes `(?<n>` (renamed through `cap` when given), a literal `[` inside a
    class is escaped, `(?s)` becomes `(?m)`.  With `grok=True` quotes, `$` and `%` are
    hex-escaped so the text is safe inside a Logstash config string and grok never sees
    a `%{...}` reference.  Flags that have no Oniguruma twin raise Unsupported."""
    out: list[str] = []
    i, n = 0, len(p)
    in_class = False
    class_start = 0

    def lit(ch: str) -> str:
        if grok:
            if ch == '"':
                return r"\x22"
            if ch == "'":
                return r"\x27"
            if ch == "%":
                return r"\x25"
            if ch == "$":
                return r"\x24"
        return ch

    while i < n:
        ch = p[i]
        if ch == "\\":
            nxt = p[i + 1] if i + 1 < n else ""
            if nxt == "x" and p[i + 2:i + 3] == "{":
                j = p.index("}", i)
                out.append("\\u{" + p[i + 3:j] + "}")
                i = j + 1
                continue
            if nxt in ("Q", "E", "C"):
                raise Unsupported(f"\\{nxt} in pattern")
            if nxt in ('"', "'", "%", "$"):
                out.append(lit(nxt))
            else:
                out.append(ch + nxt)
            i += 2
            continue
        if in_class:
            if ch == "[" and p[i + 1:i + 2] == ":":
                j = p.find(":]", i)
                out.append(p[i:j + 2])
                i = j + 2
                continue
            if ch == "[":
                out.append("\\[")
            elif ch == "]" and i > class_start:
                out.append("]")
                in_class = False
            elif ch == "&" and p[i + 1:i + 2] == "&":
                out.append("&\\&")
                i += 1
            else:
                out.append(lit(ch))
            i += 1
            continue
        if ch == "[":
            in_class = True
            out.append("[")
            i += 1
            if p[i:i + 1] == "^":
                out.append("^")
                i += 1
            if p[i:i + 1] == "]":
                out.append("\\]")
                i += 1
            class_start = i
            continue
        if ch == "(" and p[i + 1:i + 2] == "?":
            m = re.compile(r"\(\?P<([A-Za-z_]\w*)>").match(p, i)
            if m:
                name = m.group(1)
                out.append("(?<" + (cap(name) if cap else name) + ">")
                i = m.end()
                continue
            m = re.compile(r"\(\?([a-zA-Z]*)(?:-([a-zA-Z]+))?([:)])").match(p, i)
            if m and (m.group(1) or m.group(2)):
                flags = m.group(1)
                if "U" in flags or "m" in flags or (m.group(2) and not set(m.group(2)) <= {"i", "s"}):
                    raise Unsupported("regex flag " + m.group(0))
                flags = flags.replace("s", "m")
                neg = (m.group(2) or "").replace("s", "m")
                out.append("(?" + flags + ("-" + neg if neg else "") + m.group(3))
                i = m.end()
                continue
        if ch == "^":
            out.append("\\A")
        elif ch == "$":
            out.append("\\z")
        else:
            out.append(lit(ch))
        i += 1
    return "".join(out)


_JODA = {"Y": "yyyy", "y": "yy", "m": "MM", "d": "dd", "e": "d", "H": "HH", "I": "hh", "M": "mm", "S": "ss",
         "f": "SSS", "b": "MMM", "B": "MMMM", "a": "EEE", "A": "EEEE", "p": "a", "z": "Z", "Z": "z",
         "j": "DDD", "h": "MMM", "%": "'%'"}


def strptime_to_joda(fmt: str) -> str:
    """strftime / strptime format -> Joda pattern (Logstash `date` filter).  Literal letters are quoted."""
    out: list[str] = []
    i = 0
    lit: list[str] = []

    def flush():
        if lit:
            out.append("'" + "".join(lit).replace("'", "''") + "'")
            lit.clear()
    while i < len(fmt):
        ch = fmt[i]
        if ch == "%" and i + 1 < len(fmt):
            d = fmt[i + 1]
            if d not in _JODA:
                raise Unsupported(f"strptime directive %{d}")
            flush()
            out.append(_JODA[d])
            i += 2
            continue
        if ch.isalpha() or ch == "'":
            lit.append(ch)
        else:
            flush()
            out.append(ch)
        i += 1
    flush()
    return "".join(out)


# =================================================================== literals
def rb(obj) -> str:
    """Ruby literal for plain JSON-like data.  No single quotes, no `${`, no `#{` in the output
    (the text is inlined into single-quoted Logstash config strings)."""
    if obj is None:
        return "nil"
    if obj is True:
        return "true"
    if obj is False:
        return "false"
    if isinstance(obj, int):
        return str(obj)
    if isinstance(obj, float):
        return repr(obj)
    if isinstance(obj, str):
        s = json.dumps(obj, ensure_ascii=False)
        return s.replace("'", "\\x27").replace("#", "\\x23").replace("$", "\\x24")
    if isinstance(obj, (list, tuple)):
        return "[" + ", ".join(rb(x) for x in obj) + "]"
    if isinstance(obj, dict):
        return "{" + ", ".join(f"{rb(str(k))} => {rb(v)}" for k, v in obj.items()) + "}"
    raise Unsupported(f"cannot serialise {type(obj).__name__}")


def cstr(s: str) -> str:
    """A Logstash config string literal, or Unsupported when the text cannot be quoted safely."""
    if "${" in s or "\n" in s or "\r" in s or "\x00" in s:
        raise Unsupported("string with ${ or a line break")
    if '"' not in s and not s.endswith("\\"):
        return '"' + s + '"'
    if "'" not in s and not s.endswith("\\"):
        return "'" + s + "'"
    raise Unsupported("string with both quote kinds")


def ref(path: str, base: str = "ocsf") -> str:
    return "[" + base + "]" + "".join(f"[{p}]" for p in path.split("."))


def fref(name: str) -> str:
    return f"{S}[f][{name}]"


def slugify(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", s.lower()).strip("_")[:60] or "unknown"


def sig_digest(fmt: str, sig_keys: list, disc: list, text: str) -> str:
    return hashlib.sha1("\x1f".join([fmt, "\x1e".join(sig_keys), "\x1e".join(disc), text]).encode()).hexdigest()[:16]


def dig(s: str) -> str:
    return hashlib.sha1(s.encode()).hexdigest()[:16]


def ind(text: str, n: int) -> str:
    pad = " " * n
    return "\n".join(pad + ln if ln.strip() else ln for ln in text.split("\n"))


def ruby_filter(code: str, init: str | None = None) -> str:
    assert "'" not in code, "single quote in ruby code"
    s = "ruby {\n"
    if init is not None:
        assert "'" not in init
        s += f"  init => '{init}'\n"
    return s + f"  code => '{code}'\n}}"


# =================================================================== model
@dataclass
class Leaf:
    gid: str
    root: str
    source: str
    slug: str = ""
    bucket: str = ""
    fmt: str = ""
    parser_kind: str = ""
    status: str = "ok"           # ok | unsupported
    reason: str = ""
    text: str = ""               # filter text of the mapping
    native: int = 0
    ruby: int = 0
    consts: int = 0
    cond_key: str | None = None  # split-key digest when the root is split


@dataclass
class Root:
    sig: str
    bucket: str
    fmt: str
    g: dict
    slug: str = ""
    leaves: list = field(default_factory=list)
    split: dict | None = None
    parser: dict | None = None
    rkey: str = ""
    rkeys: list = field(default_factory=list)
    status: str = "ok"
    reason: str = ""


@dataclass
class Generated:
    files: dict                  # file name -> text
    pipelines: list              # pipeline ids (order of pipelines.yml)
    leaves: dict                 # gid -> Leaf
    roots: dict
    stats: dict


# =================================================================== compiler
class Compiler:
    def __init__(self, engine, base_fallback: bool = False, direct: bool = False):
        """`base_fallback`: also compile groups that have a parser but no mapping yet, as the engine reads
        them (OCSF Base Event through the default mapping), so their data reaches the event store before
        a class mapping is learned."""
        self.e = engine
        self.base_fallback = base_fallback
        # Variant B: each group's filter is the one an agent wrote (lsfilter:<group>), rendered from its steps;
        # routing, tables and sink are shared with Variant A
        self.direct = direct
        self.snap = engine.snap
        self.schema = engine.schema
        self.tz = engine.deployment_tz()
        self.caps_need: dict[str, set] = {}
        self.tables_out: dict[str, str] = {}
        self.plans: dict = {}
        self._build()

    # ---------------------------------------------------------- model
    def _source_slug(self, source: str) -> str:
        s = self.e.sources.get(source) or {}
        if s.get("vendor") and s.get("product"):
            return slugify(f"{s['vendor']}_{s['product']}")
        return slugify(source.split("|", 1)[0])

    def _build(self) -> None:
        e = self.e
        groups = e.groups
        kids: dict[str, list] = {}
        for g in groups.values():
            p = g["detail"].get("parent")
            if p and not g["merged_into"]:
                kids.setdefault(p, []).append(g)
        self.roots: dict[str, Root] = {}
        self.leaves: dict[str, Leaf] = {}
        for g in groups.values():
            if g["merged_into"] or g["detail"].get("parent"):
                continue
            if not (g["parser_rule"] or kids.get(g["signature"]) or g["status"] in ("split", "mapped", "parsed")
                    or (self.direct and self.snap.rule("lsfilter:" + g["signature"]))):
                continue
            r = Root(g["signature"], g["bucket"], g["format"], g)
            sp = self.snap.rule("split:" + g["signature"])
            r.split = sp["body"] if sp else None
            pr = self.snap.rule(g["parser_rule"]) if g["parser_rule"] else None
            r.parser = pr["body"] if pr else None
            r.slug = self._source_slug(g["source"])
            members = kids.get(g["signature"], []) if r.split else [g]
            if r.split and not members and g["parser_rule"] and g["mapping_rule"]:
                members = []
            for m in members:
                leaf = Leaf(m["signature"], r.sig, m["source"], self._source_slug(m["source"]), r.bucket, r.fmt)
                leaf.parser_kind = (r.parser or {}).get("kind", "")
                r.leaves.append((leaf, m))
                self.leaves[leaf.gid] = leaf
            self.roots[r.sig] = r
        # one pipeline per bucket owner for unstructured buckets (they are routed by bucket)
        by_bucket: dict[str, list] = {}
        for r in self.roots.values():
            if r.fmt == "unstructured":
                by_bucket.setdefault(r.bucket, []).append(r)
        for bucket, rs in by_bucket.items():
            counts: dict[str, int] = {}
            for r in rs:
                counts[r.slug] = counts.get(r.slug, 0) + max(1, len(r.leaves))
            owner = max(sorted(counts), key=lambda k: counts[k])
            for r in rs:
                r.slug = owner
                for leaf, _ in r.leaves:
                    leaf.slug = owner
        for r in self.roots.values():
            for leaf, _ in r.leaves:
                leaf.slug = r.slug

    # ---------------------------------------------------------- sign / route keys
    def root_key(self, r: Root) -> str:
        """The route key the distributor computes for records of this root."""
        if r.fmt == "unstructured":
            return dig(r.bucket)
        d = r.g["detail"]
        sk, disc, text = d.get("sig_keys") or [], d.get("discriminators") or [], d.get("text", "")
        if r.fmt not in ("json", "kv", "cef", "leef", "delimited"):
            raise Unsupported(f"format {r.fmt} is not decoded by the pipeline")
        if len(sk) >= 400 or len(d.get("keys") or []) >= 400:
            raise Unsupported("key list truncated in the group detail")
        want = signature._h(r.bucket, r.fmt, "\x1e".join(sk), "\x1e".join(disc), text)
        if want != r.sig:
            raise Unsupported("group signature is not reproducible from its detail (drift / family)")
        return dig(r.bucket + "\x1f" + sig_digest(r.fmt, sk, disc, text))

    def alias_keys(self, r: Root) -> list:
        """Route keys of the other signatures the engine maps to this structured root (drift / optional keys).
        The engine stores only their hashes, so the key sets are recomputed from stored lines of the group
        and of its alias signatures: every line whose signature differs from the group's own but resolves
        to it contributes one route key."""
        from .reader import Record
        aliases = [sig for sig in self.e.alias if sig != r.sig and (self.e.canonical(sig) or {}).get("signature") == r.sig]
        rows: list = []
        g = r.g
        rows += [x[1] for x in self.e._samples(g)[:40]]
        for sig in [r.sig] + aliases:
            rows += [x["raw"] for x in self.e.store.raw_by_signature(sig, 150) if x.get("raw")]
            if sig != r.sig:
                rows += [x["raw"] for x in self.e.store.samples(sig)[:5]]
        out: list = []
        for raw in dict.fromkeys(rows):
            try:
                det, _src, cols = self.e.analyse(Record("lsverify", 0, text=raw))
                sg = self.e._sign(det, None, cols)
            except Exception:
                continue
            if sg.error or det.bucket != r.bucket or sg.signature == r.sig:
                continue
            if (self.e.canonical(sg.signature) or {}).get("signature") != r.sig:
                continue
            d = sg.detail
            k = dig(r.bucket + "\x1f" + sig_digest(r.fmt, d.get("sig_keys") or [], d.get("discriminators") or [],
                                                     d.get("text", "")))
            if k not in out:
                out.append(k)
        return out

    # ---------------------------------------------------------- mapping
    def attr_kind(self, cname: str, path: str):
        a = self.schema.attr_at(cname, path) if hasattr(self.schema, "attr_at") else self.schema._attr_at(cname, path)
        if a is None:
            return "obj", False, None
        t = a.get("type")
        if t in ("object_t", "json_t"):
            return "obj", bool(a.get("is_array")), a
        base = self.schema.base_type(t)
        kind = "int" if base in INT_BASE else "float" if base == "float_t" else "bool" if base == "boolean_t" \
            else "str" if base == "string_t" else "obj"
        return kind, bool(a.get("is_array")), a

    def compile_variant(self, m: dict, labels: dict, typed: bool, protected_srcs: set, gid: str):
        schema = self.schema
        c = schema.cls(m["class"])
        if c is None:
            raise Unsupported(f"unknown class {m['class']}")
        cname = c["name"]
        top = self.caps_need.setdefault(cname, {"activity_id", "severity_id", "class_uid", "category_uid", "type_uid"})
        # constants (typed at compile time with the engine's own coercion)
        cev: dict = {}
        for path, value in (m.get("constants") or {}).items():
            try:
                kind, arr, a = self.attr_kind(cname, path)
                ocsf._set_path(cev, path, ocsf._coerce(schema, a, value))
            except transforms.TransformError:
                continue
            top.add(re.split(r"[.\[]", path)[0])
        native_c: list = []
        ruby_c: list = []

        def walk(d, prefix):
            for k, v in d.items():
                p = f"{prefix}.{k}" if prefix else k
                if isinstance(v, dict) and v:
                    walk(v, p)
                elif isinstance(v, (str, int, float, bool)) and not isinstance(v, list) \
                        and SAFE_FIELD.match(p.replace("_", "a")) and "%{" not in str(v) \
                        and "\n" not in str(v) and "${" not in str(v):
                    native_c.append((p, v))
                else:
                    ruby_c.append((p, v))
        walk(cev, "")
        # entries
        fields = m.get("fields") or []
        use_count: dict[str, int] = {}
        to_count: dict[str, int] = {}
        for f in fields:
            to_count[f["to"]] = to_count.get(f["to"], 0) + 1
            srcs = f["from"] if isinstance(f.get("from"), list) else ([f["from"]] if "from" in f else [])
            for s in srcs:
                use_count[s] = use_count.get(s, 0) + 1
            if "when" in f:
                use_count[f["when"]["field"]] = use_count.get(f["when"]["field"], 0) + 5
        for s in protected_srcs:
            use_count[s] = use_count.get(s, 0) + 5
        const_paths = {p for p, _ in native_c} | {p for p, _ in ruby_c}
        rename: dict = {}
        convert: dict = {}
        guards: list = []
        enum_src: list = []
        translates: list = []
        enum_int: list = []
        ruby_entries: list = []
        static_used: list = []
        nnative = 0
        for f in fields:
            to = f["to"]
            top.add(re.split(r"[.\[]", to)[0])
            kind, arr, a = self.attr_kind(cname, to)
            srcs = f["from"] if isinstance(f.get("from"), list) else ([f["from"]] if "from" in f else [])
            steps = f.get("transform") or []
            if isinstance(steps, dict):
                steps = [steps]
            simple = ("when" not in f and "join" not in f and "value" not in f and len(srcs) == 1
                      and SAFE_FIELD.match(srcs[0]) and "[" not in to and not arr and to_count[to] == 1
                      and use_count.get(srcs[0], 0) == 1 and to not in const_paths and a is not None)
            if simple and not steps and (kind == "str" or (kind == "int" and not typed)):
                src = srcs[0]
                static_used.append(src)
                nnative += 1
                if kind == "str":
                    rename[fref(src)] = ref(to)
                    convert[ref(to)] = "string"
                else:
                    guards.append((fref(src), ref(to)))
                continue
            if simple and len(steps) == 1 and steps[0]["fn"] == "enum_lookup" and kind in ("str", "int") \
                    and set((steps[0].get("args") or {}).keys()) <= {"map", "default"}:
                args = steps[0].get("args") or {}
                try:
                    tbl = {}
                    for k, v in (args.get("map") or {}).items():
                        tbl[str(k).lower()] = ocsf._coerce(schema, a, v)
                    default = ocsf._coerce(schema, a, args["default"]) if args.get("default") is not None else None
                    if any(isinstance(v, (list, dict)) for v in list(tbl.values()) + [default]):
                        raise transforms.TransformError("list")
                    for k in tbl:
                        cstr(k)
                    ok = True
                except (transforms.TransformError, Unsupported):
                    ok = False
                if ok:
                    src = srcs[0]
                    static_used.append(src)
                    nnative += 1
                    enum_src.append(fref(src))
                    sval = lambda v: (str(v) if not isinstance(v, bool) else ("true" if v else "false"))
                    dic = " ".join(f"{cstr(k)} => {cstr(sval(v))}" for k, v in tbl.items())
                    fb = f" fallback => {cstr(sval(default))}" if default is not None else ""
                    translates.append(f"translate {{ source => {cstr(fref(src))} target => {cstr(ref(to))} "
                                      f"dictionary => {{ {dic} }}{fb} }}")
                    if kind == "int":
                        enum_int.append(ref(to))
                    continue
            ruby_entries.append(self.ruby_entry(f, srcs, steps, kind, arr, a is not None))
        parts: list = []
        nat_add = " ".join(f"{cstr(ref(p))} => {cstr(self._cs(v))}" for p, v in native_c)
        if nat_add:
            parts.append(f"mutate {{ add_field => {{ {nat_add} }} }}")
            cv = {ref(p): ("integer" if isinstance(v, int) and not isinstance(v, bool) else
                           "float" if isinstance(v, float) else "boolean")
                  for p, v in native_c if not isinstance(v, str)}
            if cv:
                parts.append("mutate { convert => { " + " ".join(f"{cstr(k)} => \"{v}\"" for k, v in cv.items()) + " } }")
        if rename:
            parts.append("mutate {\n  rename => { " + " ".join(f"{cstr(k)} => {cstr(v)}" for k, v in rename.items())
                         + " }\n  convert => { " + " ".join(f"{cstr(k)} => \"{v}\"" for k, v in convert.items()) + " }\n}")
        for src, dst in guards:
            parts.append(f'if {src} =~ /\\A\\s*[+-]?\\d+\\s*\\z/ {{\n  mutate {{\n    rename => {{ {cstr(src)} => {cstr(dst)} }}\n'
                         f'    convert => {{ {cstr(dst)} => "integer" }}\n  }}\n}}')
        if enum_src:
            lst = ", ".join(cstr(s) for s in enum_src)
            parts.append(f"mutate {{ convert => {{ {' '.join(cstr(s) + ' => \"string\"' for s in enum_src)} }}"
                         f" lowercase => [ {lst} ] strip => [ {lst} ] }}")
            parts.extend(translates)
            if enum_int:
                parts.append("mutate { convert => { " + " ".join(f'{cstr(s)} => "integer"' for s in enum_int) + " } }")
        cfg = {"cls": c["uid"], "cat": c.get("category_uid", 0), "ver": schema.version,
               "pname": labels.get("product") or "unknown", "vendor": labels.get("vendor"),
               "profiles": list(m.get("profiles") or []), "unmapped": m.get("unmapped", "rest"),
               "drop": list(m.get("drop") or []), "cname": cname}
        code = ["f = event.get(\"[@metadata][s][f]\").to_h", "o = (event.get(\"[ocsf]\") || {}).to_h", "used = {}"]
        if static_used:
            code.append(f"{rb(static_used)}.each {{ |k| used[k] = true }}")
        for p, v in ruby_c:
            code.append(f"begin; LP.put(o, {rb(p)}, {rb(v)}); rescue StandardError; end")
        code += ruby_entries
        code.append(f"LP.fin(event, o, f, used, {rb(cfg)}, @T@)")
        return {"native": "\n".join(parts), "code": code, "nnative": nnative + len(native_c), "nruby": len(ruby_entries) + len(ruby_c),
                "nconst": len(native_c) + len(ruby_c), "cname": cname}

    @staticmethod
    def _cs(v) -> str:
        return ("true" if v else "false") if isinstance(v, bool) else str(v)

    def ruby_entry(self, f: dict, srcs: list, steps: list, kind: str, arr: bool, known: bool) -> str:
        to = f["to"]
        body = []
        if "value" in f:
            body.append(f"v = {rb(f['value'])}")
        elif "join" in f:
            body.append(f"v = LP.joined(f, used, {rb(srcs)}, {rb(f['join'])})")
        else:
            body.append(f"v = LP.pick(f, used, {rb(srcs)})")
        body.append("unless v.nil?")
        for st in steps:
            args = dict(st.get("args") or {})
            fn = st["fn"]
            if "pattern" in args:
                args["pattern"] = re2_to_onig(args["pattern"])
            if fn == "enum_lookup" and args.get("patterns"):
                args["patterns"] = {re2_to_onig(k): v for k, v in args["patterns"].items()}
            if fn == "parse_timestamp" and args.get("year") is not None:
                args["year"] = int(args["year"])
            body.append(f"  v = LP.tr(v, {rb(fn)}, {rb(args)})")
        if known:
            body.append(f"  v = LP.coerce(v, {rb(kind)}, {rb(arr)})")
        body.append(f"  LP.put(o, {rb(to)}, v) unless v.nil?")
        body.append("end")
        lines = ["begin"]
        if "when" in f:
            w = dict(f["when"])
            if "matches" in w:
                w["matches"] = re2_to_onig(w["matches"])
            lines.append("  if LP.cond(f, " + rb(w) + ")")
            lines += ["    " + b for b in body]
            lines.append("  end")
        else:
            lines += ["  " + b for b in body]
        lines.append("rescue StandardError")
        lines.append("end")
        return "\n".join(lines)

    # ---------------------------------------------------------- leaf
    def compile_direct_leaf(self, leaf: Leaf, g: dict, root: Root) -> None:
        from . import lsdirect
        try:
            if root.split:
                raise Unsupported("split groups are written by Variant A")
            rule = self.snap.rule("lsfilter:" + g["signature"])
            if rule is None:
                raise Unsupported("no Logstash filter written yet")
            body = rule["body"]
            lsdirect.validate(body, self.schema)
            labels = {**lsdirect.labels_of(self.e, g), **(body.get("labels") or {})}
            leaf.extract, leaf.text = lsdirect.render_parts(
                body, self.schema, labels, leaf.gid, "@T@", (rule.get("version", 1), rule.get("version", 1)),
                tz=self.tz, source=leaf.source.split("|")[0])
            cname = self.schema.cls(body["class"])["name"]
            self.caps_need.setdefault(body["class"], set()).update(self.schema.cls(cname)["attributes"])
            leaf.status, leaf.reason = "ok", ""
        except Exception as ex:               # a bad saved rule leaves out its group, never the deploy
            leaf.status, leaf.reason = "unsupported", f"{type(ex).__name__}: {ex}"[:300]

    def direct_block(self, r: Root) -> str | None:
        """Structured root, Variant B: the agent's extraction, then (unless a step failed) the rest."""
        leaves = [l for l, _ in r.leaves if l.status == "ok" and l.included]
        if not leaves:
            return None
        l = leaves[0]
        from .lsdirect import FAIL_COND
        return ((l.extract + "\n" if l.extract else "") +
                f'if {FAIL_COND} {{\n  mutate {{ add_field => {{ "[lp][reason]" => "parse_failed" }} }}\n}} else {{\n'
                f'{ind(l.text, 2)}\n}}')

    def direct_bucket(self, rs: list) -> str:
        """Unstructured bucket, Variant B: try each group's extraction in turn (most literal text first);
        the first that succeeds owns the line."""
        from .lsdirect import FAIL_COND, FAIL_TAG_LIST
        cands = [(r, l) for r in rs for l, _ in r.leaves if l.status == "ok" and l.included]
        cands.sort(key=lambda rl: (-len(re.sub(r"<[^>]+>", "", rl[0].g["template"] or "")), rl[1].gid))
        seq, disp = [], []
        for i, (r, l) in enumerate(cands):
            attempt = (f"{l.extract}\nif {FAIL_COND} {{\n  mutate {{ remove_tag => {FAIL_TAG_LIST} "
                       f'remove_field => ["[@metadata][s][f]"] }}\n}} else {{\n'
                       f'  mutate {{ add_field => {{ "[@metadata][pm]" => "{i}" }} }}\n}}')
            seq.append(f"if ![@metadata][pm] {{\n{ind(attempt, 2)}\n}}")
            disp.append(f'{"if" if i == 0 else "else if"} [@metadata][pm] == "{i}" {{\n{ind(l.text, 2)}\n}}')
        return ("\n".join(seq) + "\n" + " ".join(disp) +
                '\nif ![@metadata][pm] {\n  mutate { add_field => { "[lp][reason]" => "parse_failed" } }\n}')

    def compile_leaf(self, leaf: Leaf, g: dict, root: Root) -> None:
        if self.direct:
            return self.compile_direct_leaf(leaf, g, root)
        e = self.e
        try:
            if not g["parser_rule"] or not e.snap.rule(g["parser_rule"]):
                raise Unsupported("no parser rule")
            mapping_rule = g["mapping_rule"]
            if not mapping_rule:
                if not self.base_fallback:
                    raise Unsupported("no mapping rule (engine falls back to the base event)")
                from .engine import DEFAULT_MAPPING
                mapping_rule = DEFAULT_MAPPING
            pr = e.snap.rule(g["parser_rule"])["body"]
            m = e._mapping(mapping_rule)
            if m is None:
                raise Unsupported("mapping rule missing")
            labels = g.get("labels") or {}
            typed = pr["kind"] == "json"
            protected = set()
            if root.split:
                protected |= set(root.split.get("fields") or []) | set(root.split.get("presence") or [])
            for cond, _sub, _n in m.get("switch") or ():
                protected.add(cond["field"])
            variants = [self.compile_variant(m, labels, typed, protected, leaf.gid)]
            conds = []
            for cond, sub, _n in m.get("switch") or ():
                c2 = dict(cond)
                if "matches" in c2:
                    c2["matches"] = re2_to_onig(c2["matches"])
                conds.append(c2)
                variants.append(self.compile_variant(sub, labels, typed, protected, leaf.gid))
            pv = (e.snap.rule(g["parser_rule"]) or {}).get("version", 0)
            mv = (e.snap.rule(mapping_rule) or {}).get("version", 0)
            meta = (f'event.set("[lp][group_id]", {rb(leaf.gid)}); event.set("[lp][source]", {rb(leaf.source.split("|")[0])}); '
                    f'event.set("[lp][parser_version]", {int(pv)}); event.set("[lp][mapping_version]", {int(mv)})')
            blocks = []
            for v in variants:
                txt = v["native"]
                code = "\n".join(v["code"]) + "\n" + meta
                txt += ("\n" if txt else "") + ruby_filter(code)
                blocks.append(txt)
            if len(blocks) == 1:
                leaf.text = blocks[0]
            else:
                body = ruby_filter(f"LP.variant(event, {rb(conds)})") + "\n"
                for i, b in enumerate(blocks):
                    kw = "if" if i == 0 else "else if"
                    if i == len(blocks) - 1:
                        kw, cond = "else", ""
                        body += f"else {{\n{ind(b, 2)}\n}}"
                    else:
                        body += f'{kw} {S}[variant] == "{i + 1}" {{\n{ind(b, 2)}\n}} '
                # variant "1".."n" first then default "0"
                body = ruby_filter(f"LP.variant(event, {rb(conds)})") + "\n"
                chain = ""
                for i, b in enumerate(blocks[1:], 1):
                    chain += f'{"if" if i == 1 else "else if"} {S}[variant] == "{i}" {{\n{ind(b, 2)}\n}} '
                chain += f"else {{\n{ind(blocks[0], 2)}\n}}"
                leaf.text = body + chain
            leaf.native = sum(v["nnative"] for v in variants)
            leaf.ruby = sum(v["nruby"] for v in variants)
            leaf.consts = sum(v["nconst"] for v in variants)
            leaf.status, leaf.reason = "ok", ""
        except Unsupported as ex:
            leaf.status, leaf.reason = "unsupported", str(ex)

    # ---------------------------------------------------------- parser step of a root
    def parse_step(self, r: Root) -> tuple[str, str]:
        """Filter text that parses the payload of a record routed to root `r` into [f] and
        sets [pm].  Returns (text, kind)."""
        pr = r.parser
        if pr is None:
            raise Unsupported("no parser")
        kind = pr["kind"]
        post = []
        if pr.get("nested"):
            post.append(f"LP.nested(event, {rb(pr['nested'])}, @T@)")
        if pr.get("extract"):
            ex = [{"field": x["field"], "pattern": re2_to_onig(x["pattern"])} for x in pr["extract"]]
            post.append(f"LP.extract(event, {rb(ex)})")
        post.append("LP.finish(event)")
        post_rb = ruby_filter("\n".join(post))
        if kind == "regex":
            if r.fmt in ("json", "kv", "cef", "leef", "delimited") and False:
                pass
            pat = re2_to_onig(pr["pattern"], cap=lambda n: f"{S}[f][{n}]", grok=True)
            txt = (f'grok {{\n  match => {{ "{S}[payload]" => "{pat}" }}\n  tag_on_failure => [] ecs_compatibility => disabled\n  timeout_millis => 1000\n'
                   f'  add_field => {{ "[@metadata][pm]" => "1" }}\n}}')
            return txt, post_rb
        same = False
        if kind == r.fmt and kind in ("json", "cef", "leef"):
            same = True
        if kind == "kv" and r.fmt == "kv" and pr.get("dialect") == self.det_dialect(r.bucket):
            same = True
        if same:
            txt = ruby_filter('LP.from_flat(event); event.set("[@metadata][pm]", "1")')
        elif kind in ("json", "kv", "cef", "leef", "delimited"):
            a = {k: pr[k] for k in ("dialect", "delimiter", "columns", "strip") if k in pr}
            txt = ruby_filter(f'begin; LP.decode(event, {rb(kind)}, {rb(a)}, @T@); event.set("[@metadata][pm]", "1"); rescue StandardError; end')
        else:
            raise Unsupported(f"parser kind {kind}")
        return txt, post_rb

    def det_dialect(self, bucket: str) -> str | None:
        chain = bucket.split("|")[0].split(">")
        for chk in self.snap.detect:
            if chk["name"] == chain[-1] and chk["test"]["kind"] == "kv":
                return chk["test"]["dialect"]
        return None

    # ---------------------------------------------------------- distributor
    def tables(self, kind: str, roots: list) -> str:
        snap = self.snap
        t: dict = {}
        dial = {}
        for k, d in snap.dialects.items():
            d = dict(d)
            for pk in ("pair_pattern", "key_pattern"):
                if pk in d:
                    d[pk] = re2_to_onig(d[pk])
            dial[k] = d
        t["DIAL"] = dial
        if kind == "distributor":
            det = {}
            for chk in snap.detect:
                if chk["name"].startswith("ai_"):
                    continue
                c = json.loads(json.dumps(chk))
                if c["test"]["kind"] == "regex":
                    c["test"]["pattern"] = re2_to_onig(c["test"]["pattern"])
                for fld, pats in (c.get("header_patterns") or {}).items():
                    c["header_patterns"][fld] = [re2_to_onig(p) for p in pats]
                det[c["name"]] = c
            t["DET"] = det
            sign = {}
            masks = {}
            for r in roots:
                if r.fmt in ("json", "kv", "cef", "leef", "delimited"):
                    sr = snap.sign_rule(r.bucket, None)
                    sign.setdefault(r.bucket, {k: v for k, v in sr.items()})
                    if r.fmt == "kv":
                        masks[r.bucket] = [[p[1].pattern if isinstance(p[1].pattern, str) else p[1].pattern.decode(),
                                            p[2], p[3]] for p in snap.mask_patterns(r.bucket, None)]
                        masks[r.bucket] = [[re2_to_onig(a), b, c] for a, b, c in masks[r.bucket]]
            sign["*"] = {"keys": "auto", "discriminators": [], "depth": 1}
            t["SIGN"] = sign
            t["MASKS"] = masks
            t["PROT"] = sorted(snap.protected)
        else:
            t["CAPS"] = self.caps_table()
        return t

    def caps_table(self) -> dict:
        out = {}
        for cname, tops in self.caps_need.items():
            c = self.schema.cls(cname)
            attrs = c["attributes"]
            d = {}
            for k in sorted(tops):
                a = attrs.get(k)
                if a and a.get("enum") and a.get("sibling") and a["sibling"] in attrs:
                    d[k] = {"sibling": a["sibling"], "enum": {kk: v.get("caption") for kk, v in a["enum"].items()}}
            out[cname] = d
        return out

    inline_lib = False

    def init_text(self, tid: str, table: dict) -> str:
        """Code of the first ruby filter of a pipeline: load the shared library and the tables of this pipeline.
        Tables (detect rules, dialects, mask patterns, caption enums) live in a JSON file next to the config,
        so the config text stays small."""
        lib = RUBY_LIB if self.inline_lib else 'require "@LPLIB@"'
        self.tables_out[tid] = json.dumps(table, ensure_ascii=False)
        return (lib + f"\nLP.tz = {rb(self.tz)}\n"
                f'T_{tid} = JSON.parse(File.read("@DIR@/tables_{tid}.json"))\n')

    # ---------------------------------------------------------- distributor filter
    def distributor_filter(self, routes: dict, roots: list) -> str:
        # detection rules added by the agent are fallbacks scoped by line shape, with time_format/tz: the
        # export does not reproduce that, so it leaves them out (their lines stay unread in Logstash) and says so
        self.not_exported = [c["name"] for c in self.snap.detect if c["name"].startswith("ai_")]
        snap = self.snap
        tbl = self.tables("distributor", roots)
        T = "T_dist"
        p = [ruby_filter("nil", init=self.init_text("dist", tbl).replace("T_dist", "T_dist")),
             f'mutate {{ add_field => {{ "{S}[chain]" => ">" }} }}',
             f'mutate {{ copy => {{ "message" => "{S}[payload]" }} }}']
        for lvl in range(5):
            for chk in snap.detect:
                if chk["name"].startswith("ai_"):
                    continue
                t = chk["test"]
                kind = t["kind"]
                if kind == "binary":
                    continue
                name = chk["name"]
                cond = f"![@metadata][s][done] and ![@metadata][s][hit]"
                if lvl > 0:
                    cond += f' and ">{name}>" not in {S}[chain]'
                if kind == "regex":
                    pat = re2_to_onig(t["pattern"], cap=lambda n: f"{S}[c][{n}]", grok=True)
                    body = (f'grok {{\n  match => {{ "{S}[payload]" => "{pat}" }}\n  keep_empty_captures => true\n'
                            f'  tag_on_failure => [] ecs_compatibility => disabled\n  timeout_millis => 1000\n  add_field => {{ "{S}[hit]" => "{name}" }}\n}}')
                elif kind == "json":
                    pat = r'\A\s*\{\s*(?:\}(?:.*\})?|\x22.*\})\s*\z'
                    body = (f'grok {{\n  match => {{ "{S}[payload]" => "{pat}" }}\n  tag_on_failure => [] ecs_compatibility => disabled\n  timeout_millis => 1000\n'
                            f'  add_field => {{ "{S}[hit]" => "{name}" }}\n}}')
                elif kind == "xml":
                    pat = r'\A\s*<[A-Za-z?!].*>\s*\z'
                    body = (f'grok {{\n  match => {{ "{S}[payload]" => "{pat}" }}\n  tag_on_failure => [] ecs_compatibility => disabled\n  timeout_millis => 1000\n'
                            f'  add_field => {{ "{S}[hit]" => "{name}" }}\n}}')
                elif kind == "always":
                    body = f'mutate {{ add_field => {{ "{S}[hit]" => "{name}" }} }}'
                elif kind == "kv":
                    body = ruby_filter(f'LP.kv_test(event, {rb(name)}, {T})')
                elif kind == "delimited":
                    body = ruby_filter(f'LP.delim_test(event, {rb(name)}, {T})')
                elif kind == "json_wrap":
                    body = ruby_filter(f'LP.jwrap_test(event, {rb(name)}, {T})')
                else:
                    raise Unsupported(f"detect kind {kind}")
                p.append(f"if {cond} {{\n{ind(body, 2)}\n}}")
            p.append(f"if ![@metadata][s][done] {{\n{ind(ruby_filter(f'LP.post(event, {lvl}, {T})'), 2)}\n}}")
        p.append(ruby_filter(f"LP.bucket(event, {T})"))
        p.append(f'if {S}[fmt] == "json" {{\n  json {{ source => "{S}[payload]" target => "{S}[j]" tag_on_failure => [] ecs_compatibility => disabled }}\n}}')
        p.append(f'if {S}[fmt] != "unstructured" {{\n{ind(ruby_filter(f"LP.sign(event, {T})"), 2)}\n}}')
        dic = " ".join(f'"{k}" => "{v}"' for k, v in sorted(routes.items()))
        if dic:
            p.append(f'translate {{ source => "[@metadata][s][rkey]" target => "[@metadata][dest]" dictionary => {{ {dic} }} }}')
        p.append('if ![@metadata][dest] {\n  mutate { add_tag => ["lp_unparsed"] add_field => { "[lp][reason]" => "no_route" } }\n}')
        return "\n".join(p)

    # ---------------------------------------------------------- source pipeline filter
    def source_filter(self, slug: str, roots: list, include: set | None) -> tuple[str, dict]:
        T = f"T_src_{slug}"
        tbl = self.tables("source", roots)
        # unstructured buckets: cascade; structured: one block per root
        blocks: list = []
        by_bucket: dict[str, list] = {}
        for r in roots:
            if r.fmt == "unstructured":
                by_bucket.setdefault(r.bucket, []).append(r)
            else:
                blocks.append((r, self.root_block(r, T, include)))
        ub = []
        for bucket in by_bucket:
            if self.direct:
                ub.append((bucket, self.direct_bucket(by_bucket[bucket])))
                continue
            clusters = self.plans.get(bucket) or []
            if not clusters:
                continue
            seq, disp = [], []
            for i, cl in enumerate(clusters):
                r0 = cl["roots"][0][0]
                pt, _post = self.parse_step(r0)
                pt = pt.replace('"[@metadata][pm]" => "1"', f'"[@metadata][pm]" => "{i}"')
                seq.append(pt if not seq else f"if ![@metadata][pm] {{\n{ind(pt, 2)}\n}}")
                inner = []
                for j, (r, conds) in enumerate(cl["roots"]):
                    _pt, post = self.parse_step(r)
                    body = self.root_inner(r, T, post)
                    if len(cl["roots"]) == 1:
                        inner.append(body)
                    else:
                        c = " and ".join(f"{fref(f)} == {cstr(v)}" for f, v in conds)
                        inner.append(f'{"if" if j == 0 else "else if"} {c} {{\n{ind(body, 2)}\n}}')
                if len(cl["roots"]) > 1:
                    inner.append('else {\n  mutate { add_field => { "[lp][reason]" => "unknown_variant" } }\n}')
                disp.append((i, "\n".join(inner)))
            body = "\n".join(seq) + "\n"
            for j, (i, inner) in enumerate(disp):
                body += f'{"if" if j == 0 else "else if"} [@metadata][pm] == "{i}" {{\n{ind(inner, 2)}\n}} '
            body += '\nif ![@metadata][pm] {\n  mutate { add_field => { "[lp][reason]" => "parse_failed" } }\n}'
            ub.append((bucket, body))
        txt = [ruby_filter("nil", init=self.init_text(f"src_{slug}", tbl))]
        first = True
        for r, b in blocks:
            if b is None:
                continue
            cond = " or ".join(f'[@metadata][s][rkey] == "{k}"' for k in r.rkeys)
            txt.append(f'{"if" if first else "else if"} {cond} {{\n{ind(b, 2)}\n}}')
            first = False
        for bucket, b in ub:
            txt.append(f'{"if" if first else "else if"} [@metadata][s][rkey] == "{dig(bucket)}" {{\n{ind(b, 2)}\n}}')
            first = False
        return "\n".join(txt).replace("@T@", T), tbl

    # ---------------------------------------------------------- unstructured buckets: cascade plan
    def root_samples(self, r: Root) -> list:
        """(payload, fields) of the stored samples of a root and its children that detect into the root's bucket."""
        from . import parsers
        from .detect import detect
        from .formats import ParseError
        out, seen = [], set()
        sigs = [r.sig] + [g["signature"] for _l, g in r.leaves]
        for sig in dict.fromkeys(sigs):
            g = self.e.groups.get(sig)
            if g is None:
                continue
            extra = [(0, r["raw"], "", None) for r in self.e.store.raw_by_signature(sig, 300) if r.get("raw")]
            for _rid, raw, _tag, _m in list(self.e._samples(g)[:40]) + extra:
                if raw in seen:
                    continue
                seen.add(raw)
                det = detect(self.snap, raw)
                if det.bucket != r.bucket:
                    continue
                try:
                    out.append((det.payload, parsers.run(self.snap, r.parser, det)))
                except ParseError:
                    continue
        return out

    def plan_bucket(self, bucket: str, rs: list) -> list:
        """Order the regex parsers of an unstructured bucket and separate groups that share one pattern.

        The engine routes by masked template; Logstash has only the parser.  Two groups with the same
        pattern are told apart by a field value that is constant in each group's samples and differs
        between the groups.  A parser that would also match the samples of another group goes after it."""
        from . import rx
        clusters: dict = {}
        for r in rs:
            clusters.setdefault(r.parser["pattern"], []).append(r)
        samples = {r.sig: self.root_samples(r) for r in rs}
        plan = []
        for pat, members in clusters.items():
            entries = []
            if len(members) == 1:
                entries = [(members[0], [])]
            else:
                for r in members:
                    mine = samples[r.sig]
                    others = [f for o in members if o is not r for _p, f in samples[o.sig]]
                    conds = []
                    if mine:
                        keys = [k for k in mine[0][1] if not k.startswith("@")
                                and all(f.get(k) == mine[0][1][k] for _p, f in mine)]
                        remaining = list(others)
                        while remaining and keys:
                            best = max(keys, key=lambda k: sum(1 for f in remaining if f.get(k) != mine[0][1][k]))
                            gain = [f for f in remaining if f.get(best) != mine[0][1][best]]
                            if not gain:
                                break
                            conds.append((best, str(mine[0][1][best])))
                            keys.remove(best)
                            remaining = [f for f in remaining if f.get(best) == mine[0][1][best]]
                        if remaining:
                            conds = None
                    else:
                        conds = None
                    try:
                        if conds is not None:
                            for _f, v in conds:
                                cstr(v)
                    except Unsupported:
                        conds = None
                    if not conds:
                        for leaf, _g in r.leaves:
                            if leaf.status == "ok":
                                leaf.status, leaf.reason = "unsupported", "same pattern as another group and no field value tells them apart"
                                leaf.included = False
                        continue
                    entries.append((r, conds))
            if entries:
                pays = [p for r, _c in entries for p, _f in samples[r.sig]]
                plan.append({"pattern": pat, "roots": entries, "payloads": pays, "spec": self.specificity(entries[0][0])})
        # a parser goes after every parser whose group samples it would also match
        compiled = {c["pattern"]: rx.compile(c["pattern"]) for c in plan}
        before: dict = {id(c): set() for c in plan}
        for a in plan:
            for b in plan:
                if a is b:
                    continue
                if any(compiled[b["pattern"]].search(p) for p in a["payloads"]):
                    before[id(b)].add(id(a))        # a must come before b
        ordered, placed = [], set()
        pending = sorted(plan, key=lambda c: (-c["spec"], c["pattern"]))
        while pending:
            pick = next((c for c in pending if before[id(c)] <= placed), pending[0])
            ordered.append(pick)
            placed.add(id(pick))
            pending.remove(pick)
        return ordered

    def specificity(self, r: Root) -> int:
        pat = (r.parser or {}).get("pattern", "")
        lit = re.sub(r"\(\?P<[^>]+>(?:[^()\\]|\\.)*\)|\[(?:[^\]\\]|\\.)*\]|\\.|[*+?{}()|^$]", "", pat)
        return len(lit)

    def root_inner(self, r: Root, T: str, post: str) -> str:
        """After a successful parse: post-processing, split selection, leaf mappings."""
        out = [post]
        leaves = [(l, g) for l, g in r.leaves if l.status == "ok" and l.included]
        if r.split:
            out.append(ruby_filter(f"LP.split_key(event, {rb(list(r.split.get('fields') or []))}, "
                                   f"{rb(list(r.split.get('presence') or []))})"))
            first = True
            for l, g in leaves:
                out.append(f'{"if" if first else "else if"} {S}[child] == "{l.cond_key}" {{\n{ind(l.text, 2)}\n}}')
                first = False
            if not first:
                out.append('else {\n  mutate { add_field => { "[lp][reason]" => "unknown_split" } }\n}')
            else:
                out.append('mutate { add_field => { "[lp][reason]" => "group_not_in_pipeline" } }')
        else:
            if leaves:
                out.append(leaves[0][0].text)
            else:
                out.append('mutate { add_field => { "[lp][reason]" => "group_not_in_pipeline" } }')
        return "\n".join(out)

    def root_block(self, r: Root, T: str, include) -> str | None:
        if self.direct:
            return self.direct_block(r)
        try:
            pt, post = self.parse_step(r)
        except Unsupported:
            return None
        inner = self.root_inner(r, T, post)
        return (pt + "\n" + f'if [@metadata][pm] {{\n{ind(inner, 2)}\n}} else {{\n'
                '  mutate { add_field => { "[lp][reason]" => "parse_failed" } }\n}')

    # ---------------------------------------------------------- everything
    def compile(self, include: set | None = None, *, tag: str = "") -> Generated:
        for leaf in self.leaves.values():
            leaf.included = False
        for r in self.roots.values():
            try:
                r.rkey = self.root_key(r)
                r.rkeys = [r.rkey] + (self.alias_keys(r) if r.fmt != "unstructured" else [])
                r.reason, r.status = "", "ok"
            except Unsupported as ex:
                r.status, r.reason = "unsupported", str(ex)
        # compile leaves
        for r in self.roots.values():
            for leaf, g in r.leaves:
                if r.status != "ok":
                    leaf.status, leaf.reason = "unsupported", r.reason
                    continue
                if not self.direct and r.fmt == "unstructured" and (r.parser is None or r.parser["kind"] != "regex"):
                    leaf.status, leaf.reason = "unsupported", "unstructured group without a regex parser"
                    continue
                self.compile_leaf(leaf, g, r)
                if r.split:
                    key = (g["detail"].get("split_key"))
                    parts = []
                    leaf.cond_key = None
                    if key is not None:
                        # the key text the engine built is the digest input of LP.split_key
                        leaf.cond_key = dig(key)
                if leaf.status == "ok":
                    leaf.included = include is None or leaf.gid in include
            # an unstructured root with unsupported parser kinds is also excluded
        self.plans = {}
        ub: dict[str, list] = {}
        for r in self.roots.values():
            if not self.direct and r.fmt == "unstructured" and r.status == "ok" and r.parser and r.parser["kind"] == "regex" \
                    and any(l.included for l, _ in r.leaves):
                ub.setdefault(r.bucket, []).append(r)
        for bucket, rs in ub.items():
            self.plans[bucket] = self.plan_bucket(bucket, rs)
        by_slug: dict[str, list] = {}
        for r in self.roots.values():
            if r.status == "ok" and any(l.included for l, _ in r.leaves):
                by_slug.setdefault(r.slug, []).append(r)
        routes: dict[str, str] = {}
        for slug, rs in by_slug.items():
            for r in rs:
                for key in ([dig(r.bucket)] if r.fmt == "unstructured" else r.rkeys):
                    routes[key] = "src_" + slug
        files: dict[str, str] = {}
        self.tables_out = {}
        all_roots = [r for r in self.roots.values() if r.status == "ok" and any(l.included for l, _ in r.leaves)]
        srcs: dict[str, str] = {}
        for slug, rs in sorted(by_slug.items()):
            ftxt, _ = self.source_filter(slug, rs, include)
            srcs[slug] = ftxt
        dist = self.distributor_filter(routes, all_roots)
        stats = {"sources": len(srcs), "roots": len(all_roots),
                 "leaves": sum(1 for l in self.leaves.values() if l.included),
                 "agent_detection_rules_not_exported": getattr(self, "not_exported", [])}
        return Generated({"distributor.filter": dist, **{f"src_{s}.filter": t for s, t in srcs.items()},
                          **{f"tables_{k}.json": v for k, v in self.tables_out.items()}},
                         ["distributor"] + [f"src_{s}" for s in sorted(srcs)] + ["sink"], self.leaves, self.roots, stats)


# the Leaf dataclass gets a plain attribute at compile time
Leaf.included = False
Leaf.extract = ""


# =================================================================== assembling files
def _read_sink_template(root: str, name: str = "output-clickhouse.conf") -> str:
    path = os.path.join(root, "deploy", "logstash", name)
    with open(path) as fh:
        return fh.read()


def kafka_io(bootstrap: str, topics: list, group_id: str, parsed_topic: str, root: str, extra: dict | None = None,
             failed_topic: str | None = None):
    """Input and sink for the learning service: read the unparsed (and replay) topics, write each parsed
    OCSF event, flattened to the ClickHouse columns, as JSON to the parsed topic. Lines no compiled group
    parses are dropped here: the learner reads the unparsed topic itself."""
    q = lambda v: json.dumps(str(v))
    ex = "".join(f"\n  {k} => {q(v)}" for k, v in (extra or {}).items())
    # the unparsed topic from the latest offset (the learner holds the lines that came before); the replay
    # topic from the earliest, under its own group: its lines are sent when a format is deployed, before
    # Logstash may have read it at all
    def one(tops, group, reset):
        return (f"kafka {{\n  bootstrap_servers => {q(bootstrap)}\n  topics => {json.dumps(tops)}\n  group_id => {q(group)}"
                f"\n  codec => plain {{ charset => \"UTF-8\" }}\n  consumer_threads => 2\n  auto_offset_reset => {q(reset)}{ex}\n}}")
    inp = one(topics[:1], group_id, "latest") + ("\n" + one(topics[1:], group_id + "-replay", "earliest") if topics[1:] else "")
    ch = _read_sink_template(root)
    flatten = ch[ch.index("filter {"):ch.index("\noutput {")]
    sink = (flatten + "\nfilter {\n  if !(\"lp_unparsed\" in [tags]) {\n    ruby { code => 'event.set(\"valid\", 1); "
            "event.set(\"ingest_id\", \"logstash\")' }\n  }\n}\n"
            f"output {{\n  if !(\"lp_unparsed\" in [tags]) {{\n    kafka {{\n      bootstrap_servers => {q(bootstrap)}\n"
            f"      topic_id => {q(parsed_topic)}\n      codec => json\n      compression_type => \"lz4\"{ex.replace(chr(10), chr(10) + '    ')}\n    }}\n  }}\n}}\n")
    if failed_topic:
        # lines a deployed format's pipeline failed on (parse or time): the drift signal on the Logstash side.
        # Lines with no route at all are not sent: the learner reads every unparsed line itself.
        sink += ("filter {\n  if \"lp_unparsed\" in [tags] and [lp][pipeline] {\n    ruby { code => '"
                 "event.set(\"[@metadata][fail]\", {\"message\" => event.get(\"message\").to_s[0, 8000], "
                 "\"reason\" => event.get(\"[lp][reason]\").to_s, \"pipeline\" => event.get(\"[lp][pipeline]\").to_s, "
                 "\"lp_group_id\" => event.get(\"[lp][group_id]\").to_s, "
                 "\"at\" => Time.now.utc.strftime(\"%Y-%m-%d %H:%M:%S.%L\")}.to_json)' }\n  }\n}\n"
                 f"output {{\n  if \"lp_unparsed\" in [tags] and [lp][pipeline] {{\n    kafka {{\n"
                 f"      bootstrap_servers => {q(bootstrap)}\n      topic_id => {q(failed_topic)}\n"
                 f"      codec => plain {{ format => \"%{{[@metadata][fail]}}\" }}{ex.replace(chr(10), chr(10) + '    ')}\n    }}\n  }}\n}}\n")
    return inp, sink


def write_set(gen: Generated, out_dir: str, *, root: str, test: dict | None = None, workers: int = 1,
              dist_workers: int = 2, heap: str = "2g", io: tuple | None = None) -> dict:
    """Write distributor.conf, src_*.conf, sink.conf and pipelines.yml.

    Production: http input on 8088 and the ClickHouse sink template.  `test` (a dict with
    `input` and `output` paths) swaps them for a file input (JSON lines with `id` and `message`)
    and a json_lines file output, so the harness can run the same pipelines without ClickHouse."""
    os.makedirs(out_dir, exist_ok=True)
    out_dir = os.path.abspath(out_dir)
    for f in os.listdir(out_dir):
        if f.endswith(".conf") or f == "pipelines.yml" or (f.startswith("tables_") and f.endswith(".json")):
            os.remove(os.path.join(out_dir, f))
    routes = {}
    dist_text = gen.files["distributor.filter"]
    # destinations: parse the translate dictionary back out of the compiled text is fragile; read it from stats
    slugs = [p for p in gen.pipelines if p.startswith("src_")]
    if test:
        inp = (f'file {{\n  path => "{test["input"]}"\n  mode => "read"\n  codec => "json"\n  sincedb_path => "/dev/null"\n'
               f'  file_completed_action => "log"\n  file_completed_log_path => "{test["input"]}.done"\n}}')
    elif io:
        inp = io[0]                     # e.g. kafka_io(): the service's topics
    else:
        inp = 'http {\n  port => 8088\n  codec => line\n}'
    outs = "".join(f'  if [@metadata][dest] == "{s}" {{\n    pipeline {{ send_to => ["{s}"] }}\n  }} else ' for s in slugs)
    outs += '{\n    pipeline { send_to => ["sink"] }\n  }'
    dist = f"input {{\n{ind(inp, 2)}\n}}\nfilter {{\n{ind(dist_text, 2)}\n}}\noutput {{\n{outs}\n}}\n"
    files = {"distributor.conf": dist}
    lib_path = os.path.join(out_dir, "lp_lib.rb")
    with open(lib_path, "w") as fh:
        fh.write(RUBY_LIB)
    for s in slugs:
        files[s + ".conf"] = (f'input {{ pipeline {{ address => "{s}" }} }}\nfilter {{\n{ind(gen.files[s + ".filter"], 2)}\n'
                              '  if ![lp][group_id] {\n    if ![lp][reason] {\n      mutate { add_field => { "[lp][reason]" => "no_group_matched" } }\n    }\n'
                              f'    mutate {{ add_tag => ["lp_unparsed"] remove_field => ["[ocsf]"] add_field => {{ "[lp][pipeline]" => "{s}" }} }}\n  }}\n}}\n'
                              'output { pipeline { send_to => ["sink"] } }\n')
    if test:
        files["sink.conf"] = ('input { pipeline { address => "sink" } }\n'
                              f'output {{ file {{ path => "{test["output"]}" codec => json_lines }} }}\n')
    elif io:
        files["sink.conf"] = 'input { pipeline { address => "sink" } }\n' + io[1]
    else:
        files["sink.conf"] = 'input { pipeline { address => "sink" } }\n' + _read_sink_template(root)
    y = []
    for pid in gen.pipelines:
        w = dist_workers if pid == "distributor" else workers
        y.append(f'- pipeline.id: {pid}\n  path.config: "{os.path.join(out_dir, pid + ".conf")}"\n  pipeline.workers: {w}\n  pipeline.ordered: false\n')
    files["pipelines.yml"] = "".join(y)
    for name, text in files.items():
        with open(os.path.join(out_dir, name), "w") as fh:
            fh.write(text.replace("@LPLIB@", lib_path).replace("@DIR@", out_dir))
    for name, text in gen.files.items():
        if name.endswith(".json"):
            with open(os.path.join(out_dir, name), "w") as fh:
                fh.write(text)
    # settings so `logstash --path.settings <dir>` works and reloads config on change
    brew = "/opt/homebrew/Cellar/logstash"
    for name in ("jvm.options", "log4j2.properties"):
        dst = os.path.join(out_dir, name)
        if os.path.isdir(brew) and not os.path.exists(dst):
            for ver in sorted(os.listdir(brew)):
                src = os.path.join(brew, ver, "libexec", "config", name)
                if os.path.exists(src):
                    with open(src) as a, open(dst, "w") as b:
                        txt = a.read()
                        if name == "jvm.options":      # many pipelines with large configs need more than 1g
                            txt = re.sub(r"(?m)^-Xms\S+", f"-Xms{heap}", txt)
                            txt = re.sub(r"(?m)^-Xmx\S+", f"-Xmx{heap}", txt)
                        b.write(txt)
    with open(os.path.join(out_dir, "logstash.yml"), "w") as fh:
        fh.write(f'path.data: "{os.path.join(out_dir, "data")}"\npath.logs: "{os.path.join(out_dir, "logs")}"\n'
                 'config.reload.automatic: true\nconfig.reload.interval: 10s\napi.enabled: false\n')
    return files


def compile_pipeline(engine, include_groups=None) -> str:
    """The whole compiled set as ONE filter section (for tests and single-pipeline use): the
    distributor's detection and routing, then each source's filter under its route.  Production
    uses `Compiler(...).compile()` + `write_set()` (one pipeline per source)."""
    comp = Compiler(engine)
    comp.inline_lib = True
    gen = comp.compile(None if include_groups is None else set(include_groups))
    parts = [gen.files["distributor.filter"]]
    for k, v in gen.files.items():
        if k.startswith("src_"):
            slug = k[:-7]
            parts.append(f'if [@metadata][dest] == "{slug}" {{\n{ind(v, 2)}\n}}')
    return "\n".join(parts)


def wrap_io(filter_text: str, input_conf: str, output_conf: str) -> str:
    return f"input {{\n{ind(input_conf, 2)}\n}}\nfilter {{\n{ind(filter_text, 2)}\n}}\noutput {{\n{ind(output_conf, 2)}\n}}\n"
