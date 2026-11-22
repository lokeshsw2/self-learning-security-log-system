"""The deterministic pipeline. No AI is called from this module.

Per record: detect -> bucket -> signature -> group lookup -> parse ->
normalise -> OCSF map -> validate. Per batch: thresholds and queues,
near-duplicate merge, explosion guard, long-tail timeouts, then one
transaction that writes the batch state and the read offset together.
"""
from __future__ import annotations

import hashlib
import json
import time

from drain3 import TemplateMiner
from drain3.template_miner_config import TemplateMinerConfig

from . import ocsf, parsers, registry, signature
from .config import Settings
from .detect import Detection, detect
from .formats import ParseError
from .reader import FileSource, Framer, Record
from .store import SqliteStore, _j

STRUCTURED = ("json", "kv", "cef", "leef", "delimited", "xml")
DEFAULT_MAPPING = "mapping:default-base"
MAX_SOURCES_PER_LABEL = 2000


def _tokens(text: str) -> set:
    return set(text.split()[:400])


class Engine:
    def __init__(self, store: SqliteStore, settings: Settings | None = None, schema: ocsf.Schema | None = None,
                 now: float | None = None):
        self.store = store
        self.settings = settings or Settings()
        self.schema = schema or ocsf.Schema()
        self.now = now                      # fixed clock for tests and replay; None = wall clock
        self.snap = registry.Snapshot(store)
        self.batch_no = int(store.get_state("batch", 0))
        self.groups: dict = {}
        self.alias: dict = {}
        self.by_bucket: dict = {}
        self.merged_index: dict = {}
        self.sources: dict = {}
        self.source_sigs: dict = {}
        self.label_sources: dict = {}
        self.columns: dict = store.get_state("columns", {})
        self._resolved: dict = {}
        self._dirty_groups: set = set()
        self._dirty_samples: set = set()
        self._dirty_sources: set = set()
        self._new_unstructured: set = set()
        self._queue_ops: list = []
        self._new_sigs: list = []           # (signature, group id) rows to persist
        from .family import Families
        self.families = Families(store, self.settings.family_threshold)
        self._dirty_stats: set = set()
        self._load()

    # ------------------------------------------------------------ state
    def _load(self) -> None:
        for g in self.store.groups():
            g["_samples"] = None
            g["_tokens"] = None
            self.groups[g["signature"]] = g
            g["_stats"] = None
            if g["merged_into"]:
                self.alias[g["signature"]] = g["merged_into"]
            else:
                self.by_bucket.setdefault(g["bucket"], []).append(g["signature"])
                self.source_sigs.setdefault(g["source"], set()).add(g["signature"])
                if g["format"] == "unstructured" and "<*>" in g["template"] and not g["detail"].get("parent"):
                    toks = g["template"].split()
                    self.merged_index.setdefault((g["bucket"], len(toks)), []).append((toks, g["signature"]))
        for sig, gid in self.store.signature_map().items():
            if sig != gid:
                self.alias[sig] = gid
        for s in self.store.sources():
            self.sources[s["source"]] = s
            self.label_sources.setdefault(s["source"].split("|", 1)[0], set()).add(s["source"])

    def reload(self) -> None:
        gen = int(self.store.get_state("registry_generation", 0))
        if gen != self.snap.generation:
            self.snap = registry.Snapshot(self.store)
            self._resolved = {}

    def _clock(self) -> float:
        return self.now if self.now is not None else time.time()

    def canonical(self, sig: str) -> dict | None:
        seen = 0
        while sig in self.alias and seen < 8:
            sig = self.alias[sig]
            seen += 1
        return self.groups.get(sig)

    def _link(self, sig: str, gid: str) -> None:
        """Point a signature at a group. Many signatures can lead to one group."""
        if sig != gid:
            self.alias[sig] = gid
        self._new_sigs.append((sig, gid))

    def _samples(self, g: dict) -> list:
        if g["_samples"] is None:
            g["_samples"] = [(r["raw_id"], r["raw"], r["tag"], r["masked"])
                             for r in self.store.samples(g["signature"], tags=True)]
            toks = set()
            for smp in g["_samples"]:
                toks |= _tokens(smp[1])
            g["_tokens"] = toks
        return g["_samples"]

    def _source(self, key: str) -> dict:
        s = self.sources.get(key)
        if s is None:
            s = self.store.source(key)
            self.sources[key] = s
        return s

    # ------------------------------------------------------------ directives
    def _directive(self, rec: Record) -> bool:
        from . import rx
        for d in self.snap.directives:
            m = rx.compile(d["pattern"]).search(rec.text)
            if m:
                cols = [c.strip() for c in m.group("fields").split(d["field_sep"]) if c.strip()]
                self.columns[rec.stream] = {"columns": cols, "delimiter": d["delimiter"]}
                return True
        return any(d.get("drop_pattern") and rx.compile(d["drop_pattern"]).search(rec.text)
                   for d in self.snap.directives)

    # ------------------------------------------------------------ groups
    def _new_group(self, sig: str, det: Detection, sg: signature.Signed, source: str,
                   columns: list | None = None) -> dict:
        g = {"signature": sig, "bucket": det.bucket, "source": source, "format": det.format,
             "template": sg.template, "detail": dict(sg.detail), "count": 0,
             "first_batch": self.batch_no, "last_batch": self.batch_no, "status": "new",
             "parser_rule": None, "mapping_rule": None, "merged_into": None, "drift_of": None,
             "labels": {}, "parse_failures": 0, "_samples": [], "_tokens": set(), "_stats": {}}
        if det.dialect:
            g["detail"]["dialect"] = det.dialect
        if det.delimiter:
            g["detail"]["delimiter"] = det.delimiter
        if columns:
            g["detail"]["columns"] = list(columns)
        self.groups[sig] = g
        self._dirty_groups.add(sig)
        return g

    def _register(self, g: dict) -> None:
        self.by_bucket.setdefault(g["bucket"], []).append(g["signature"])
        self.source_sigs.setdefault(g["source"], set()).add(g["signature"])

    def _lookup(self, sg: signature.Signed, det: Detection, source: str, fields: dict | None,
                columns: list | None) -> dict:
        sig = sg.signature
        g = self.canonical(sig)
        if g is not None:
            return g
        if det.format == "unstructured":
            toks = sg.template.split()
            for mtoks, msig in self.merged_index.get((det.bucket, len(toks)), ()):
                if all(a == "<*>" or a == b for a, b in zip(mtoks, toks)):
                    self._link(sig, msig)
                    return self.groups[msig]
        elif sg.detail.get("sig_keys") and det.format in ("json", "kv", "xml"):
            keys = set(sg.detail["sig_keys"])
            disc = sg.detail.get("discriminators")
            best, best_j = None, 0.0
            for other_sig in self.by_bucket.get(det.bucket, ()):
                o = self.groups[other_sig]
                if o["format"] != det.format or o["detail"].get("discriminators") != disc \
                        or o["detail"].get("text", "") != sg.detail.get("text", ""):
                    continue
                ok = set(o["detail"].get("sig_keys") or ())
                if not ok:
                    continue
                j = len(keys & ok) / len(keys | ok)
                if j > best_j:
                    best, best_j = o, j
            if best is not None and best_j >= self.settings.drift_overlap:
                # format drift: a new signature of the same group, not a new group
                self._link(sig, best["signature"])
                best["detail"]["drift_signatures"] = best["detail"].get("drift_signatures", 0) + 1
                return best
        if det.format == "unstructured":
            sib = self._sibling(det, sg)
            if sib is not None:
                self._link(sig, sib["signature"])
                return sib
        g = self._new_group(sig, det, sg, source, columns)
        self._register(g)
        self._link(sig, sig)
        if det.format == "unstructured":
            self._new_unstructured.add(det.bucket)
        self._bind(g, det, sg, fields, columns)
        return g

    def _sibling(self, det: Detection, sg: signature.Signed) -> dict | None:
        """A new unstructured signature that an existing group's parser already
        matches, and whose template differs from that group's in at most two
        tokens, is the same template with an unmasked variable. Checked once
        per new signature, never per event."""
        from . import rx
        toks = sg.template.split()
        for other_sig in self.by_bucket.get(det.bucket, ()):
            o = self.groups[other_sig]
            if o["format"] != "unstructured" or not o["parser_rule"] or o["parser_rule"].startswith("parser:seed-") \
                    or o["detail"].get("parent"):
                continue
            otoks = o["template"].split()
            if len(otoks) != len(toks) or sum(1 for a, b in zip(toks, otoks) if a != b) > 2:
                continue
            r = self.snap.rule(o["parser_rule"])
            if r and r["body"]["kind"] == "regex" and rx.compile(r["body"]["pattern"]).search(det.payload):
                return o
        return None

    # ------------------------------------------------------------ group splits
    def split_key(self, g: dict, det: Detection) -> str | None:
        """Sub-group key for a record of a group that has a `split:` rule."""
        r = self.snap.rule("split:" + g["signature"])
        pr = self.snap.rule(g["parser_rule"])
        if not r or not pr:
            return None
        try:
            fields = parsers.run(self.snap, pr["body"], det)
        except ParseError:
            return "~unparsed"
        parts = [f"{f}={str(fields.get(f, ''))[:80]}" for f in r["body"].get("fields") or []]
        parts += [f"has:{k}={'0' if fields.get(k) in (None, '') else '1'}" for k in r["body"].get("presence") or []]
        return " ".join(parts)

    def _subgroup(self, g: dict, det: Detection) -> dict:
        """Route a record of a split group to its child group (created on first sight).
        The split is scoped to this one group: no other group's signature changes."""
        key = self.split_key(g, det)
        if key is None:
            return g
        csig = signature._h(g["signature"], "split", key)
        child = self.groups.get(csig)
        if child is None:
            detail = {"parent": g["signature"], "split_key": key}
            detail.update({k: g["detail"][k] for k in ("dialect", "delimiter", "columns") if k in g["detail"]})
            child = {"signature": csig, "bucket": g["bucket"], "source": g["source"], "format": g["format"],
                     "template": (g["template"][:3000] + " :: split " + key), "detail": detail, "count": 0,
                     "first_batch": self.batch_no, "last_batch": self.batch_no,
                     "status": "mapped" if g["mapping_rule"] else "parsed",
                     "parser_rule": g["parser_rule"], "mapping_rule": g["mapping_rule"], "merged_into": None,
                     "drift_of": None, "labels": dict(g["labels"]), "parse_failures": 0,
                     "_samples": [], "_tokens": set(), "_stats": {}}
            self.groups[csig] = child
            self._register(child)
            self._dirty_groups.add(csig)
        return child

    def children(self, sig: str) -> list:
        return [g for g in self.groups.values() if g["detail"].get("parent") == sig]

    def resplit(self, sig: str) -> list:
        """Apply (or re-apply) the split rule of a group to its stored lines."""
        self.reload()
        parent = self.groups[sig]
        old = self.children(sig)
        rows = self.store.raw_by_signature(sig)
        for k in old:
            rows += self.store.raw_by_signature(k["signature"])
        self.store.begin()
        try:
            for k in old:
                self.store.x("UPDATE raw SET signature=? WHERE signature=?", (sig, k["signature"]))
                self.store.x("UPDATE events SET signature=? WHERE signature=?", (sig, k["signature"]))
                self.store.x("DELETE FROM groups WHERE signature=?", (k["signature"],))
                self.store.x("DELETE FROM samples WHERE signature=?", (k["signature"],))
                self.store.x("DELETE FROM queue WHERE key=?", (k["signature"],))
            self.store.commit()
        except Exception:
            self.store.rollback()
            raise
        for k in old:
            self.groups.pop(k["signature"], None)
            if k["signature"] in self.by_bucket.get(k["bucket"], ()):
                self.by_bucket[k["bucket"]].remove(k["signature"])
            self.source_sigs.get(k["source"], set()).discard(k["signature"])
        upd, kids = [], {}
        for r in rows:
            if r["raw"] is None:
                continue
            label = r["source"].split("|", 1)[0]
            rec = Record(r["stream"], r["offset"], text=r["raw"], label=None if label == "-" else label,
                         columns=self._header_of(parent))
            det, _, _ = self.analyse(rec)
            child = self._subgroup(parent, det)
            if child is parent:
                continue
            child["count"] += 1
            child["last_batch"] = self.batch_no
            self._sample(child, r["id"], r["raw"])
            kids[child["signature"]] = child
            upd.append((child["signature"], r["status"], r["source"], r["id"]))
        if kids:
            parent["status"] = "split"
            parent["count"] = 0
        elif parent["status"] == "split":
            parent["status"] = "mapped" if parent["mapping_rule"] else "parsed"
            parent["count"] = len(rows)
        self._dirty_groups.add(sig)
        self.store.begin()
        try:
            self.store.update_raw(upd)
            self._flush()
            self.store.commit()
        except Exception:
            self.store.rollback()
            raise
        self.replay_signatures(list(kids) or [sig])
        return list(kids.values())

    def _bind(self, g: dict, det: Detection, sg: signature.Signed, fields: dict | None, columns: list | None) -> None:
        """Give a new group the rules that need no AI: an auto parser for a
        structured format, or a seeded rule whose scope and pattern fit."""
        from . import rx
        learned_p, learned_m = self.snap.rule("parser:" + g["signature"]), self.snap.rule("mapping:" + g["signature"])
        if learned_p:            # a rule learned earlier (or elsewhere) for exactly this signature
            g["parser_rule"] = learned_p["rule_id"]
            g["mapping_rule"] = learned_m["rule_id"] if learned_m else None
            g["status"] = "mapped" if learned_m else "parsed"
            return
        if det.format in STRUCTURED:
            body = parsers.auto_parser(det, columns)
            for r in self.snap.seed_parsers:   # a seeded structured parser (named columns) wins
                b = r["body"]
                if b["kind"] == det.format and self.snap._in_scope(b["scope"], det.bucket, g["source"].split("|")[0]):
                    try:
                        if not self._fits(b, parsers.run(self.snap, b, det)):
                            continue
                    except ParseError:
                        continue
                    g["parser_rule"] = r["rule_id"]
                    g["labels"] = dict(b.get("labels") or {})
                    if b.get("mapping"):
                        g["mapping_rule"] = b["mapping"]
                    break
            if not g["parser_rule"] and body:
                tag = det.dialect or (hashlib.md5(_j(body).encode()).hexdigest()[:8] if det.format == "delimited" else "")
                rid = f"parser:auto-{det.format}" + (f"-{tag}" if tag else "")
                if not self.snap.rule(rid):
                    registry.save_rule(self.store, rid, body, {"created_by": "engine", "note": "automatic decoder"})
                    self.reload()
                g["parser_rule"] = rid
            g["status"] = "parsed"
        else:
            for r in self.snap.seed_parsers:
                b = r["body"]
                if b["kind"] != "regex" or not self.snap._in_scope(b["scope"], det.bucket, g["source"].split("|")[0]):
                    continue
                if rx.compile(b["pattern"]).search(det.payload):
                    g["parser_rule"] = r["rule_id"]
                    g["labels"] = dict(b.get("labels") or {})
                    g["mapping_rule"] = b.get("mapping")
                    g["status"] = "mapped" if g["mapping_rule"] else "parsed"
                    break
        if g["parser_rule"] and not g["mapping_rule"] and learned_m:
            g["mapping_rule"] = learned_m["rule_id"]
            g["status"] = "mapped"
        if g["parser_rule"] and not g["mapping_rule"]:
            probe = fields
            if probe is None:
                try:
                    probe = parsers.run(self.snap, self.snap.rule(g["parser_rule"])["body"], det, sg.parsed)
                except (ParseError, TypeError):
                    probe = {}
            for r in self.snap.scoped_mappings:
                b = r["body"]
                if not self.snap._in_scope(b["scope"], det.bucket, g["source"].split("|")[0]):
                    continue
                if self._fits(b, probe):
                    g["mapping_rule"] = r["rule_id"]
                    g["labels"] = {**(b.get("labels") or {}), **g["labels"]}
                    g["status"] = "mapped"
                    break

    @staticmethod
    def _fits(mapping_body: dict, fields: dict) -> bool:
        """A scoped rule fits a group when its `match` block holds on the
        group's first record: required fields present, listed values equal."""
        req = (mapping_body.get("match") or {}).get("requires") or []
        eq = (mapping_body.get("match") or {}).get("equals") or {}
        absent = (mapping_body.get("match") or {}).get("absent") or []
        return all(k in fields for k in req) and not any(k in fields for k in absent) \
            and all(str(fields.get(k)) == str(v) for k, v in eq.items())

    def _sample(self, g: dict, rid: int, text: str, masked: str | None = None, fields: dict | None = None,
                failure: bool = False) -> None:
        """Keep a small, useful set of raw lines per group:
        diverse (lines that add new tokens), recent (a reservoir that newer
        batches refresh, so drift shows), value:<field>=<v> (a few lines per
        recurring value of an ambiguous field) and failure (kept apart)."""
        samples = self._samples(g)
        cap = self.settings.samples_max
        if failure:
            fails = [x for x in samples if x[2] == "failure"]
            if len(fails) < 10:
                samples.append((rid, text, "failure", masked))
                self._dirty_samples.add(g["signature"])
            return
        h = int(hashlib.md5(text.encode("utf-8", "replace")).hexdigest()[:8], 16)
        changed = False
        diverse = sum(1 for x in samples if x[2] == "diverse")
        toks = _tokens(text)
        novel = toks - g["_tokens"]
        if diverse < 5 or (diverse < cap and novel):
            samples.append((rid, text, "diverse", masked))
            changed = True
            if len(g["_tokens"]) < 5000:
                g["_tokens"] |= toks
        else:
            recent = [i for i, x in enumerate(samples) if x[2] == "recent"]
            if len(recent) < 6:
                samples.append((rid, text, "recent", masked))
                changed = True
            elif h % 16 == 0:                    # reservoir: newer lines replace the oldest recent one
                samples.pop(recent[0])
                samples.append((rid, text, "recent", masked))
                changed = True
        for fld in (g["detail"].get("ambiguous") or ()) if fields else ():
            v = fields.get(fld)
            if v in (None, ""):
                continue
            tag = f"value:{fld}={str(v)[:40]}"
            if sum(1 for x in samples if x[2] == tag) < 2 and sum(1 for x in samples if x[2].startswith("value:")) < 30:
                samples.append((rid, text, tag, masked))
                changed = True
        if changed:
            self._dirty_samples.add(g["signature"])

    # ------------------------------------------------------------ group statistics
    @staticmethod
    def _kind(v: str) -> str:
        if not v:
            return "empty"
        c = v[0]
        if v.replace(".", "", 3).isdigit():
            return "ip" if v.count(".") == 3 else "num"
        if ":" in v and all(ch in "0123456789abcdefABCDEF:." for ch in v):
            return "ip"
        return "word" if c.isalpha() and v.replace("_", "").replace("-", "").isalnum() else "text"

    def _stat(self, g: dict, fields: dict) -> None:
        """Cheap per-field counters: lines seen, distinct values (capped), type mix."""
        st = g["_stats"]
        if st is None:
            st = g["_stats"] = self.store.stats(g["signature"])
        cap = self.settings.stats_max_values
        for k, v in fields.items():
            if k[0] == "@" and k != "@msgid":
                continue
            f = st.get(k)
            if f is None:
                if len(st) >= 80:
                    continue
                f = st[k] = {"n": 0, "vals": {}, "over": False, "kinds": {}}
            f["n"] += 1
            sv = v if isinstance(v, str) else json.dumps(v)
            sv = sv[:60]
            kd = self._kind(sv)
            f["kinds"][kd] = f["kinds"].get(kd, 0) + 1
            if not f["over"]:
                vals = f["vals"]
                vals[sv] = vals.get(sv, 0) + 1
                if len(vals) > cap:
                    f["over"] = True
                    f["vals"] = {}
        self._dirty_stats.add(g["signature"])

    def classify(self, g: dict) -> dict:
        """Per field: fixed (one value), variable (many), or ambiguous (a few
        recurring values: an enum field, or the thing that defines the event type)."""
        st = g["_stats"] if g["_stats"] is not None else self.store.stats(g["signature"])
        out = {}
        s = self.settings
        for k, f in st.items():
            if f["over"]:
                out[k] = "variable"
            elif len(f["vals"]) <= 1:
                out[k] = "fixed"
            elif (f["n"] >= s.ambiguous_min_lines and len(f["vals"]) <= s.ambiguous_max_values
                  and min(f["vals"].values()) >= 2 and f["kinds"].get("word", 0) >= 0.9 * f["n"]):
                out[k] = "ambiguous"
            else:
                out[k] = "variable"
        return out

    # ------------------------------------------------------------ parse + map
    def _mapping(self, rule_id: str | None) -> dict | None:
        rule_id = rule_id or DEFAULT_MAPPING
        if rule_id not in self._resolved:
            r = self.snap.rule(rule_id)
            self._resolved[rule_id] = ocsf.resolve_mapping(r["body"], self.snap.rule) if r else None
        return self._resolved[rule_id]

    def _ctx(self, g: dict, rec: Record) -> dict:
        ctx = {"now": self._clock(), "default_tz": self.settings.default_tz, "labels": g.get("labels") or {}}
        if self.settings.keep_raw_data:
            ctx["raw_data"] = rec.text
        return ctx

    def parse_record(self, g: dict, det: Detection, sg: signature.Signed, rec: Record,
                     parser_body: dict | None = None, mapping: dict | None = None,
                     mapping_given: bool = False) -> dict:
        """Parse and map one record. Returns a result dict; writes nothing."""
        tags = list(rec.flags)
        pr = self.snap.rule(g["parser_rule"])
        body = parser_body or (pr["body"] if pr else None)
        if body is None:
            lt = self.snap.rule("longtail:" + g["signature"])
            if not lt:
                return {"status": "pending"}
            fields = {}
            for name, spec in lt["body"]["fields"].items():
                if "const" in spec:
                    if spec["const"] in rec.text:
                        fields[name] = spec["const"]
                elif spec["var"] < len(sg.variables):
                    val = sg.variables[spec["var"]][1]
                    fields[name] = val.strip(spec["trim"]) if spec.get("trim") else val
            if lt["body"].get("summary"):
                fields["summary"] = lt["body"]["summary"]
            for k, v in det.header.items():
                fields.setdefault(k, v)
            tags.append("ai_extracted")
            rule_used = lt["rule_id"]
        else:
            try:
                fields = parsers.run(self.snap, body, det, None)
            except ParseError as exc:
                return {"status": "dlq", "stage": "parse", "reason": str(exc)[:300]}
            rule_used = g["parser_rule"]
        if not mapping_given:
            mapping = self._mapping(g["mapping_rule"])
            if not g["mapping_rule"]:
                tags.append("base_fallback")
        if mapping is None:
            return {"status": "parsed", "fields": fields, "event": None, "valid": None, "errors": [],
                    "tags": tags, "parser_rule": rule_used, "mapping_rule": None}
        event, problems, flags = ocsf.map_event(self.schema, mapping, fields, self._ctx(g, rec))
        errors, warnings = self.schema.validate(event)
        tags += sorted(flags)
        if problems:
            tags.append("transform_error")
        return {"status": "parsed", "fields": fields, "event": event, "valid": not errors,
                "errors": errors + problems, "warnings": warnings, "tags": tags,
                "parser_rule": rule_used, "mapping_rule": g["mapping_rule"] or DEFAULT_MAPPING}

    def _event_row(self, rid: int, g: dict, res: dict) -> tuple:
        """Every parsed event carries its group id and the rule versions that made it."""
        ev = res["event"]
        pr = self.snap.rule(res["parser_rule"])
        mr = self.snap.rule(res["mapping_rule"])
        return (rid, g["signature"], _j(res["fields"]), _j(ev) if ev is not None else None,
                ev.get("class_uid") if ev else None, None if res["valid"] is None else int(res["valid"]),
                _j(res["errors"][:8]), res["parser_rule"], res["mapping_rule"], _j(res["tags"]),
                pr["version"] if pr else None, mr["version"] if mr else None)

    def _shadow(self, g: dict, det: Detection, sg: signature.Signed, rec: Record, counts: dict) -> None:
        for rid in (g["parser_rule"], g["mapping_rule"]):
            sh = self.snap.shadow.get(rid) if rid else None
            if not sh:
                continue
            key = (sh["rule_id"], sh["version"])
            c = counts.setdefault(key, [0, 0, None])
            c[0] += 1
            try:
                if sh["kind"] == "parser":
                    res = self.parse_record(g, det, sg, rec, parser_body=sh["body"])
                else:
                    res = self.parse_record(g, det, sg, rec, mapping=ocsf.resolve_mapping(sh["body"], self.snap.rule),
                                            mapping_given=True)
                if res["status"] == "parsed" and res.get("valid") is not False:
                    c[1] += 1
                else:
                    c[2] = (res.get("reason") or "; ".join(res.get("errors") or []))[:300]
            except Exception as exc:  # a shadow rule must never break the live path
                c[2] = repr(exc)[:300]

    # ------------------------------------------------------------ the batch
    def _family_of(self, det: Detection, flat: dict):
        from .family import STRUCTURED, keyset
        if det.app or det.format not in STRUCTURED or not flat:
            return None
        return self.families.assign(det.bucket, keyset(det.format, flat, det.delimiter))

    def _sign(self, det: Detection, label: str | None, cols, snap=None) -> signature.Signed:
        return signature.sign(snap or self.snap, det, label, cols, self._family_of)

    def analyse(self, rec: Record):
        """Detection and signature for one record (shared by process and tools)."""
        det = detect(self.snap, rec.text)
        label = rec.label or "-"
        cols = None
        sc = rec.columns or self.columns.get(rec.stream)
        if sc:
            from .formats import split_delimited
            if det.format in ("unstructured", "delimited") and not det.header \
                    and len(split_delimited(rec.text, sc["delimiter"])) == len(sc["columns"]):
                det = Detection(chain=["directive", "delimited"], format="delimited", payload=rec.text,
                                delimiter=sc["delimiter"])
                cols = sc["columns"]
            elif rec.columns is None:
                # A header line describes the lines that follow it. The first line that
                # does not fit ends its reach (another file or source has started).
                self.columns.pop(rec.stream, None)
        source = f"{label}|{det.bucket}"
        known = self.label_sources.setdefault(label, set())
        if source not in known:
            if len(known) >= MAX_SOURCES_PER_LABEL:
                det.app = "~overflow"
                source = f"{label}|{det.bucket}"
            known.add(source)
        return det, source, cols

    def process(self, records: list, state: dict | None = None, raw_ids: list | None = None) -> dict:
        """Run one batch. `state` is written in the same transaction (read offset).
        `raw_ids` is set on replay: the raw rows exist and are updated in place."""
        self.reload()
        self.batch_no += 1
        stats = {"records": len(records), "parsed": 0, "pending": 0, "dlq": 0, "binary": 0,
                 "quarantined": 0, "directive": 0, "new_groups": 0}
        raw_rows, upd_rows, event_rows, dlq_rows, drop_events = [], [], [], [], []
        shadow_counts: dict = {}
        next_id = self.store.next_raw_id() if raw_ids is None else 0
        before = len(self.groups)
        for i, rec in enumerate(records):
            rid = raw_ids[i] if raw_ids is not None else next_id + i

            def put(sig, status, source, _rec=rec, _rid=rid):
                if raw_ids is None:
                    raw_rows.append((_rid, _rec.stream, _rec.offset, source, sig, status, self.batch_no,
                                     _rec.text if _rec.blob is None else None, _rec.blob))
                else:
                    upd_rows.append((sig, status, source, _rid))
                    drop_events.append(_rid)
            if rec.blob is not None:
                put(None, "binary", f"{rec.label or '-'}|binary")
                stats["binary"] += 1
                continue
            if self._directive(rec):
                put(None, "directive", f"{rec.label or '-'}|directive")
                stats["directive"] += 1
                continue
            det, source, cols = self.analyse(rec)
            sg = self._sign(det, rec.label, cols)
            if sg.family:
                source = f"{source}#{sg.family}"
            src = self._source(source)
            src["lines"] += 1
            self._dirty_sources.add(source)
            if src["quarantined"]:
                put(None, "quarantined", source)
                stats["quarantined"] += 1
                continue
            if sg.error:
                put(sg.signature, "dlq", source)
                dlq_rows.append((rid, "decode", sg.error[:300], sg.signature, self.batch_no))
                stats["dlq"] += 1
                continue
            g = self._subgroup(self._lookup(sg, det, source, None, cols), det)
            g["count"] += 1
            g["last_batch"] = self.batch_no
            self._dirty_groups.add(g["signature"])
            res = self.parse_record(g, det, sg, rec)
            if self.snap.shadow:
                self._shadow(g, det, sg, rec, shadow_counts)
            masked = sg.template if det.format == "unstructured" else None
            if res["status"] == "pending":
                put(g["signature"], "pending", source)
                self._sample(g, rid, rec.text, masked)
                self._stat(g, {f"#{i} {ph}": v for i, (ph, v) in enumerate(sg.variables[:30])})
                stats["pending"] += 1
            elif res["status"] == "dlq":
                put(g["signature"], "dlq", source)
                dlq_rows.append((rid, res["stage"], res["reason"], g["signature"], self.batch_no))
                g["parse_failures"] += 1
                self._sample(g, rid, rec.text, masked, failure=True)
                stats["dlq"] += 1
            else:
                put(g["signature"], "parsed", source)
                self._sample(g, rid, rec.text, masked, res["fields"], failure=res["valid"] is False)
                self._stat(g, res["fields"])
                event_rows.append(self._event_row(rid, g, res))
                if res["valid"] is False:
                    dlq_rows.append((rid, "ocsf", "; ".join(res["errors"][:3])[:300], g["signature"], self.batch_no))
                stats["parsed"] += 1
        stats["new_groups"] = len(self.groups) - before
        self._merge()
        self._after_batch()
        touched = set(self._dirty_groups)
        self.store.begin()
        try:
            if raw_rows:
                self.store.insert_raw(raw_rows)
            if upd_rows:
                self.store.delete_events(drop_events)
                self.store.update_raw(upd_rows)
            self.store.put_events(event_rows)
            self.store.put_dlq(dlq_rows)
            self._flush()
            for (rid_, ver), c in shadow_counts.items():
                self.store.x("INSERT INTO shadow(rule_id,version,lines,ok,last_error) VALUES(?,?,?,?,?) "
                             "ON CONFLICT(rule_id,version) DO UPDATE SET lines=lines+excluded.lines, "
                             "ok=ok+excluded.ok, last_error=COALESCE(excluded.last_error,last_error)",
                             (rid_, ver, c[0], c[1], c[2]))
            self.store.set_state("batch", self.batch_no)
            self.store.set_state("columns", self.columns)
            for k, v in (state or {}).items():
                self.store.set_state(k, v)
            self.store.commit()
        except Exception:
            self.store.rollback()
            raise
        if self.settings.auto_repair and raw_ids is None:
            from . import repair
            stats["repair"] = repair.after_batch(self, touched)
        return stats

    def _flush(self) -> None:
        for sig in self._dirty_groups:
            g = self.groups.get(sig)
            if g:
                self.store.upsert_group(g)
        for sig in self._dirty_samples:
            g = self.groups.get(sig)
            if g and g["_samples"] is not None:
                self.store.replace_samples(sig, g["_samples"])
        self.families.flush()
        if self._new_sigs:
            self.store.put_signatures(self._new_sigs)
            self._new_sigs = []
        for sig in self._dirty_stats:
            g = self.groups.get(sig)
            if g and g["_stats"] is not None:
                self.store.put_stats(sig, g["_stats"])
        self._dirty_stats = set()
        for key in self._dirty_sources:
            self.store.put_source(self.sources[key])
        for op in self._queue_ops:
            if op[0] == "enqueue":
                self.store.enqueue(op[1], op[2], op[3])
            elif op[0] == "reopen":
                self.store.reopen(op[1], op[2], op[3])
            elif op[0] == "sql":
                self.store.x(op[1], op[2])
        self._dirty_groups, self._dirty_samples, self._dirty_sources, self._queue_ops = set(), set(), set(), []

    # ------------------------------------------------------------ end of batch
    def _after_batch(self, final: bool = False) -> None:
        s = self.settings
        for sig in list(self._dirty_groups):
            g = self.groups.get(sig)
            if not g or g["merged_into"]:
                continue
            payload = {"signature": sig, "bucket": g["bucket"], "source": g["source"], "count": g["count"]}
            if not g["parser_rule"]:
                if g["count"] >= s.group_threshold and g["status"] in ("new", "longtail"):
                    g["status"] = "queued"
                    self._queue_ops.append(("reopen", "needs-parser", sig, payload))
                    self._queue_ops.append(("sql", "UPDATE queue SET status='done' WHERE name='longtail' AND key=?", (sig,)))
            else:
                if g["parse_failures"] >= s.drift_failures and g["status"] != "drift":
                    g["status"] = "drift"
                    self._queue_ops.append(("reopen", "needs-parser", sig, {**payload, "reason": "parse failures on an "
                                            "existing group: treat as a new version of its rule",
                                            "current_rule": g["parser_rule"], "failures": g["parse_failures"]}))
                if not g["mapping_rule"] and g["count"] >= s.group_threshold:
                    self._queue_ops.append(("enqueue", "needs-mapping", sig, payload))
        if final:   # end of input: parsed groups still without a class mapping get their turn too
            for sig, g in self.groups.items():
                if g["parser_rule"] and not g["mapping_rule"] and not g["merged_into"] and g["status"] != "split" \
                        and g["count"] > 0:
                    self._queue_ops.append(("enqueue", "needs-mapping", sig, {
                        "signature": sig, "bucket": g["bucket"], "source": g["source"], "count": g["count"]}))
        for sig, g in self.groups.items():
            if g["merged_into"] or g["parser_rule"] or g["status"] != "new":
                continue
            idle = self.batch_no - (g["last_batch"] or 0)
            if final or idle >= s.longtail_idle_batches:
                g["status"] = "longtail"
                self._dirty_groups.add(sig)
                self._queue_ops.append(("enqueue", "longtail", sig, {"signature": sig, "bucket": g["bucket"],
                                                                      "source": g["source"], "count": g["count"]}))
        # explosion guard
        for key in list(self._dirty_sources):
            src = self.sources[key]
            live = sum(1 for sg_ in self.source_sigs.get(key, ()) if not self.groups[sg_]["merged_into"])
            src["signatures"] = live
            src["history"].append([self.batch_no, src["lines"], live])
            if src["quarantined"]:
                continue
            reason = None
            if live > s.signature_cap:
                reason = f"{live} signatures exceeds the cap of {s.signature_cap}"
            elif src["lines"] >= s.explosion_min_lines and live / src["lines"] > s.explosion_ratio:
                reason = f"{live} signatures in {src['lines']} lines (ratio above {s.explosion_ratio})"
            if reason:
                src["quarantined"] = 1
                src["reason"] = reason
                self._queue_ops.append(("reopen", "mask-repair", key, {"source": key, "reason": reason,
                                                                        "lines": src["lines"], "signatures": live}))

    @staticmethod
    def _header_of(g: dict) -> dict | None:
        d = g.get("detail") or {}
        if d.get("columns") and d.get("delimiter"):
            return {"columns": d["columns"], "delimiter": d["delimiter"]}
        return None

    def finalize(self) -> None:
        """End of input: groups still below the threshold go to the long tail."""
        self._after_batch(final=True)
        self.store.begin()
        self._flush()
        self.store.commit()

    # ------------------------------------------------------------ near-duplicate merge
    def _merge(self) -> None:
        """Near-duplicate merge over signature templates (never raw lines).

        Candidate sets come from Drain3 clusters (`merge_candidates="drain"`)
        or from the whole bucket (`"exact"`, the default: Drain's prefix tree
        keeps apart templates whose variable sits in the first tokens). Either
        way a merge happens only after the check in _merge_cluster."""
        k = self.settings.merge_min_distinct
        for bucket in self._new_unstructured:
            members = [self.groups[s] for s in self.by_bucket.get(bucket, ())
                       if self.groups[s]["format"] == "unstructured" and not self.groups[s]["merged_into"]
                       and self.groups[s]["template"].strip() and not self.groups[s]["detail"].get("parent")]
            if len(members) < 2:
                continue
            if self.settings.merge_candidates == "exact":
                self._merge_cluster(bucket, members, k)
                continue
            cfg = TemplateMinerConfig()
            cfg.drain_sim_th = self.settings.drain_sim_th
            cfg.drain_depth = self.settings.drain_depth
            cfg.profiling_enabled = False
            cfg.parametrize_numeric_tokens = False
            tm = TemplateMiner(config=cfg)
            clusters: dict = {}
            for g in sorted(members, key=lambda g: g["signature"]):
                res = tm.add_log_message(g["template"])
                clusters.setdefault(res["cluster_id"], []).append(g)
            for cl in clusters.values():
                if len(cl) >= 2:
                    self._merge_cluster(bucket, cl, k)
        self._new_unstructured = set()

    @staticmethod
    def _static_words(toks: list) -> int:
        n = 0
        for t in toks:
            if "<" in t and ">" in t:
                continue
            if sum(1 for ch in t if ch.isalpha()) >= 3:
                n += 1
        return n

    def _merge_cluster(self, bucket: str, cl: list, k: int) -> None:
        """Merge only what is provably one template split by unmasked variables.

        One position: templates equal everywhere else, with at least `k`
        distinct values there. Two positions at once (a value that is logged
        twice, or two ids that change together): each position must be nearly
        unique per template. In both cases enough fixed words must remain to
        still identify the event. Short lists of alternatives such as
        opened/closed are never merged."""
        live = {g["signature"]: g["template"].split() for g in cl}
        by_sig = {g["signature"]: g for g in cl}

        def families(width: int):
            by_len: dict = {}
            for sig, toks in live.items():
                by_len.setdefault(len(toks), []).append(sig)
            for n, sigs in by_len.items():
                if len(sigs) < 2 or n < width + 1:
                    continue
                combos = [(p,) for p in range(n)] if width == 1 else \
                    [(p, q) for p in range(n) for q in range(p + 1, n)]
                if width == 2 and (n > 40 or len(sigs) * len(combos) > 400000):
                    continue
                for combo in combos:
                    fam: dict = {}
                    for sig in sigs:
                        t = live.get(sig)
                        if t is None:
                            continue
                        fam.setdefault(tuple(x for i, x in enumerate(t) if i not in combo), []).append(sig)
                    for members in fam.values():
                        members = [m for m in members if m in live]
                        if len(members) < 2:
                            continue
                        ok = True
                        for p in combo:
                            vals = {live[m][p] for m in members}
                            if any(v.strip(signature._EDGE).lower() in self.snap.protected for v in vals):
                                ok = False       # outcome and action words never merge away
                                break
                            if width == 1:
                                ok = "<*>" in vals or len(vals) >= k
                            else:
                                ok = ok and len(vals) >= max(k + 1, int(0.6 * len(members)))
                                if not ok:
                                    break
                        if not ok:
                            continue
                        toks = list(live[members[0]])
                        for p in combo:
                            toks[p] = "<*>"
                        if self._static_words(toks) < 2:
                            continue
                        canon = self._merge_groups(bucket, toks, [by_sig[m] for m in members])
                        for m in members:
                            live.pop(m, None)
                        live[canon["signature"]] = toks
                        by_sig[canon["signature"]] = canon
                        yield True

        for _round in range(6):
            if not any(list(families(1))):
                if not any(list(families(2))):
                    break

    def _merge_groups(self, bucket: str, toks: list, gs: list) -> dict:
        template = " ".join(toks)
        sig = signature._h(bucket, "u", template)
        canon = self.groups.get(sig)
        with_rule = [g for g in gs if g["parser_rule"]]
        if canon is None:
            keep = max(with_rule or gs, key=lambda g: g["count"])
            canon = {**keep, "signature": sig, "template": template, "count": 0, "merged_into": None,
                     "_samples": [], "_tokens": set(), "_stats": {}, "detail": {"merged": True},
                     "status": keep["status"] if keep["parser_rule"] else "new",
                     "first_batch": min(g["first_batch"] or 0 for g in gs)}
            if not keep["parser_rule"]:
                canon["parser_rule"] = canon["mapping_rule"] = None
            self.groups[sig] = canon
            self._register(canon)
            self._link(sig, sig)
            self.merged_index.setdefault((bucket, len(toks)), []).append((toks, sig))
        elif not any(m[1] == sig for m in self.merged_index.get((bucket, len(toks)), ())):
            self.merged_index.setdefault((bucket, len(toks)), []).append((toks, sig))
        pool = list(self._samples(canon))
        for g in gs:
            if g["signature"] == sig:
                continue
            canon["count"] += g["count"]
            canon["last_batch"] = max(canon["last_batch"] or 0, g["last_batch"] or 0)
            pool += self._samples(g)
            g["status"] = "merged"
            g["merged_into"] = sig
            self.alias[g["signature"]] = sig
            for a, c in list(self.alias.items()):       # every signature of the member now leads to the merged group
                if c == g["signature"]:
                    self.alias[a] = sig
            self._queue_ops.append(("sql", "UPDATE group_signatures SET group_id=? WHERE group_id=?", (sig, g["signature"])))
            self._dirty_groups.add(g["signature"])
            self._queue_ops.append(("sql", "UPDATE raw SET signature=? WHERE signature=?", (sig, g["signature"])))
            self._queue_ops.append(("sql", "UPDATE events SET signature=? WHERE signature=?", (sig, g["signature"])))
            self._queue_ops.append(("sql", "UPDATE queue SET status='done' WHERE key=? AND status='open'", (g["signature"],)))
        # keep a diverse sample set: spread picks across the merged members
        pool = sorted({x[0]: x for x in pool if x[2] != "recent"}.values(), key=lambda x: x[0])
        cap = self.settings.samples_max
        if len(pool) > cap:
            step = len(pool) / cap
            pool = [pool[int(i * step)] for i in range(cap)]
        canon["_samples"] = [(x[0], x[1], x[2] if x[2] == "failure" else "diverse", x[3]) for x in pool]
        canon["_tokens"] = set().union(*[_tokens(x[1]) for x in pool]) if pool else set()
        self._dirty_groups.add(sig)
        self._dirty_samples.add(sig)
        return canon

    # ------------------------------------------------------------ running sources
    def run_file(self, path: str, label: str | None = None, batch_size: int = 2000,
                 stream: str | None = None, progress=None) -> dict:
        src = FileSource(path, stream, label)
        key = f"offset:{src.stream}"
        total = {"records": 0, "parsed": 0, "pending": 0, "dlq": 0, "binary": 0, "quarantined": 0,
                 "directive": 0, "new_groups": 0, "batches": 0}
        while True:
            self.reload()
            framer = Framer(self.snap.framing, self.settings.max_line_len)
            offset = int(self.store.get_state(key, 0))
            lines, eof = src.read(offset, batch_size)
            if not lines:
                break
            recs, consumed = framer.frame(src.stream, lines, eof, label)
            if consumed == 0:
                recs, consumed = framer.frame(src.stream, lines, True, label)
            new_offset = src.end_offset(lines, consumed, eof)
            st = self.process(recs, {key: new_offset})
            for k in st:
                if k in total:
                    total[k] += st[k]
            total["batches"] += 1
            if progress:
                progress(st)
            if eof and consumed >= len(lines):
                break
        return total

    # ------------------------------------------------------------ replay
    def replay_signatures(self, sigs: list, restat: bool = False) -> dict:
        """Re-parse and re-map the stored raw lines of these groups after a rule
        was created or changed. Counts and samples are not touched."""
        self.reload()
        stats = {"records": 0, "parsed": 0, "pending": 0, "dlq": 0}
        for sig in sigs:
            g = self.canonical(sig)
            if g is None:
                continue
            rows = self.store.raw_by_signature(g["signature"])
            event_rows, dlq_rows, upd = [], [], []
            g["parse_failures"] = 0
            if restat:
                g["_stats"] = {}
            for r in rows:
                if r["raw"] is None:
                    continue
                rec = Record(r["stream"], r["offset"], text=r["raw"], label=r["source"].split("|", 1)[0],
                             columns=self._header_of(g))
                if rec.label == "-":
                    rec.label = None
                det, source, cols = self.analyse(rec)
                sg = self._sign(det, rec.label, cols)
                res = self.parse_record(g, det, sg, rec)
                if restat:
                    self._stat(g, res["fields"] if res["status"] == "parsed" else
                               {f"#{i} {ph}": v for i, (ph, v) in enumerate(sg.variables[:30])})
                stats["records"] += 1
                if res["status"] == "parsed":
                    event_rows.append(self._event_row(r["id"], g, res))
                    if res["valid"] is False:
                        dlq_rows.append((r["id"], "ocsf", "; ".join(res["errors"][:3])[:300], g["signature"], self.batch_no))
                    stats["parsed"] += 1
                elif res["status"] == "dlq":
                    dlq_rows.append((r["id"], res["stage"], res["reason"], g["signature"], self.batch_no))
                    g["parse_failures"] += 1
                    stats["dlq"] += 1
                else:
                    stats["pending"] += 1
                upd.append((g["signature"], res["status"], r["source"], r["id"]))
            self.store.begin()
            try:
                self.store.delete_events([r["id"] for r in rows])
                self.store.update_raw(upd)
                self.store.put_events(event_rows)
                self.store.put_dlq(dlq_rows)
                self.store.upsert_group(g)
                if restat and g["_stats"] is not None:
                    self.store.put_stats(g["signature"], g["_stats"])
                self.store.commit()
            except Exception:
                self.store.rollback()
                raise
        return stats

    def replay_source(self, source: str) -> dict:
        """Re-hash every stored line of a source after its mask or sign rule
        changed. Groups keep their ids, so parsers and mappings survive:
        each new signature goes to the old group that most of its lines came
        from. Old groups that lose all their lines are marked merged into the
        group that took them. Only signatures with no old group get a new one."""
        from collections import Counter
        self.reload()
        rows = self.store.raw_by_source(source)
        label = source.split("|", 1)[0]

        def top(gid):
            g = self.groups.get(gid)
            while g is not None and g["detail"].get("parent"):
                g = self.groups.get(g["detail"]["parent"])
            return g["signature"] if g is not None else None
        old = {s for s, g in self.groups.items() if g["source"] == source and not g["merged_into"]
               and not g["detail"].get("parent")}
        plan: dict = {}
        for r in rows:
            g0 = self.groups.get(r["signature"]) if r["signature"] else None
            rec = Record(r["stream"], r["offset"], text=r["raw"], label=None if label == "-" else label,
                         columns=self._header_of(self.groups[top(r["signature"])]) if g0 and top(r["signature"]) else None)
            det, _, cols = self.analyse(rec)
            sg = self._sign(det, rec.label, cols)
            if sg.error:
                continue
            e = plan.setdefault(sg.signature, {"rows": [], "from": Counter(), "det": det, "sg": sg, "cols": cols})
            e["rows"].append(r)
            if g0:
                e["from"][top(r["signature"])] += 1
        # assign group ids: an unchanged signature keeps its group; then the biggest new
        # signatures claim the old group that gave them the most lines (one with rules first)
        claimed: dict = {n: n for n in plan if n in old}
        taken = set(claimed.values())
        for nsig, e in sorted(plan.items(), key=lambda kv: -len(kv[1]["rows"])):
            if nsig in claimed:
                continue
            cands = sorted(((bool(self.groups[g]["parser_rule"]), n, g) for g, n in e["from"].items()
                            if g in old and g not in taken), reverse=True)
            if cands:
                claimed[nsig] = cands[0][2]
                taken.add(cands[0][2])
        # forget the source's old signatures and children, then rebuild
        kids = [s for s, g in self.groups.items() if g["source"] == source and g["detail"].get("parent")]
        self.store.begin()
        try:
            for gid in list(old) + kids:
                self.store.x("DELETE FROM group_signatures WHERE group_id=?", (gid,))
            for k in kids:
                self.store.x("DELETE FROM groups WHERE signature=?", (k,))
                self.store.x("DELETE FROM samples WHERE signature=?", (k,))
                self.store.x("DELETE FROM queue WHERE key=?", (k,))
            self.store.commit()
        except Exception:
            self.store.rollback()
            raise
        gone = set(old) | set(kids)
        self.alias = {a: c for a, c in self.alias.items() if c not in gone and a not in gone}
        for k in kids:
            g = self.groups.pop(k)
            self.by_bucket.get(g["bucket"], []).remove(k) if k in self.by_bucket.get(g["bucket"], []) else None
            self.source_sigs.get(source, set()).discard(k)
        self.merged_index = {k: [m for m in v if m[1] not in gone] for k, v in self.merged_index.items()}
        for gid in old:
            g = self.groups[gid]
            g.update({"count": 0, "_samples": [], "_tokens": set(), "_stats": {}})
            self._dirty_samples.add(gid)
        upd, final, received = [], {}, Counter()
        for nsig, e in plan.items():
            det, sg = e["det"], e["sg"]
            gid = claimed.get(nsig)
            if gid:
                g = self.groups[gid]
                keep = {k: g["detail"][k] for k in ("ambiguous", "cooldown_until", "merged") if k in g["detail"]}
                g["template"], g["bucket"], g["format"] = sg.template, det.bucket, det.format
                g["detail"] = {**sg.detail, **keep}
                if det.dialect:
                    g["detail"]["dialect"] = det.dialect
                if det.delimiter:
                    g["detail"]["delimiter"] = det.delimiter
                if e["cols"]:
                    g["detail"]["columns"] = list(e["cols"])
            else:
                new_id = nsig if nsig not in self.groups else signature._h(nsig, "regroup", str(self.batch_no))
                g = self._new_group(new_id, det, sg, source, e["cols"])
                self._register(g)
                self._bind(g, det, sg, None, e["cols"])
                donor = e["from"].most_common(1)
                if donor:                                   # lineage: start from the parent's rules when they fit
                    par = self.groups[donor[0][0]]
                    g["detail"]["parent_lineage"] = par["signature"]
                    pr = self.snap.rule(par["parser_rule"])
                    if pr and not g["parser_rule"]:
                        try:
                            for r in e["rows"][:20]:
                                d2 = self.analyse(Record(r["stream"], r["offset"], text=r["raw"],
                                                         label=None if label == "-" else label))[0]
                                parsers.run(self.snap, pr["body"], d2)
                            g["parser_rule"], g["mapping_rule"] = par["parser_rule"], par["mapping_rule"]
                            g["labels"] = dict(par["labels"])
                            g["status"] = "mapped" if g["mapping_rule"] else "parsed"
                        except ParseError:
                            pass
            self._link(nsig, g["signature"])
            if det.format == "unstructured":
                self._new_unstructured.add(det.bucket)
            for o, n in e["from"].items():
                received[(o, g["signature"])] += n
            for r in e["rows"]:
                rec = Record(r["stream"], r["offset"], text=r["raw"], label=None if label == "-" else label,
                             columns=self._header_of(g))
                tgt = self._subgroup(g, self.analyse(rec)[0])
                tgt["count"] += 1
                tgt["last_batch"] = self.batch_no
                self._sample(tgt, r["id"], r["raw"], sg.template if det.format == "unstructured" else None)
                final[tgt["signature"]] = tgt
                upd.append((tgt["signature"], "pending", r["source"], r["id"]))
            self._dirty_groups.add(g["signature"])
        for gid in old:                       # an old group with no lines left: merged into whoever took them
            g = self.groups[gid]
            if g["count"] == 0 and gid not in claimed.values() and g["status"] != "split":
                to = max(((n, t) for (o, t), n in received.items() if o == gid), default=(0, None))[1]
                g["status"], g["merged_into"] = "merged", to
                if to:
                    self.alias[gid] = to
                self._queue_ops.append(("sql", "UPDATE queue SET status='done' WHERE key=? AND status='open'", (gid,)))
            self._dirty_groups.add(gid)
        src = self._source(source)
        src.update({"lines": len(rows), "quarantined": 0, "reason": None})
        self._dirty_sources.add(source)
        self.batch_no += 1
        self._merge()
        self._after_batch()
        self.store.begin()
        try:
            self.store.update_raw(upd)
            self._flush()
            self.store.set_state("batch", self.batch_no)
            self.store.commit()
        except Exception:
            self.store.rollback()
            raise
        live = [s for s in final if not self.groups[s]["merged_into"]] + \
               list({self.alias[s] for s in final if s in self.alias})
        out = self.replay_signatures(sorted(set(live)), restat=True)
        out["groups_kept"] = len(set(claimed.values()))
        out["groups_new"] = len(plan) - len(claimed)
        return out


def metrics(store: SqliteStore) -> dict:
    """Per-source operating numbers."""
    out = {}
    for s in store.sources():
        out[s["source"]] = {"lines": s["lines"], "signatures": s["signatures"], "quarantined": bool(s["quarantined"]),
                            "signature_growth": s["history"][-10:], "parsed": 0, "pending": 0, "dlq": 0,
                            "events": 0, "valid": 0, "base_fallback": 0, "unmapped_ratio": None}
    for r in store.q("SELECT source, status, COUNT(*) n FROM raw GROUP BY source, status"):
        m = out.setdefault(r["source"], {"lines": 0, "parsed": 0, "pending": 0, "dlq": 0})
        m[r["status"]] = r["n"]
    for r in store.q("""SELECT raw.source s, COUNT(*) n, SUM(COALESCE(valid,0)) v,
                        SUM(CASE WHEN events.mapping_rule=? THEN 1 ELSE 0 END) b
                        FROM events JOIN raw ON raw.id=events.raw_id GROUP BY raw.source""", (DEFAULT_MAPPING,)):
        m = out.setdefault(r["s"], {})
        m.update({"events": r["n"], "valid": r["v"], "base_fallback": r["b"]})
    for src, m in out.items():
        seen = (m.get("parsed", 0) + m.get("pending", 0) + m.get("dlq", 0) + m.get("quarantined", 0)
                + m.get("longtail", 0))
        m["parse_rate"] = round(m.get("parsed", 0) / seen, 4) if seen else None
    # unmapped ratio: share of parsed field values that ended in `unmapped`
    for r in store.q("""SELECT raw.source s, events.fields f, events.ocsf o FROM events JOIN raw ON raw.id=events.raw_id
                        WHERE events.raw_id IN (SELECT MIN(raw_id) FROM events GROUP BY signature)"""):
        try:
            nf = len(json.loads(r["f"]))
            nu = len((json.loads(r["o"]) or {}).get("unmapped") or {}) if r["o"] else nf
        except Exception:
            continue
        m = out.setdefault(r["s"], {})
        a = m.setdefault("_u", [0, 0])
        a[0] += nu
        a[1] += nf
    for m in out.values():
        if "_u" in m:
            m["unmapped_ratio"] = round(m["_u"][0] / m["_u"][1], 3) if m["_u"][1] else None
            del m["_u"]
    now = time.time()
    queues = {}
    for r in store.q("SELECT name, status, COUNT(*) n, MIN(created_at) oldest FROM queue GROUP BY name, status"):
        q = queues.setdefault(r["name"], {})
        q[r["status"]] = r["n"]
        if r["status"] == "open":
            q["lag_seconds"] = round(now - r["oldest"], 1)
    spend = {r["agent"]: {"tool_calls": r["n"], "tokens_in": r["ti"], "tokens_out": r["to_"]} for r in store.q(
        "SELECT agent, COUNT(*) n, SUM(tokens_in) ti, SUM(tokens_out) to_ FROM tool_calls GROUP BY agent")}
    return {"sources": out, "queues": queues, "ai_spend": spend}
