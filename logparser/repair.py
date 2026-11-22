"""Self-correcting grouping loop.

Runs after every batch. Code finds symptoms from the group statistics and maps
each to one of a fixed set of operations. Where a symptom needs judgement, one
narrow question goes to the `grouping-repair` queue. Whoever answers (an agent
or a human) returns an operation with parameters, never a free-form change.
Code verifies the operation by replay on stored lines and applies it only if
the check passes. Every answer is remembered, every operation is logged with
its verification, a changed group rests for a cooldown, and an operation that
makes a group's health worse is rolled back.

Operations
  remask           {"op":"remask","source":S,"rule":{mask or sign body}}
  merge            {"op":"merge","groups":[A,B,...]}
  split            {"op":"split","group":G,"rule":{"fields":[..],"presence":[..]}}
  classify_fields  {"op":"classify_fields","source":S,"event_type_fields":[..],
                    "value_fields":[..],"uncertain":[..]}
  keep_separate    {"op":"keep_separate","groups":[A,B]}

Confidence tiers
  verified   code checked it by replay: applied automatically
  plausible  applied, queued for a human spot check
  hold       not applied; waits for a human (the only tier that blocks)
"""
from __future__ import annotations

import json

from . import registry, signature
from .engine import Engine
from .tools import Refused, Tools

OPS = ("remask", "merge", "split", "classify_fields", "keep_separate")


def _scope(g_or_source) -> str:
    return g_or_source if isinstance(g_or_source, str) else g_or_source["source"]


def health(engine: Engine, gids: list) -> dict:
    """Parse rate and valid-event rate over the stored lines of these groups."""
    if not gids:
        return {"lines": 0, "parsed": 0.0, "valid": 0.0}
    q = ",".join("?" * len(gids))
    lines = engine.store.q(f"SELECT COUNT(*) n, SUM(status='parsed') p FROM raw WHERE signature IN ({q})", gids)[0]
    ev = engine.store.q(f"SELECT COUNT(*) n, SUM(COALESCE(valid,0)) v FROM events WHERE signature IN ({q})", gids)[0]
    n = lines["n"] or 0
    return {"lines": n, "parsed": round((lines["p"] or 0) / n, 4) if n else 0.0,
            "valid": round((ev["v"] or 0) / ev["n"], 4) if ev["n"] else 0.0}


def cooling(engine: Engine, g: dict) -> bool:
    return (g["detail"].get("cooldown_until") or 0) > engine.batch_no


def _cool(engine: Engine, gids: list) -> None:
    for gid in gids:
        g = engine.groups.get(gid)
        if g:
            g["detail"]["cooldown_until"] = engine.batch_no + engine.settings.cooldown_batches
            engine.store.upsert_group(g)


# ---------------------------------------------------------------- symptoms
def scan(engine: Engine, touched: set | None = None) -> dict:
    """Find symptoms on the groups the last batch touched. Applies what code
    can verify alone and queues one narrow question for the rest."""
    s = engine.settings
    store = engine.store
    out = {"auto_splits": 0, "questions": 0, "merge_candidates": 0, "remask_candidates": 0, "retired": 0}
    gids = touched if touched is not None else {g for g, v in engine.groups.items() if not v["merged_into"]}
    by_source: dict = {}
    t = Tools(engine, "code")
    for gid in sorted(gids):
        g = engine.groups.get(gid)
        if not g or g["merged_into"] or g["status"] == "split" or g["count"] < max(s.group_threshold, s.ambiguous_min_lines):
            continue
        cls = engine.classify(g)
        amb = sorted(f for f, c in cls.items() if c == "ambiguous" and not f.startswith("#"))
        if amb != (g["detail"].get("ambiguous") or []):
            g["detail"]["ambiguous"] = amb          # sampling keeps a few lines per value of these
            store.upsert_group(g)
        if not g["parser_rule"] or g["detail"].get("parent") or cooling(engine, g):
            continue
        st = g["_stats"] or {}
        for f in amb:
            d = store.decision(_scope(g), f"field:{f}")
            vals = st[f]["vals"]
            if d and d["answer"] == "event_type" or (d is None and all(v.lower() in engine.snap.protected for v in vals)):
                # every value is an outcome or action word: this field defines the event type
                try:
                    apply(engine, {"op": "split", "group": gid, "rule": {"fields": [f]}}, by="code", tier="verified")
                    out["auto_splits"] += 1
                    if d is None:
                        store.decide(_scope(g), f"field:{f}", "event_type", "code", "verified")
                except Refused as exc:
                    store.decide(_scope(g), f"field:{f}", f"split_refused: {str(exc)[:120]}", "code", "verified")
                break
            if d is None:
                e = by_source.setdefault(g["source"], {})
                e.setdefault(f, {"values": dict(sorted(vals.items(), key=lambda kv: -kv[1])[:12]), "groups": []})
                e[f]["groups"].append(gid)
    for source, fields in by_source.items():
        key = f"fields:{source}"
        cur = store.q("SELECT payload, status FROM queue WHERE name='grouping-repair' AND key=?", (key,))
        known = set(json.loads(cur[0]["payload"]).get("fields", {})) if cur else set()
        if cur and cur[0]["status"] == "open" and set(fields) <= known:
            continue
        store.reopen("grouping-repair", key, {
            "symptom": "fields with a few recurring values", "source": source, "fields": fields,
            "question": "For each field: do its values define different event types (they should be separate "
                        "groups), or is it an ordinary field value inside one event type?",
            "answer_with": "classify_fields"})
        out["questions"] += 1
    # two unparsed templates that differ in one position with two values: same event or two events?
    for bucket in {engine.groups[g]["bucket"] for g in gids if g in engine.groups}:
        members = [engine.groups[x] for x in engine.by_bucket.get(bucket, ())
                   if engine.groups[x]["format"] == "unstructured" and not engine.groups[x]["merged_into"]
                   and not engine.groups[x]["parser_rule"] and not engine.groups[x]["detail"].get("parent")]
        fam: dict = {}
        for g in members:
            toks = g["template"].split()
            for p in range(len(toks)):
                fam.setdefault((len(toks), p, tuple(toks[:p] + toks[p + 1:])), []).append((toks[p], g))
        n_open = 0
        for (n, p, rest), items in fam.items():
            if len(items) != 2 or n < 4 or n_open >= 10:
                continue
            (va, ga), (vb, gb) = items
            if any(v.strip(signature._EDGE).lower() in engine.snap.protected for v in (va, vb)):
                continue                      # an outcome word: these are two events by rule
            if min(ga["count"], gb["count"]) < s.group_threshold or cooling(engine, ga) or cooling(engine, gb):
                continue
            q = "merge:" + "|".join(sorted((ga["template"], gb["template"])))[:300]
            if store.decision(bucket, q):
                continue
            key = "merge:" + ":".join(sorted((ga["signature"], gb["signature"])))
            if store.enqueue("grouping-repair", key, {
                    "symptom": "two groups differ in one position", "source": ga["source"],
                    "groups": [ga["signature"], gb["signature"]], "position": p, "values": [va, vb],
                    "templates": [ga["template"][:300], gb["template"][:300]],
                    "question": f"Position {p} is `{va}` in one group and `{vb}` in the other. Is it a variable of one "
                                "event type (merge), or do the two words mean different events (keep separate)?",
                    "answer_with": "merge or keep_separate"}):
                out["merge_candidates"] += 1
            n_open += 1
    # many small groups of one source that share a long prefix: a free-text tail is not masked
    for source in {engine.groups[g]["source"] for g in gids if g in engine.groups}:
        if store.decision(source, "remask:prefix") or engine.sources.get(source, {}).get("quarantined"):
            continue
        pref: dict = {}
        for x in engine.source_sigs.get(source, ()):
            g = engine.groups.get(x)
            if g and not g["merged_into"] and g["format"] == "unstructured" and not g["detail"].get("parent"):
                toks = g["template"].split()
                if len(toks) >= 5:
                    pref.setdefault(tuple(toks[:4]), set()).add(len(toks))
        worst = max(pref.items(), key=lambda kv: len(kv[1]), default=(None, set()))
        if len(worst[1]) >= 5:
            if store.enqueue("grouping-repair", f"remask:{source}", {
                    "symptom": "many groups share a prefix and differ only in length", "source": source,
                    "prefix": " ".join(worst[0]), "groups_with_prefix": len(worst[1]),
                    "question": "A free-text tail (a command line, a message, a user agent) is splitting one event "
                                "into many groups. Which mask pattern covers the tail?",
                    "answer_with": "remask"}):
                out["remask_candidates"] += 1
    # retire signatures that have been idle past their TTL and never got a rule
    for gid, g in engine.groups.items():
        if (not g["merged_into"] and not g["parser_rule"] and g["status"] in ("new", "longtail")
                and engine.batch_no - (g["last_batch"] or 0) >= s.ttl_idle_batches):
            g["status"] = "retired"
            store.upsert_group(g)
            store.log_operation(engine.batch_no, "retire", gid, {}, {"idle_batches": engine.batch_no - g["last_batch"]},
                                "verified", "code", status="kept")
            out["retired"] += 1
    return out


# ---------------------------------------------------------------- operations
def _split_types(engine: Engine, t: Tools, g: dict, body: dict) -> dict:
    """Field-type consistency before and after a split (the spec's SPLIT check)."""
    rows = [(f, d) for _, f, d in t._parsed_rows(g, 600) if f]

    def mixed(fs):
        kinds: dict = {}
        for f in fs:
            for k, v in f.items():
                kinds.setdefault(k, {})
                kd = engine._kind(str(v)[:60])
                kinds[k][kd] = kinds[k].get(kd, 0) + 1
        return sum(1 for c in kinds.values() if len(c) > 1 and max(c.values()) < 0.95 * sum(c.values()))
    pieces: dict = {}
    for f, _ in rows:
        key = tuple(str(f.get(x, "")) for x in body.get("fields") or []) + \
            tuple(f.get(x) not in (None, "") for x in body.get("presence") or [])
        pieces.setdefault(key, []).append(f)
    return {"mixed_type_fields_before": mixed([f for f, _ in rows]),
            "mixed_type_fields_after_worst_piece": max((mixed(v) for v in pieces.values()), default=0),
            "parse_rate_per_piece": 1.0}


def test(engine: Engine, op: dict, by: str = "agent") -> dict:
    """Replay check for an operation. Changes nothing."""
    kind = op.get("op")
    t = Tools(engine, by)
    if kind not in OPS:
        return {"ok": False, "error": f"unknown operation; use one of {OPS}"}
    try:
        if kind == "remask":
            r = t.test_mask(op["source"], op["rule"])
            if r.get("ok"):
                r["improves"] = r["signatures_after"] < r["signatures_before"]
                r["ok"] = r["improves"]
                if not r["improves"]:
                    r["error"] = "signature count does not drop"
            return r
        if kind == "split":
            g = t._group(op["group"])
            if cooling(engine, g):
                return {"ok": False, "error": f"group is in cooldown until batch {g['detail']['cooldown_until']}"}
            r = t.test_split(op["group"], op["rule"])
            if r.get("ok"):
                r.update(_split_types(engine, t, g, op["rule"]))
                if r["pieces"] < 2:
                    r.update(ok=False, error="one piece: the split separates nothing")
                elif r["pieces"] > t.MAX_PIECES or r["pieces"] > max(2, r["lines"] // 2):
                    r.update(ok=False, error="too many pieces: that field is a variable, not an event type")
            return r
        if kind == "merge":
            gs = [t._group(x) for x in op["groups"]]
            if len(gs) < 2 or len({g["bucket"] for g in gs}) != 1 or any(g["format"] != "unstructured" for g in gs):
                return {"ok": False, "error": "merge needs two or more unstructured groups of one bucket"}
            if any(cooling(engine, g) for g in gs):
                return {"ok": False, "error": "a group is in cooldown"}
            toks = [g["template"].split() for g in gs]
            if len({len(x) for x in toks}) != 1:
                return {"ok": False, "error": "templates have different lengths"}
            diff = [i for i in range(len(toks[0])) if len({x[i] for x in toks}) > 1]
            if len(diff) != 1:
                return {"ok": False, "error": f"templates differ in {len(diff)} positions; merge needs exactly one"}
            vals = {x[diff[0]] for x in toks}
            if any(v.strip(signature._EDGE).lower() in engine.snap.protected for v in vals):
                return {"ok": False, "error": "that position holds an outcome or action word; those never merge"}
            merged = list(toks[0])
            merged[diff[0]] = "<*>"
            if engine._static_words(merged) < 2:
                return {"ok": False, "error": "too little fixed text would remain"}
            return {"ok": True, "signatures_before": len(gs), "signatures_after": 1, "template": " ".join(merged),
                    "position": diff[0], "values": sorted(vals)}
        if kind == "classify_fields":
            if not isinstance(op.get("source"), str):
                return {"ok": False, "error": "classify_fields needs `source`"}
            return {"ok": True, "note": "event_type_fields are split group by group through the split check"}
        return {"ok": len(op.get("groups") or []) >= 2}
    except (KeyError, TypeError) as exc:
        return {"ok": False, "error": f"operation is missing a parameter: {exc!r}"}
    except Refused as exc:
        return {"ok": False, "error": str(exc)}


def apply(engine: Engine, op: dict, by: str, tier: str | None = None) -> dict:
    """Verify, then apply. Raises Refused when the replay check fails."""
    v = test(engine, op, by)
    if not v.get("ok"):
        engine.store.log_tool(by, "save_operation", op.get("op"), False, str(v.get("error"))[:300])
        raise Refused(v.get("error") or "the replay check failed")
    kind, store, t = op["op"], engine.store, Tools(engine, by)
    slim = {k: v[k] for k in v if k in ("signatures_before", "signatures_after", "pieces", "lines", "template",
                                         "mixed_type_fields_before", "mixed_type_fields_after_worst_piece")}
    if kind == "remask":
        base = health(engine, sorted(engine.source_sigs.get(op["source"], ())))
        res = t.save_mask(op["source"], op["rule"], op.get("note", ""))
        store.decide(op["source"], "remask:prefix", "remasked", by, "verified")
        store.queue_done("grouping-repair", f"remask:{op['source']}")
        oid = store.log_operation(engine.batch_no, kind, op["source"], op, slim, tier or "verified", by, base)
        return {"applied": kind, "operation": oid, "tier": tier or "verified", **res}
    if kind == "split":
        g = t._group(op["group"])
        base = health(engine, [g["signature"]])
        res = t.save_split(op["group"], op["rule"], op.get("note", ""))
        _cool(engine, [g["signature"]] + [p["group"] for p in res["pieces"]])
        oid = store.log_operation(engine.batch_no, kind, g["signature"], op, slim, tier or "verified", by, base)
        return {"applied": kind, "operation": oid, "tier": tier or "verified", **res}
    if kind == "merge":
        gs = [t._group(x) for x in op["groups"]]
        base = health(engine, [g["signature"] for g in gs])
        canon = engine._merge_groups(gs[0]["bucket"], v["template"].split(), gs)
        store.begin()
        engine._flush()
        store.commit()
        engine.replay_signatures([canon["signature"]], restat=True)
        _cool(engine, [canon["signature"]])
        store.decide(gs[0]["bucket"], "merge:" + "|".join(sorted(g["template"] for g in gs))[:300], "merged", by, "verified")
        store.queue_done("grouping-repair", "merge:" + ":".join(sorted(g["signature"] for g in gs)))
        oid = store.log_operation(engine.batch_no, kind, canon["signature"],
                                  {**op, "members": [g["signature"] for g in gs]}, slim, tier or "verified", by, base)
        return {"applied": kind, "operation": oid, "tier": tier or "verified", "group": canon["signature"]}
    if kind == "keep_separate":
        gs = [t._group(x) for x in op["groups"]]
        store.decide(gs[0]["bucket"], "merge:" + "|".join(sorted(g["template"] for g in gs))[:300], "separate", by,
                     tier or "plausible")
        store.queue_done("grouping-repair", "merge:" + ":".join(sorted(g["signature"] for g in gs)))
        return {"applied": kind, "tier": tier or "plausible"}
    # classify_fields
    source = op["source"]
    done = {"split": [], "refused": [], "value_fields": [], "held": []}
    for f in op.get("value_fields") or []:
        store.decide(source, f"field:{f}", "field_value", by, tier or "plausible")
        done["value_fields"].append(f)
    for f in op.get("uncertain") or []:
        store.decide(source, f"field:{f}", "uncertain", by, "hold")
        store.reopen("human-review", f"field:{source}:{f}", {
            "source": source, "field": f, "question": f"Does field `{f}` define the event type, or is it a field value?",
            "asked_by": by})
        done["held"].append(f)
    for f in op.get("event_type_fields") or []:
        store.decide(source, f"field:{f}", "event_type", by, tier or "verified")
        for gid in sorted(engine.source_sigs.get(source, ())):
            g = engine.groups.get(gid)
            if not g or g["merged_into"] or g["status"] == "split" or g["detail"].get("parent") or not g["parser_rule"]:
                continue
            if f not in (g["detail"].get("ambiguous") or []):
                continue
            try:
                r = apply(engine, {"op": "split", "group": gid, "rule": {"fields": [f]}}, by, "verified")
                done["split"].append({"group": gid, "field": f, "pieces": len(r["pieces"])})
            except Refused as exc:
                done["refused"].append({"group": gid, "field": f, "why": str(exc)[:160]})
    store.queue_done("grouping-repair", f"fields:{source}")
    return {"applied": kind, "tier": tier or "plausible", **done}


# ---------------------------------------------------------------- auto-rollback
def review(engine: Engine) -> list:
    """Compare each recent operation's groups with their health before it.
    Worse by more than the allowed drop: undo it."""
    out = []
    store, s = engine.store, engine.settings
    for o in store.q("SELECT * FROM operations WHERE status='applied' AND op IN ('split','remask','merge')"):
        if engine.batch_no - o["batch"] < s.cooldown_batches:
            continue
        base = json.loads(o["baseline"])
        params = json.loads(o["params"])
        if o["op"] == "split":
            gids = [g["signature"] for g in engine.children(o["target"])]
        elif o["op"] == "remask":
            gids = sorted(engine.source_sigs.get(o["target"], ()))
        else:
            gids = [o["target"]]
        now = health(engine, gids)
        worse = base.get("lines") and (base["valid"] - now["valid"] > s.rollback_drop
                                       or base["parsed"] - now["parsed"] > s.rollback_drop)
        if not worse:
            store.x("UPDATE operations SET status='kept' WHERE id=?", (o["id"],))
            out.append({"operation": o["id"], "op": o["op"], "decision": "kept", "before": base, "after": now})
            continue
        if o["op"] == "split":
            rid = "split:" + o["target"]
            cur = store.active_rule(rid)
            if cur:
                store.set_rule_status(rid, cur["version"], "retired")
            engine.resplit(o["target"])
        elif o["op"] == "remask":
            kind = "sign" if any(k in params["rule"] for k in ("keys", "discriminators", "core_keys")) else "mask"
            from .tools import _slug
            rid = f"{kind}:{_slug(o['target'])}"
            cur = store.active_rule(rid)
            if cur:
                store.set_rule_status(rid, cur["version"], "retired")
            engine.replay_source(o["target"])
        else:
            out.append({"operation": o["id"], "op": "merge", "decision": "worse, needs a human",
                        "before": base, "after": now})
            store.reopen("human-review", f"operation:{o['id']}", {"question": "A merge made a group's health worse; "
                         "it cannot be undone automatically.", "before": base, "after": now})
            store.x("UPDATE operations SET status='kept' WHERE id=?", (o["id"],))
            continue
        store.x("UPDATE operations SET status='rolled_back' WHERE id=?", (o["id"],))
        store.log_operation(engine.batch_no, "rollback", o["target"], {"of": o["id"]}, {"before": base, "after": now},
                            "verified", "code", status="kept")
        _cool(engine, (gids + [o["target"]]) if o["op"] != "remask" else [])
        out.append({"operation": o["id"], "op": o["op"], "decision": "rolled_back", "before": base, "after": now})
    return out


def after_batch(engine: Engine, touched: set) -> dict:
    out = scan(engine, touched)
    out["reviewed"] = len(review(engine))
    return out


def tiers(store) -> dict:
    """Share of decisions and operations per confidence tier."""
    d = {r["tier"]: r["n"] for r in store.q("SELECT tier, COUNT(*) n FROM decisions GROUP BY tier")}
    o = {r["tier"]: r["n"] for r in store.q("SELECT tier, COUNT(*) n FROM operations GROUP BY tier")}
    by = {f"{r['op']}/{r['status']}": r["n"] for r in store.q("SELECT op, status, COUNT(*) n FROM operations GROUP BY 1,2")}
    return {"decisions": d, "operations": o, "operations_by_kind": by,
            "held_for_human": store.q("SELECT COUNT(*) n FROM queue WHERE name='human-review' AND status='open'")[0]["n"]}
