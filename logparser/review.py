"""Review loop: human corrections to AI-written rules.

A reviewer replaces a rule body and says why. The corrected rule goes through
the same validation as any other rule and becomes the active version. The
correction is stored, and the agent harness shows the most recent corrections
of that kind to the agent the next time it runs.

  python -m logparser.review --db run.db pending
  python -m logparser.review --db run.db correct mapping:SIG --file fixed.json --why "status was inverted" --author ana
"""
from __future__ import annotations

import argparse
import json
import time

from . import registry

ROLE = {"mask": "mask-repair", "sign": "mask-repair", "parser": "parser-gen", "mapping": "ocsf-mapping"}


def pending(store) -> list:
    """AI-written mappings no human has looked at yet."""
    out = []
    for r in store.rules("mapping"):
        if r["meta"].get("needs_human_review") and not r["meta"].get("reviewed_by"):
            out.append({"rule_id": r["rule_id"], "version": r["version"], "class": r["body"].get("class"),
                        "created_by": r["meta"].get("created_by"),
                        "low_confidence": [f["to"] for f in r["body"].get("fields", [])
                                           if f.get("confidence") == "low"]})
    return out


def correct(engine, rule_id: str, body: dict, why: str, author: str) -> dict:
    kind = registry.kind_of(rule_id)
    old = engine.store.active_rule(rule_id)
    version = registry.save_rule(engine.store, rule_id, body, {
        "created_by": f"human:{author}", "reviewed_by": author, "note": why})
    engine.store.x("INSERT INTO corrections(at,kind,target,body,author) VALUES(?,?,?,?,?)", (
        time.time(), ROLE.get(kind, kind), rule_id,
        json.dumps({"why": why, "before": old["body"] if old else None, "after": body}, ensure_ascii=False), author))
    sigs = [g["signature"] for g in engine.store.groups("parser_rule=? OR mapping_rule=?", (rule_id, rule_id))]
    return {"rule_id": rule_id, "version": version, "replay": engine.replay_signatures(sigs)}


def approve(store, rule_id: str, author: str) -> None:
    r = store.active_rule(rule_id)
    if not r:
        raise registry.RuleError(f"no active rule {rule_id}")
    meta = {**r["meta"], "reviewed_by": author, "reviewed_at": time.time()}
    store.x("UPDATE rules SET meta=? WHERE rule_id=? AND version=?", (json.dumps(meta), rule_id, r["version"]))


# ---------------------------------------------------------------- the reviewer's inbox
AGENT_QUEUES = {"needs-detection": "detection", "needs-source": "source-naming", "grouping-repair": "grouping-repair",
                "needs-parser": "parser-gen", "needs-mapping": "ocsf-mapping", "longtail": "longtail",
                "needs-lsfilter": "ls-direct"}


def _group_view(engine, sig: str | None) -> dict | None:
    g = engine.canonical(sig) if sig else None
    if not g:
        return None
    return {"signature": g["signature"], "source": g["source"], "format": g["format"], "count": g["count"],
            "template": (g["template"] or "")[:400], "status": g["status"], "labels": g.get("labels") or {},
            "rules": [r for r in (g["parser_rule"], g["mapping_rule"],
                                  "lsfilter:" + g["signature"] if engine.snap.rule("lsfilter:" + g["signature"]) else None)
                      if r],
            "samples": [s["raw"][:600] for s in engine.store.samples(g["signature"])[:4]]}


def _sig_of(name: str, key: str, payload: dict) -> str | None:
    if isinstance(payload.get("signature"), str):
        return payload["signature"]
    if name == "human-review" and key.startswith(("audit:", "lsaudit:")):
        return key.split(":", 1)[1]
    return None


def inbox(engine, limit: int = 200) -> list:
    """Everything waiting for a person: items an agent gave up on (flagged) and human-review questions."""
    rows = engine.store.q("SELECT name, key, status, payload, created_at, done_at, attempts FROM queue WHERE "
                          "(status='flagged') OR (name='human-review' AND status='open') "
                          "ORDER BY COALESCE(done_at, created_at) DESC LIMIT ?", (limit,))
    out = []
    for r in rows:
        p = json.loads(r["payload"])
        sig = _sig_of(r["name"], r["key"], p)
        why = p.get("question") or p.get("flag_reason") or p.get("reason") or ""
        out.append({"name": r["name"], "key": r["key"], "status": r["status"], "at": r["done_at"] or r["created_at"],
                    "attempts": r["attempts"], "why": str(why)[:1500], "agent": AGENT_QUEUES.get(r["name"]),
                    "examples": (p.get("examples") or [])[:4], "group": _group_view(engine, sig)})
    return out


def _owner_queue(engine, name: str, key: str, payload: dict) -> str | None:
    """Which agent queue an answer goes to."""
    if name in AGENT_QUEUES:
        return name
    if key.startswith("lsaudit:"):
        return "needs-lsfilter"
    if key.startswith("audit:"):
        rule = str(payload.get("current_rule") or "")
        return "longtail" if rule.startswith("longtail:") else (
            "needs-mapping" if payload.get("current_mapping") and rule.startswith("parser:") else "needs-parser")
    return None


def answer(engine, name: str, key: str, text: str, author: str = "reviewer") -> dict:
    """A person answers an item. Group items go back to their agent with the answer (and the answer is kept
    as a correction the agent sees on later items too); other questions become decisions."""
    text = (text or "").strip()
    if not text:
        raise ValueError("an answer is needed")
    rows = engine.store.q("SELECT payload, status FROM queue WHERE name=? AND key=?", (name, key))
    if not rows:
        raise ValueError(f"no such item {name}/{key}")
    payload = json.loads(rows[0]["payload"])
    owner = _owner_queue(engine, name, key, payload)
    sig = _sig_of(name, key, payload)
    question = str(payload.get("question") or payload.get("flag_reason") or payload.get("reason") or "")[:900]
    if owner and sig:
        role = AGENT_QUEUES[owner]
        engine.store.x("INSERT INTO corrections(at,kind,target,body,author) VALUES(?,?,?,?,?)", (
            time.time(), role, sig, json.dumps({"question": question, "answer": text}, ensure_ascii=False), author))
        new = {k: v for k, v in payload.items() if k not in ("flag_reason", "question")}
        new = {"human_answer": text[:1500], "previous_problem": question, **new, "signature": sig}
        engine.store.reopen(owner, sig, new)
        engine.store.x("UPDATE queue SET attempts=0 WHERE name=? AND key=?", (owner, sig))
        for k in (f"audit_rounds:{sig}", f"lsaudit_rounds:{sig}"):
            engine.store.set_state(k, 0)
        if name != owner:
            engine.store.queue_done(name, key, "answered")
        return {"sent_to": owner, "signature": sig}
    engine.store.x("INSERT INTO decisions(at,scope,question,answer,answered_by,tier) VALUES(?,?,?,?,?,?) "
                   "ON CONFLICT(scope,question) DO UPDATE SET answer=excluded.answer, at=excluded.at, "
                   "answered_by=excluded.answered_by", (time.time(), payload.get("source") or key, question or key,
                                                        text, f"human:{author}", "verified"))
    engine.store.queue_done(name, key, "answered")
    return {"decision": True}


def resolve(engine, name: str, key: str, action: str, author: str = "reviewer") -> dict:
    """dismiss: nothing to do. ignore_group: the group's lines stay unparsed on purpose; no agent takes it up."""
    rows = engine.store.q("SELECT payload FROM queue WHERE name=? AND key=?", (name, key))
    if not rows:
        raise ValueError(f"no such item {name}/{key}")
    payload = json.loads(rows[0]["payload"])
    if action == "ignore_group":
        sig = _sig_of(name, key, payload)
        g = engine.canonical(sig) if sig else None
        if not g:
            raise ValueError("this item is not about a group")
        g["status"] = "ignored"
        engine.store.upsert_group(g)
        engine.store.x("UPDATE queue SET status='dismissed', done_at=? WHERE key=? AND status IN ('open','flagged')",
                       (time.time(), g["signature"]))
    elif action != "dismiss":
        raise ValueError("action is dismiss or ignore_group")
    engine.store.queue_done(name, key, "dismissed")
    engine.store.x("INSERT INTO corrections(at,kind,target,body,author) VALUES(?,?,?,?,?)", (
        time.time(), "review", f"{name}/{key}", json.dumps({"action": action}), author))
    return {"resolved": action}


# ---------------------------------------------------------------- drift
def logstash_failures(clickhouse: tuple, hours: int = 24) -> list:
    """Lines deployed Logstash pipelines failed on, per pipeline and reason (from <db>.ls_failures)."""
    import re as _re
    import urllib.request
    url, db = clickhouse
    if not _re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", db):
        return []
    q = (f"SELECT pipeline, reason, count() n, any(message) example, max(at) last FROM {db}.ls_failures "
         f"WHERE at > now() - INTERVAL {int(hours)} HOUR GROUP BY pipeline, reason ORDER BY n DESC LIMIT 50 "
         f"FORMAT JSONEachRow")
    try:
        rows = urllib.request.urlopen(urllib.request.Request(url.rstrip("/") + "/", data=q.encode()), timeout=15)
        return [json.loads(l) for l in rows.read().decode().splitlines()]
    except Exception:
        return []


def drift(engine, recent_batches: int = 50, clickhouse: tuple | None = None) -> dict:
    """Signs that a known format changed:
    - rule failing: groups whose Variant A rule started failing on new lines (engine status `drift`)
    - new key sets: structured groups that absorbed new key combinations (drift-linked signatures)
    - new format from a known source: groups first seen recently whose source already has deployed groups
    - went quiet: deployed groups with no lines for `recent_batches` batches
    plus the last Variant B audit (newest lines through each saved Logstash filter)."""
    e = engine
    now = e.batch_no
    deployed = set(e.store.get_state("deployed_groups", []) or [])
    has_rule = lambda g: bool(g["parser_rule"] or e.snap.rule("lsfilter:" + g["signature"]))
    live = [g for g in e.groups.values() if not g["merged_into"] and g["status"] != "ignored"]
    by_source: dict = {}
    for g in live:
        if has_rule(g):
            by_source.setdefault(g["source"], []).append(g["signature"])
    row = lambda g, **k: {"signature": g["signature"], "source": g["source"], "format": g["format"],
                          "count": g["count"], "template": (g["template"] or "")[:200], **k}
    return {
        "batch": now,
        "rule_failing": [row(g, failures=g["parse_failures"], rule=g["parser_rule"])
                         for g in live if g["status"] == "drift"],
        "new_key_sets": [row(g, new_signatures=g["detail"].get("drift_signatures", 0))
                         for g in live if g["detail"].get("drift_signatures") and has_rule(g)],
        "new_format_known_source": [row(g, first_batch=g["first_batch"], known_groups=len(by_source[g["source"]]))
                                    for g in live if not has_rule(g) and g["source"] in by_source
                                    and (g["first_batch"] or 0) >= now - recent_batches and g["count"] >= 2],
        "went_quiet": [row(g, last_batch=g["last_batch"]) for g in live
                       if g["signature"] in deployed and now - (g["last_batch"] or 0) >= recent_batches],
        "last_lsaudit": e.store.get_state("last_lsaudit", None),
        "logstash_failures": logstash_failures(clickhouse) if clickhouse else [],
    }


def main(argv=None) -> None:
    from .cli import open_engine
    ap = argparse.ArgumentParser(prog="logparser.review")
    ap.add_argument("--db", required=True)
    ap.add_argument("--settings")
    ap.add_argument("cmd", choices=["pending", "correct", "approve", "inbox", "drift"])
    ap.add_argument("rule_id", nargs="?")
    ap.add_argument("--file")
    ap.add_argument("--why", default="")
    ap.add_argument("--author", default="reviewer")
    a = ap.parse_args(argv)
    eng = open_engine(a)
    if a.cmd == "inbox":
        print(json.dumps(inbox(eng), indent=1, default=str))
    elif a.cmd == "drift":
        print(json.dumps(drift(eng), indent=1, default=str))
    elif a.cmd == "pending":
        print(json.dumps(pending(eng.store), indent=1))
    elif a.cmd == "approve":
        approve(eng.store, a.rule_id, a.author)
        print("approved")
    else:
        print(json.dumps(correct(eng, a.rule_id, json.load(open(a.file)), a.why, a.author), indent=1))


if __name__ == "__main__":
    main()
