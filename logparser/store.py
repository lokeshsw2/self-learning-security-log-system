"""Storage interface and its SQLite implementation.

The engine talks only to the `Store` methods. A Postgres implementation can
replace `SqliteStore` later without touching the engine. JSON export/import of
the registry is in registry.py and uses only these methods.
"""
from __future__ import annotations

import json
import sqlite3
import time
from typing import Any, Iterable

SCHEMA = """
CREATE TABLE IF NOT EXISTS rules (
  rule_id TEXT NOT NULL, version INTEGER NOT NULL, kind TEXT NOT NULL,
  status TEXT NOT NULL,              -- active | shadow | retired | rejected
  body TEXT NOT NULL, meta TEXT NOT NULL, created_at REAL NOT NULL,
  PRIMARY KEY (rule_id, version));
CREATE INDEX IF NOT EXISTS rules_kind ON rules(kind, status);

CREATE TABLE IF NOT EXISTS groups (
  signature TEXT PRIMARY KEY, bucket TEXT NOT NULL, source TEXT NOT NULL,
  format TEXT NOT NULL, template TEXT NOT NULL, detail TEXT NOT NULL,
  count INTEGER NOT NULL DEFAULT 0, first_batch INTEGER, last_batch INTEGER,
  status TEXT NOT NULL,              -- new | queued | parsed | mapped | longtail | merged | drift
  parser_rule TEXT, mapping_rule TEXT, merged_into TEXT, drift_of TEXT,
  labels TEXT NOT NULL DEFAULT '{}', parse_failures INTEGER NOT NULL DEFAULT 0);
CREATE INDEX IF NOT EXISTS groups_bucket ON groups(bucket);
CREATE INDEX IF NOT EXISTS groups_source ON groups(source);

-- In `groups`, `raw`, `events` and `samples` the column named `signature` holds the
-- GROUP ID. A group id is stable; the signatures that lead to it are in group_signatures.
CREATE TABLE IF NOT EXISTS group_signatures (signature TEXT PRIMARY KEY, group_id TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS gs_group ON group_signatures(group_id);

CREATE TABLE IF NOT EXISTS samples (
  signature TEXT NOT NULL, raw_id INTEGER NOT NULL, raw TEXT NOT NULL,
  tag TEXT NOT NULL DEFAULT 'diverse',      -- diverse | recent | failure | value:<field>=<value>
  masked TEXT, PRIMARY KEY (signature, raw_id));

CREATE TABLE IF NOT EXISTS families (
  id TEXT PRIMARY KEY, bucket TEXT NOT NULL, keys TEXT NOT NULL, n INTEGER NOT NULL, label TEXT);
CREATE TABLE IF NOT EXISTS family_keys (keyhash TEXT PRIMARY KEY, family_id TEXT NOT NULL);

CREATE TABLE IF NOT EXISTS group_stats (group_id TEXT PRIMARY KEY, stats TEXT NOT NULL);

CREATE TABLE IF NOT EXISTS decisions (
  id INTEGER PRIMARY KEY, at REAL NOT NULL, scope TEXT NOT NULL, question TEXT NOT NULL,
  answer TEXT NOT NULL, answered_by TEXT NOT NULL, tier TEXT NOT NULL,   -- verified | plausible | hold
  UNIQUE (scope, question));

CREATE TABLE IF NOT EXISTS operations (
  id INTEGER PRIMARY KEY, at REAL NOT NULL, batch INTEGER NOT NULL, op TEXT NOT NULL, target TEXT NOT NULL,
  params TEXT NOT NULL, verification TEXT NOT NULL, tier TEXT NOT NULL, by TEXT NOT NULL,
  status TEXT NOT NULL,              -- applied | kept | rolled_back
  baseline TEXT NOT NULL DEFAULT '{}');

CREATE TABLE IF NOT EXISTS raw (
  id INTEGER PRIMARY KEY, stream TEXT NOT NULL, offset INTEGER NOT NULL,
  source TEXT NOT NULL, signature TEXT, status TEXT NOT NULL,
  -- parsed | pending | dlq | quarantined | binary | longtail
  batch INTEGER NOT NULL, raw TEXT, blob BLOB);
CREATE INDEX IF NOT EXISTS raw_sig ON raw(signature);
CREATE INDEX IF NOT EXISTS raw_source ON raw(source, status);

CREATE TABLE IF NOT EXISTS events (
  raw_id INTEGER PRIMARY KEY, signature TEXT NOT NULL, fields TEXT NOT NULL,
  ocsf TEXT, class_uid INTEGER, valid INTEGER, errors TEXT,
  parser_rule TEXT, mapping_rule TEXT, tags TEXT NOT NULL DEFAULT '[]',
  parser_version INTEGER, mapping_version INTEGER);
CREATE INDEX IF NOT EXISTS events_sig ON events(signature);

CREATE TABLE IF NOT EXISTS dlq (
  raw_id INTEGER NOT NULL, stage TEXT NOT NULL, reason TEXT NOT NULL,
  signature TEXT, batch INTEGER, PRIMARY KEY (raw_id, stage));

CREATE TABLE IF NOT EXISTS queue (
  name TEXT NOT NULL, key TEXT NOT NULL, status TEXT NOT NULL,   -- open | done | flagged
  payload TEXT NOT NULL, created_at REAL NOT NULL, done_at REAL, attempts INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (name, key));

CREATE TABLE IF NOT EXISTS sources (
  source TEXT PRIMARY KEY, lines INTEGER NOT NULL DEFAULT 0,
  signatures INTEGER NOT NULL DEFAULT 0, quarantined INTEGER NOT NULL DEFAULT 0,
  reason TEXT, history TEXT NOT NULL DEFAULT '[]',
  vendor TEXT, product TEXT, source_rule TEXT);

CREATE TABLE IF NOT EXISTS state (key TEXT PRIMARY KEY, value TEXT NOT NULL);

CREATE TABLE IF NOT EXISTS shadow (
  rule_id TEXT NOT NULL, version INTEGER NOT NULL, lines INTEGER NOT NULL DEFAULT 0,
  ok INTEGER NOT NULL DEFAULT 0, last_error TEXT, PRIMARY KEY (rule_id, version));

CREATE TABLE IF NOT EXISTS tool_calls (
  id INTEGER PRIMARY KEY, at REAL NOT NULL, agent TEXT NOT NULL, tool TEXT NOT NULL,
  target TEXT, ok INTEGER NOT NULL, detail TEXT, tokens_in INTEGER DEFAULT 0, tokens_out INTEGER DEFAULT 0);

CREATE TABLE IF NOT EXISTS corrections (
  id INTEGER PRIMARY KEY, at REAL NOT NULL, kind TEXT NOT NULL, target TEXT NOT NULL,
  body TEXT NOT NULL, author TEXT NOT NULL);
"""


def _j(v: Any) -> str:
    return json.dumps(v, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


class Store:
    """Interface. See SqliteStore for the meaning of each method."""


class SqliteStore(Store):
    def __init__(self, path: str):
        self.path = path
        self.db = sqlite3.connect(path, timeout=60, isolation_level=None)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=NORMAL")
        self.db.execute("PRAGMA busy_timeout=60000")
        self.db.executescript(SCHEMA)
        cols = {r[1] for r in self.db.execute("PRAGMA table_info(sources)")}
        for c in ("vendor", "product", "source_rule"):
            if c not in cols:
                self.db.execute(f"ALTER TABLE sources ADD COLUMN {c} TEXT")

    # ------------------------------------------------------------ transactions
    def begin(self) -> None:
        self.db.execute("BEGIN IMMEDIATE")

    def commit(self) -> None:
        self.db.execute("COMMIT")

    def rollback(self) -> None:
        self.db.execute("ROLLBACK")

    def close(self) -> None:
        self.db.close()

    def q(self, sql: str, args: Iterable = ()) -> list[sqlite3.Row]:
        return self.db.execute(sql, tuple(args)).fetchall()

    def x(self, sql: str, args: Iterable = ()) -> sqlite3.Cursor:
        return self.db.execute(sql, tuple(args))

    # ------------------------------------------------------------ key/value state
    def get_state(self, key: str, default: Any = None) -> Any:
        r = self.q("SELECT value FROM state WHERE key=?", (key,))
        return json.loads(r[0]["value"]) if r else default

    def set_state(self, key: str, value: Any) -> None:
        self.x("INSERT INTO state(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
               (key, _j(value)))

    def bump_generation(self) -> int:
        g = int(self.get_state("registry_generation", 0)) + 1
        self.set_state("registry_generation", g)
        return g

    # ------------------------------------------------------------ rules
    def rule_versions(self, rule_id: str) -> list[dict]:
        return [self._rule(r) for r in self.q("SELECT * FROM rules WHERE rule_id=? ORDER BY version", (rule_id,))]

    def active_rule(self, rule_id: str) -> dict | None:
        r = self.q("SELECT * FROM rules WHERE rule_id=? AND status='active'", (rule_id,))
        return self._rule(r[0]) if r else None

    def rules(self, kind: str | None = None, status: str = "active") -> list[dict]:
        if kind:
            rows = self.q("SELECT * FROM rules WHERE kind=? AND status=? ORDER BY rule_id", (kind, status))
        else:
            rows = self.q("SELECT * FROM rules WHERE status=? ORDER BY kind, rule_id", (status,))
        return [self._rule(r) for r in rows]

    def insert_rule(self, rule_id: str, kind: str, body: dict, meta: dict, status: str) -> int:
        r = self.q("SELECT COALESCE(MAX(version),0) v FROM rules WHERE rule_id=?", (rule_id,))
        version = r[0]["v"] + 1
        if status == "active":
            self.x("UPDATE rules SET status='retired' WHERE rule_id=? AND status='active'", (rule_id,))
        self.x("INSERT INTO rules VALUES(?,?,?,?,?,?,?)",
               (rule_id, version, kind, status, _j(body), _j(meta), time.time()))
        self.bump_generation()
        return version

    def set_rule_status(self, rule_id: str, version: int, status: str) -> None:
        if status == "active":
            self.x("UPDATE rules SET status='retired' WHERE rule_id=? AND status='active'", (rule_id,))
        self.x("UPDATE rules SET status=? WHERE rule_id=? AND version=?", (status, rule_id, version))
        self.bump_generation()

    @staticmethod
    def _rule(r: sqlite3.Row) -> dict:
        return {"rule_id": r["rule_id"], "version": r["version"], "kind": r["kind"], "status": r["status"],
                "body": json.loads(r["body"]), "meta": json.loads(r["meta"]), "created_at": r["created_at"]}

    # ------------------------------------------------------------ groups
    def group(self, signature: str) -> dict | None:
        r = self.q("SELECT * FROM groups WHERE signature=?", (signature,))
        return self._group(r[0]) if r else None

    def groups(self, where: str = "1=1", args: Iterable = ()) -> list[dict]:
        return [self._group(r) for r in self.q(f"SELECT * FROM groups WHERE {where} ORDER BY signature", args)]

    def upsert_group(self, g: dict) -> None:
        self.x("""INSERT INTO groups(signature,bucket,source,format,template,detail,count,first_batch,last_batch,
                  status,parser_rule,mapping_rule,merged_into,drift_of,labels,parse_failures)
                  VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                  ON CONFLICT(signature) DO UPDATE SET count=excluded.count,last_batch=excluded.last_batch,
                  status=excluded.status,parser_rule=excluded.parser_rule,mapping_rule=excluded.mapping_rule,
                  merged_into=excluded.merged_into,drift_of=excluded.drift_of,labels=excluded.labels,
                  parse_failures=excluded.parse_failures,template=excluded.template,detail=excluded.detail,
                  source=excluded.source""",
               (g["signature"], g["bucket"], g["source"], g["format"], g["template"], _j(g.get("detail") or {}),
                g["count"], g.get("first_batch"), g.get("last_batch"), g["status"], g.get("parser_rule"),
                g.get("mapping_rule"), g.get("merged_into"), g.get("drift_of"), _j(g.get("labels") or {}),
                g.get("parse_failures", 0)))

    @staticmethod
    def _group(r: sqlite3.Row) -> dict:
        d = dict(r)
        d["detail"] = json.loads(d["detail"])
        d["labels"] = json.loads(d["labels"])
        return d

    def samples(self, signature: str, tags: bool = False) -> list[dict]:
        """Sample lines of a group. Without `tags`, failures are left out."""
        rows = self.q("SELECT raw_id, raw, tag, masked FROM samples WHERE signature=? ORDER BY raw_id", (signature,))
        return [dict(r) for r in rows if tags or r["tag"] != "failure"]

    def replace_samples(self, signature: str, samples: list) -> None:
        """samples: (raw_id, raw) or (raw_id, raw, tag, masked)."""
        self.x("DELETE FROM samples WHERE signature=?", (signature,))
        self.db.executemany("INSERT OR IGNORE INTO samples(signature,raw_id,raw,tag,masked) VALUES(?,?,?,?,?)",
                            [(signature, s[0], s[1], s[2] if len(s) > 2 else "diverse", s[3] if len(s) > 3 else None)
                             for s in samples])

    # ------------------------------------------------------------ signatures, stats, decisions, operations
    def signature_map(self) -> dict:
        return {r["signature"]: r["group_id"] for r in self.q("SELECT signature, group_id FROM group_signatures")}

    def put_signatures(self, rows: list) -> None:
        self.db.executemany("INSERT INTO group_signatures(signature, group_id) VALUES(?,?) "
                            "ON CONFLICT(signature) DO UPDATE SET group_id=excluded.group_id", rows)

    def stats(self, group_id: str) -> dict:
        r = self.q("SELECT stats FROM group_stats WHERE group_id=?", (group_id,))
        return json.loads(r[0]["stats"]) if r else {}

    def put_stats(self, group_id: str, stats: dict) -> None:
        self.x("INSERT INTO group_stats(group_id, stats) VALUES(?,?) ON CONFLICT(group_id) DO UPDATE SET stats=excluded.stats",
               (group_id, _j(stats)))

    def decision(self, scope: str, question: str) -> dict | None:
        r = self.q("SELECT * FROM decisions WHERE scope=? AND question=?", (scope, question))
        return dict(r[0]) if r else None

    def decisions(self, scope_prefix: str = "") -> list:
        return [dict(r) for r in self.q("SELECT * FROM decisions WHERE scope LIKE ? ORDER BY id", (scope_prefix + "%",))]

    def decide(self, scope: str, question: str, answer: str, by: str, tier: str) -> None:
        self.x("INSERT INTO decisions(at,scope,question,answer,answered_by,tier) VALUES(?,?,?,?,?,?) "
               "ON CONFLICT(scope,question) DO UPDATE SET answer=excluded.answer, answered_by=excluded.answered_by, "
               "tier=excluded.tier, at=excluded.at", (time.time(), scope, question, answer, by, tier))

    def log_operation(self, batch: int, op: str, target: str, params: dict, verification: dict, tier: str, by: str,
                      baseline: dict | None = None, status: str = "applied") -> int:
        cur = self.x("INSERT INTO operations(at,batch,op,target,params,verification,tier,by,status,baseline) "
                     "VALUES(?,?,?,?,?,?,?,?,?,?)", (time.time(), batch, op, target, _j(params), _j(verification), tier,
                                                    by, status, _j(baseline or {})))
        return cur.lastrowid

    # ------------------------------------------------------------ raw lines and events
    def next_raw_id(self) -> int:
        return self.q("SELECT COALESCE(MAX(id),0)+1 n FROM raw")[0]["n"]

    def insert_raw(self, rows: list[tuple]) -> None:
        self.db.executemany("INSERT OR REPLACE INTO raw(id,stream,offset,source,signature,status,batch,raw,blob) "
                            "VALUES(?,?,?,?,?,?,?,?,?)", rows)

    def update_raw(self, rows: list[tuple]) -> None:
        """rows: (signature, status, source, id)"""
        self.db.executemany("UPDATE raw SET signature=?, status=?, source=? WHERE id=?", rows)

    def raw_by_signature(self, signature: str, limit: int | None = None) -> list[dict]:
        sql = "SELECT id, raw, status, stream, offset, source FROM raw WHERE signature=? ORDER BY id"
        if limit:
            sql += f" LIMIT {int(limit)}"
        return [dict(r) for r in self.q(sql, (signature,))]

    def raw_by_source(self, source: str) -> list[dict]:
        return [dict(r) for r in self.q(
            "SELECT id, raw, status, stream, offset, source, signature FROM raw WHERE source=? AND blob IS NULL ORDER BY id",
            (source,))]

    def prune(self, keep_parsed: int, keep_unparsed: int) -> int:
        """Keep the newest lines per signature; drop older rows and their events. Samples keep their own copies."""
        dropped = 0
        for status_sql, keep in (("status='parsed'", keep_parsed), ("status<>'parsed'", keep_unparsed)):
            if keep <= 0:
                continue
            cur = self.db.execute(
                f"DELETE FROM raw WHERE id IN (SELECT id FROM (SELECT id, ROW_NUMBER() OVER "
                f"(PARTITION BY signature ORDER BY id DESC) rn FROM raw WHERE {status_sql}) WHERE rn > ?)", (keep,))
            dropped += cur.rowcount
        if dropped:
            self.db.execute("DELETE FROM events WHERE raw_id NOT IN (SELECT id FROM raw)")
        return dropped

    def put_events(self, rows: list[tuple]) -> None:
        self.db.executemany("INSERT OR REPLACE INTO events(raw_id,signature,fields,ocsf,class_uid,valid,errors,"
                            "parser_rule,mapping_rule,tags,parser_version,mapping_version) "
                            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)", rows)

    def delete_events(self, raw_ids: list[int]) -> None:
        self.db.executemany("DELETE FROM events WHERE raw_id=?", [(i,) for i in raw_ids])
        self.db.executemany("DELETE FROM dlq WHERE raw_id=?", [(i,) for i in raw_ids])

    def put_dlq(self, rows: list[tuple]) -> None:
        self.db.executemany("INSERT OR REPLACE INTO dlq(raw_id,stage,reason,signature,batch) VALUES(?,?,?,?,?)", rows)

    # ------------------------------------------------------------ queues
    def enqueue(self, name: str, key: str, payload: dict) -> bool:
        cur = self.x("INSERT OR IGNORE INTO queue(name,key,status,payload,created_at) VALUES(?,?,'open',?,?)",
                     (name, key, _j(payload), time.time()))
        return cur.rowcount > 0

    def reopen(self, name: str, key: str, payload: dict) -> None:
        self.x("INSERT INTO queue(name,key,status,payload,created_at) VALUES(?,?,'open',?,?) "
               "ON CONFLICT(name,key) DO UPDATE SET status='open', payload=excluded.payload, "
               "created_at=excluded.created_at, done_at=NULL", (name, key, _j(payload), time.time()))

    def queue_items(self, name: str, status: str = "open") -> list[dict]:
        out = []
        for r in self.q("SELECT * FROM queue WHERE name=? AND status=? ORDER BY created_at, key", (name, status)):
            d = dict(r)
            d["payload"] = json.loads(d["payload"])
            out.append(d)
        return out

    def queue_done(self, name: str, key: str, status: str = "done") -> None:
        self.x("UPDATE queue SET status=?, done_at=? WHERE name=? AND key=?", (status, time.time(), name, key))

    def queue_attempt(self, name: str, key: str) -> int:
        self.x("UPDATE queue SET attempts=attempts+1 WHERE name=? AND key=?", (name, key))
        r = self.q("SELECT attempts FROM queue WHERE name=? AND key=?", (name, key))
        return r[0]["attempts"] if r else 0

    # ------------------------------------------------------------ sources
    def source(self, source: str) -> dict:
        r = self.q("SELECT * FROM sources WHERE source=?", (source,))
        if r:
            d = dict(r[0])
            d["history"] = json.loads(d["history"])
            return d
        return {"source": source, "lines": 0, "signatures": 0, "quarantined": 0, "reason": None, "history": [],
                "vendor": None, "product": None, "source_rule": None}

    def sources(self) -> list[dict]:
        return [self.source(r["source"]) for r in self.q("SELECT source FROM sources ORDER BY source")]

    def put_source(self, s: dict) -> None:
        self.x("INSERT INTO sources(source,lines,signatures,quarantined,reason,history,vendor,product,source_rule) "
               "VALUES(?,?,?,?,?,?,?,?,?) "
               "ON CONFLICT(source) DO UPDATE SET lines=excluded.lines, signatures=excluded.signatures, "
               "quarantined=excluded.quarantined, reason=excluded.reason, history=excluded.history, "
               "vendor=excluded.vendor, product=excluded.product, source_rule=excluded.source_rule",
               (s["source"], s["lines"], s["signatures"], s["quarantined"], s.get("reason"), _j(s["history"][-200:]),
                s.get("vendor"), s.get("product"), s.get("source_rule")))

    # ------------------------------------------------------------ audit
    def log_tool(self, agent: str, tool: str, target: str | None, ok: bool, detail: str = "",
                 tokens_in: int = 0, tokens_out: int = 0) -> None:
        self.x("INSERT INTO tool_calls(at,agent,tool,target,ok,detail,tokens_in,tokens_out) VALUES(?,?,?,?,?,?,?,?)",
               (time.time(), agent, tool, target, int(ok), detail[:2000], tokens_in, tokens_out))
