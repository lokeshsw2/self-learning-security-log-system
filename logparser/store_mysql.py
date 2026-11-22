"""MySQL 8 implementation of the store (production: the GRA system's MySQL).

  open_store("mysql://user:password@host:3306/database")

The store methods are SqliteStore's; this class swaps the connection and the schema, and translates the
SQLite dialect the code uses (here and in the 80-odd queries elsewhere) into MySQL:

  ?  -> %s                    INSERT OR IGNORE -> INSERT IGNORE      INSERT OR REPLACE -> REPLACE
  ON CONFLICT(..) DO UPDATE SET a=excluded.a  -> ON DUPLICATE KEY UPDATE a=VALUES(a)
  json_extract(x, p)          -> JSON_UNQUOTE(JSON_EXTRACT(x, p))  (the text value, as SQLite returns it)
  reserved column / table names (key, by, groups, lines, fields, keys, blob) -> `quoted`

Text compares byte for byte (utf8mb4_bin), as in SQLite. The connection runs in autocommit mode, like the
SQLite one; begin/commit/rollback bracket the engine's batches.
"""
from __future__ import annotations

import decimal
import re
import threading
import urllib.parse

from .store import SqliteStore

SCHEMA = """
CREATE TABLE IF NOT EXISTS rules (
  rule_id VARCHAR(255) NOT NULL, version INT NOT NULL, kind VARCHAR(64) NOT NULL, status VARCHAR(32) NOT NULL,
  body LONGTEXT NOT NULL, meta LONGTEXT NOT NULL, created_at DOUBLE NOT NULL,
  PRIMARY KEY (rule_id, version), KEY rules_kind (kind, status));
CREATE TABLE IF NOT EXISTS `groups` (
  signature VARCHAR(64) PRIMARY KEY, bucket VARCHAR(512) NOT NULL, source VARCHAR(512) NOT NULL,
  format VARCHAR(64) NOT NULL, template LONGTEXT NOT NULL, detail LONGTEXT NOT NULL,
  count BIGINT NOT NULL DEFAULT 0, first_batch BIGINT, last_batch BIGINT, status VARCHAR(32) NOT NULL,
  parser_rule VARCHAR(255), mapping_rule VARCHAR(255), merged_into VARCHAR(64), drift_of VARCHAR(64),
  labels TEXT NOT NULL, parse_failures INT NOT NULL DEFAULT 0,
  KEY groups_bucket (bucket), KEY groups_source (source));
CREATE TABLE IF NOT EXISTS group_signatures (signature VARCHAR(64) PRIMARY KEY, group_id VARCHAR(64) NOT NULL,
  KEY gs_group (group_id));
CREATE TABLE IF NOT EXISTS samples (
  signature VARCHAR(64) NOT NULL, raw_id BIGINT NOT NULL, raw LONGTEXT NOT NULL,
  tag VARCHAR(512) NOT NULL DEFAULT 'diverse', masked LONGTEXT, PRIMARY KEY (signature, raw_id));
CREATE TABLE IF NOT EXISTS families (
  id VARCHAR(64) PRIMARY KEY, bucket VARCHAR(512) NOT NULL, `keys` LONGTEXT NOT NULL, n INT NOT NULL, label TEXT);
CREATE TABLE IF NOT EXISTS family_keys (keyhash VARCHAR(64) PRIMARY KEY, family_id VARCHAR(64) NOT NULL);
CREATE TABLE IF NOT EXISTS group_stats (group_id VARCHAR(64) PRIMARY KEY, stats LONGTEXT NOT NULL);
CREATE TABLE IF NOT EXISTS decisions (
  id BIGINT AUTO_INCREMENT PRIMARY KEY, at DOUBLE NOT NULL, scope VARCHAR(512) NOT NULL,
  question VARCHAR(1024) NOT NULL, answer LONGTEXT NOT NULL, answered_by VARCHAR(255) NOT NULL,
  tier VARCHAR(32) NOT NULL, UNIQUE KEY decisions_q (scope(255), question(450)));
CREATE TABLE IF NOT EXISTS operations (
  id BIGINT AUTO_INCREMENT PRIMARY KEY, at DOUBLE NOT NULL, batch BIGINT NOT NULL, op VARCHAR(64) NOT NULL,
  target VARCHAR(512) NOT NULL, params LONGTEXT NOT NULL, verification LONGTEXT NOT NULL, tier VARCHAR(32) NOT NULL,
  `by` VARCHAR(255) NOT NULL, status VARCHAR(32) NOT NULL, baseline LONGTEXT NOT NULL);
CREATE TABLE IF NOT EXISTS raw (
  id BIGINT PRIMARY KEY, stream VARCHAR(512) NOT NULL, `offset` BIGINT NOT NULL, source VARCHAR(512) NOT NULL,
  signature VARCHAR(64), status VARCHAR(32) NOT NULL, batch BIGINT NOT NULL, raw LONGTEXT, `blob` LONGBLOB,
  KEY raw_sig (signature), KEY raw_source (source, status));
CREATE TABLE IF NOT EXISTS events (
  raw_id BIGINT PRIMARY KEY, signature VARCHAR(64) NOT NULL, `fields` LONGTEXT NOT NULL, ocsf LONGTEXT,
  class_uid INT, valid INT, errors LONGTEXT, parser_rule VARCHAR(255), mapping_rule VARCHAR(255),
  tags TEXT NOT NULL, parser_version INT, mapping_version INT, KEY events_sig (signature));
CREATE TABLE IF NOT EXISTS dlq (
  raw_id BIGINT NOT NULL, stage VARCHAR(64) NOT NULL, reason LONGTEXT NOT NULL, signature VARCHAR(64), batch BIGINT,
  PRIMARY KEY (raw_id, stage));
CREATE TABLE IF NOT EXISTS queue (
  name VARCHAR(64) NOT NULL, `key` VARCHAR(512) NOT NULL, status VARCHAR(32) NOT NULL, payload LONGTEXT NOT NULL,
  created_at DOUBLE NOT NULL, done_at DOUBLE, attempts INT NOT NULL DEFAULT 0, PRIMARY KEY (name, `key`));
CREATE TABLE IF NOT EXISTS sources (
  source VARCHAR(512) PRIMARY KEY, `lines` BIGINT NOT NULL DEFAULT 0, signatures BIGINT NOT NULL DEFAULT 0,
  quarantined BIGINT NOT NULL DEFAULT 0, reason LONGTEXT, history LONGTEXT NOT NULL,
  vendor VARCHAR(255), product VARCHAR(255), source_rule VARCHAR(255));
CREATE TABLE IF NOT EXISTS state (`key` VARCHAR(512) PRIMARY KEY, value LONGTEXT NOT NULL);
CREATE TABLE IF NOT EXISTS shadow (
  rule_id VARCHAR(255) NOT NULL, version INT NOT NULL, `lines` BIGINT NOT NULL DEFAULT 0, ok BIGINT NOT NULL DEFAULT 0,
  last_error LONGTEXT, PRIMARY KEY (rule_id, version));
CREATE TABLE IF NOT EXISTS tool_calls (
  id BIGINT AUTO_INCREMENT PRIMARY KEY, at DOUBLE NOT NULL, agent VARCHAR(128) NOT NULL, tool VARCHAR(64) NOT NULL,
  target VARCHAR(512), ok INT NOT NULL, detail LONGTEXT, tokens_in BIGINT DEFAULT 0, tokens_out BIGINT DEFAULT 0,
  KEY tool_calls_agent (agent, tool));
CREATE TABLE IF NOT EXISTS corrections (
  id BIGINT AUTO_INCREMENT PRIMARY KEY, at DOUBLE NOT NULL, kind VARCHAR(64) NOT NULL, target VARCHAR(512) NOT NULL,
  body LONGTEXT NOT NULL, author VARCHAR(255) NOT NULL);
"""
# text columns with a SQLite default: MySQL allows no default on TEXT, so inserts that leave them out get one here
TEXT_DEFAULTS = {"groups": {"labels": "{}"}, "events": {"tags": "[]"}, "operations": {"baseline": "{}"},
                 "sources": {"history": "[]"}}

RESERVED = {"key", "by", "groups", "lines", "fields", "keys", "blob", "offset"}
_LIT = re.compile(r"('(?:[^']|'')*')")
_WORD = re.compile(r"(?<![`.\w])([A-Za-z_]+)(?![`\w])")


def _quote_words(seg: str) -> str:
    def q(m):
        w = m.group(1)
        if w.lower() not in RESERVED:
            return w
        before = seg[:m.start()].rstrip().upper()
        after = seg[m.end():].lstrip().upper()
        if w.lower() == "by" and before.endswith(("ORDER", "GROUP", "PARTITION")):
            return w
        if w.lower() == "key" and (before.endswith(("PRIMARY", "DUPLICATE", "UNIQUE", "FOREIGN")) or after.startswith("UPDATE")):
            return w
        return f"`{w}`"
    return _WORD.sub(q, seg)


def _json_extract(sql: str) -> str:
    out, i, low = [], 0, sql.lower()
    while True:
        j = low.find("json_extract(", i)
        if j < 0:
            out.append(sql[i:])
            return "".join(out)
        depth, k = 0, j + len("json_extract")
        while k < len(sql):
            if sql[k] == "(":
                depth += 1
            elif sql[k] == ")":
                depth -= 1
                if depth == 0:
                    break
            k += 1
        out.append(sql[i:j] + "JSON_UNQUOTE(JSON_EXTRACT" + sql[j + len("json_extract"):k + 1] + ")")
        i = k + 1


_CONFLICT = re.compile(r"ON\s+CONFLICT\s*\([^)]*\)\s*DO\s+UPDATE\s+SET", re.I)
_NOTHING = re.compile(r"ON\s+CONFLICT\s*(\([^)]*\))?\s*DO\s+NOTHING", re.I)


def translate(sql: str) -> str:
    """SQLite dialect (as this code writes it) -> MySQL 8."""
    parts = _LIT.split(sql)
    for n in range(1, len(parts), 2):          # PyMySQL formats the whole statement: a % in a literal too
        parts[n] = parts[n].replace("%", "%%")
    for n in range(0, len(parts), 2):          # outside string literals only
        s = parts[n].replace("%", "%%").replace("?", "%s")
        s = re.sub(r"\bINSERT\s+OR\s+IGNORE\b", "INSERT IGNORE", s, flags=re.I)
        s = re.sub(r"\bINSERT\s+OR\s+REPLACE\b", "REPLACE", s, flags=re.I)
        if _NOTHING.search(s):
            s = _NOTHING.sub("", s)
            s = re.sub(r"\bINSERT\s+INTO\b", "INSERT IGNORE INTO", s, count=1, flags=re.I)
        s = _CONFLICT.sub("ON DUPLICATE KEY UPDATE", s)
        s = re.sub(r"\bexcluded\.(\w+)", r"VALUES(\1)", s, flags=re.I)
        s = re.sub(r"\bjson_set\(", "JSON_SET(", s, flags=re.I)
        parts[n] = _quote_words(s)
    out = "".join(parts)
    return _json_extract(out) if "json_extract(" in out.lower() else out


class Row(dict):
    """A result row usable like sqlite3.Row: by column name or by position."""
    __slots__ = ("_vals",)

    def __init__(self, d: dict):
        # MySQL returns SUM/AVG as Decimal and text in binary collation as bytes; SQLite gives int/float/str
        d = {k: (int(v) if v == v.to_integral_value() else float(v)) if isinstance(v, decimal.Decimal) else v
             for k, v in d.items()}
        super().__init__(d)
        self._vals = list(d.values())

    def __getitem__(self, k):
        if isinstance(k, int):
            return self._vals[k]
        return dict.__getitem__(self, k)

    def keys(self):
        return dict.keys(self)


class _Cursor:
    def __init__(self, cur):
        self.c = cur

    def fetchall(self):
        return [Row(r) for r in self.c.fetchall()]

    def fetchone(self):
        r = self.c.fetchone()
        return Row(r) if r is not None else None

    @property
    def rowcount(self):
        return self.c.rowcount

    @property
    def lastrowid(self):
        return self.c.lastrowid


def _with_defaults(sql: str, rows):
    """Fill the TEXT defaults MySQL cannot declare, for INSERTs that leave those columns out."""
    m = re.match(r"\s*(?:INSERT(?:\s+OR\s+\w+)?|REPLACE)\s+INTO\s+(\w+)\s*\(([^)]*)\)\s*VALUES\s*\(([^)]*)\)", sql, re.I)
    if not m or m.group(1) not in TEXT_DEFAULTS:
        return sql, rows
    cols = [c.strip() for c in m.group(2).split(",")]
    add = {c: v for c, v in TEXT_DEFAULTS[m.group(1)].items() if c not in cols}
    if not add:
        return sql, rows
    lits = ",".join("'" + v.replace("'", "''") + "'" for v in add.values())
    sql = sql[:m.start(2)] + m.group(2) + "," + ",".join(add) + sql[m.end(2):m.start(3)] + m.group(3) + "," + lits + sql[m.end(3):]
    return sql, rows


class _Conn:
    """The parts of a sqlite3 connection the store and its callers use, on a PyMySQL connection."""

    def __init__(self, params: dict):
        import pymysql
        self._pymysql = pymysql
        self.params = params
        self.lock = threading.RLock()
        self.cx = self._connect()

    def _connect(self):
        p = self._pymysql
        return p.connect(**self.params, autocommit=True, charset="utf8mb4",
                         cursorclass=p.cursors.DictCursor, client_flag=p.constants.CLIENT.MULTI_STATEMENTS)

    def _run(self, fn):
        with self.lock:
            try:
                return fn()
            except self._pymysql.err.OperationalError as exc:      # a dropped connection: reconnect once
                if exc.args and exc.args[0] in (2006, 2013) and self.cx.get_autocommit():
                    self.cx = self._connect()
                    return fn()
                raise

    def execute(self, sql: str, args=()):
        sql, _ = _with_defaults(sql, None)
        t = translate(sql)

        def go():
            cur = self.cx.cursor()
            cur.execute(t, tuple(args))
            return _Cursor(cur)
        return self._run(go)

    def executemany(self, sql: str, rows):
        sql, _ = _with_defaults(sql, None)
        t = translate(sql)
        rows = [tuple(r) for r in rows]

        def go():
            cur = self.cx.cursor()
            if rows:
                cur.executemany(t, rows)
            return _Cursor(cur)
        return self._run(go)

    def close(self):
        try:
            self.cx.close()
        except Exception:
            pass


def parse_url(url: str) -> dict:
    u = urllib.parse.urlparse(url)
    if u.scheme not in ("mysql", "mysql+pymysql") or not u.path.strip("/"):
        raise ValueError("MySQL store url: mysql://user:password@host:port/database")
    q = dict(urllib.parse.parse_qsl(u.query))
    p = {"host": u.hostname or "127.0.0.1", "port": u.port or 3306, "user": urllib.parse.unquote(u.username or "root"),
         "password": urllib.parse.unquote(u.password or ""), "database": u.path.strip("/")}
    if q.get("ssl_ca"):
        p["ssl"] = {"ca": q["ssl_ca"]}
    return p


class MySQLStore(SqliteStore):
    def __init__(self, url: str, create_database: bool = False):
        self.url = url
        params = parse_url(url)
        self.path = f"mysql://{params['host']}:{params['port']}/{params['database']}"   # no password in it
        if create_database:
            import pymysql
            cx = pymysql.connect(**{k: v for k, v in params.items() if k != "database"}, autocommit=True)
            with cx.cursor() as c:
                c.execute(f"CREATE DATABASE IF NOT EXISTS `{params['database']}` "
                          "CHARACTER SET utf8mb4 COLLATE utf8mb4_bin")
            cx.close()
        self.db = _Conn(params)
        cur = self.db.cx.cursor()
        for stmt in (s.strip() for s in SCHEMA.split(";")):
            if stmt:
                cur.execute(stmt)

    # transactions: the same brackets as SQLite's BEGIN IMMEDIATE / COMMIT
    def begin(self) -> None:
        self.db.lock.acquire()
        self.db.cx.begin()

    def commit(self) -> None:
        try:
            self.db.cx.commit()
        finally:
            self.db.lock.release()

    def rollback(self) -> None:
        try:
            self.db.cx.rollback()
        finally:
            self.db.lock.release()

    def close(self) -> None:
        self.db.close()

    def export_sqlite(self, dst: str) -> str:
        """A SQLite copy of every table (the deploy check and the comparison open SQLite snapshots)."""
        import os
        import sqlite3
        from .store import SCHEMA as SQLITE_SCHEMA
        for ext in ("", "-wal", "-shm"):
            if os.path.exists(dst + ext):
                os.remove(dst + ext)
        out = sqlite3.connect(dst)
        out.executescript(SQLITE_SCHEMA)
        tables = [r[0] for r in out.execute("SELECT name FROM sqlite_master WHERE type='table'")]
        for t in tables:
            cols = [r[1] for r in out.execute(f"PRAGMA table_info({t})")]
            rows = self.db.execute(f"SELECT {','.join(cols)} FROM {t}").fetchall()
            if rows:
                out.executemany(f"INSERT INTO {t}({','.join(cols)}) VALUES({','.join('?' * len(cols))})",
                                [tuple(r[c] for c in cols) for r in rows])
        out.commit()
        out.close()
        return dst
