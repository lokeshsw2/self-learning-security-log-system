"""Web UI and API around the engine, its rule database, and the ClickHouse event store.

  python -m logparser.web --db work/app.db --port 8090 [--clickhouse http://localhost:8123]

Lines (pasted, uploaded, or read from a stream) go through the engine; parsed OCSF events and
unparsed lines are written to ClickHouse and read back from there. Rules, groups and sources
are read from the engine's database. All engine work runs under one lock.
"""
from __future__ import annotations

import argparse
import json
import os
import threading
import time
import traceback
import types
import urllib.parse
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .cli import open_engine
from .reader import Record
from .sink import ClickHouseSink

HERE = os.path.dirname(os.path.abspath(__file__))
BATCH = 2000


def _esc(v: str) -> str:
    return str(v).replace("\\", "\\\\").replace("'", "\\'")


class App:
    def __init__(self, db: str, settings: str | None, clickhouse: str):
        self.eng = open_engine(types.SimpleNamespace(db=db, settings=settings))
        self.ch = ClickHouseSink(clickhouse)
        self.eng.sink = self.ch
        self.lock = threading.RLock()
        self.streams: dict = {}

    # ------------------------------------------------------------------ ingest
    def ingest(self, lines: list, ingest_id: str | None = None, label: str | None = None) -> dict:
        ingest_id = ingest_id or time.strftime("ui-%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:6]
        lines = [ln.rstrip("\r") for ln in lines if ln.strip()]
        tot: dict = {"ingest_id": ingest_id, "records": 0, "parsed": 0, "pending": 0, "dlq": 0, "new_groups": 0}
        with self.lock:
            for i in range(0, len(lines), BATCH):
                recs = [Record(ingest_id, i + j, text=t, label=label) for j, t in enumerate(lines[i:i + BATCH])]
                st = self.eng.process(recs)
                for k in ("records", "parsed", "pending", "dlq", "new_groups"):
                    tot[k] += st.get(k, 0)
        return tot

    # ------------------------------------------------------------------ streams
    def start_stream(self, kind: str, target: str, label: str | None = None) -> dict:
        sid = uuid.uuid4().hex[:8]
        st = {"id": sid, "kind": kind, "target": target, "label": label, "ingest_id": f"stream-{sid}",
              "lines": 0, "parsed": 0, "pending": 0, "started": time.time(), "error": None, "running": True}
        stop = threading.Event()
        st["_stop"] = stop

        def run_file():
            pos = 0
            while not stop.is_set():
                try:
                    with open(target, "rb") as fh:
                        fh.seek(pos)
                        chunk = fh.read(8 << 20)
                    if chunk:
                        cut = chunk.rfind(b"\n") + 1
                        if cut:
                            pos += cut
                            lines = chunk[:cut].decode("utf-8", "replace").split("\n")
                            r = self.ingest(lines, st["ingest_id"], label)
                            for k in ("lines", "parsed", "pending"):
                                st[k] += r["records" if k == "lines" else k]
                            continue
                    stop.wait(1.0)
                except Exception as exc:
                    st["error"] = str(exc)
                    stop.wait(3.0)
            st["running"] = False

        def run_kafka():
            from .reader import KafkaSource
            try:
                bootstrap, topic = target.split("/", 1)
                src = KafkaSource(topic, {"bootstrap.servers": bootstrap, "group.id": "logparser-ui",
                                          "auto.offset.reset": "earliest"})
            except Exception as exc:
                st["error"], st["running"] = str(exc), False
                return
            while not stop.is_set():
                try:
                    msgs = src.read_messages(BATCH, timeout=1.0)
                    if msgs:
                        lines = [m[1].decode("utf-8", "replace") for m in msgs]
                        r = self.ingest(lines, st["ingest_id"], label)
                        src.commit()            # after the events are written
                        for k in ("lines", "parsed", "pending"):
                            st[k] += r["records" if k == "lines" else k]
                except Exception as exc:
                    st["error"] = str(exc)
                    stop.wait(3.0)
            st["running"] = False

        threading.Thread(target=run_file if kind == "file" else run_kafka, daemon=True).start()
        self.streams[sid] = st
        return self._pub(st)

    def stop_stream(self, sid: str) -> dict:
        st = self.streams.get(sid)
        if st:
            st["_stop"].set()
        return {"stopped": bool(st)}

    @staticmethod
    def _pub(st: dict) -> dict:
        return {k: v for k, v in st.items() if not k.startswith("_")}

    # ------------------------------------------------------------------ reads: ClickHouse
    def events(self, p: dict) -> dict:
        where = ["1"]
        if p.get("ingest_id"):
            where.append(f"ingest_id = '{_esc(p['ingest_id'])}'")
        if p.get("source"):
            where.append(f"lp_source = '{_esc(p['source'])}'")
        if p.get("group"):
            where.append(f"lp_group_id = '{_esc(p['group'])}'")
        if p.get("class_uid"):
            where.append(f"class_uid = {int(p['class_uid'])}")
        if p.get("q"):
            where.append(f"positionCaseInsensitive(message, '{_esc(p['q'])}') > 0")
        w = " AND ".join(where)
        limit, offset = min(int(p.get("limit", 50)), 500), int(p.get("offset", 0))
        rows = self.ch.query(
            f"SELECT toString(time) time, class_uid, activity_id, severity_id, status_id, src_ip, dst_ip, user_name, "
            f"vendor_name, product_name, lp_source, lp_group_id, parser_rule, mapping_rule, lp_parser_version, "
            f"lp_mapping_version, valid, errors, ingest_id, raw_id, fields_json, event_json, message "
            f"FROM logs.ocsf_events WHERE {w} ORDER BY ingested_at DESC, raw_id LIMIT {limit} OFFSET {offset}")
        n = self.ch.query(f"SELECT count() n FROM logs.ocsf_events WHERE {w}")[0]["n"]
        for r in rows:
            r["fields"] = json.loads(r.pop("fields_json") or "{}")
            r["event"] = json.loads(r.pop("event_json") or "{}")
            r["class_name"] = self._class_name(r["class_uid"])
        return {"total": int(n), "rows": rows}

    def unparsed(self, p: dict) -> dict:
        where = ["1"]
        if p.get("ingest_id"):
            where.append(f"ingest_id = '{_esc(p['ingest_id'])}'")
        if p.get("group"):
            where.append(f"lp_group_id = '{_esc(p['group'])}'")
        w = " AND ".join(where)
        rows = self.ch.query(f"SELECT toString(received_at) received_at, ingest_id, raw_id, lp_source, lp_group_id, "
                             f"status, reason, message FROM logs.unparsed WHERE {w} "
                             f"ORDER BY received_at DESC LIMIT {min(int(p.get('limit', 100)), 500)}")
        by = self.ch.query(f"SELECT lp_group_id, any(lp_source) source, any(reason) reason, count() n, "
                           f"any(message) example FROM logs.unparsed WHERE {w} GROUP BY 1 ORDER BY n DESC LIMIT 100")
        return {"rows": rows, "by_group": by}

    def overview(self) -> dict:
        ev = self.ch.query("SELECT count() n, uniqExact(lp_source) sources, countIf(valid=0) invalid FROM logs.ocsf_events")[0]
        un = self.ch.query("SELECT count() n FROM logs.unparsed")[0]
        ingests = self.ch.query(
            "SELECT ingest_id, sum(p) parsed, sum(u) unparsed, toString(min(t)) first_at FROM ("
            " SELECT ingest_id, count() p, 0 u, min(ingested_at) t FROM logs.ocsf_events GROUP BY ingest_id"
            " UNION ALL SELECT ingest_id, 0 p, count() u, min(received_at) t FROM logs.unparsed GROUP BY ingest_id)"
            " GROUP BY ingest_id ORDER BY first_at DESC LIMIT 30")
        by_class = self.ch.query("SELECT class_uid, count() n FROM logs.ocsf_events GROUP BY 1 ORDER BY n DESC LIMIT 30")
        for r in by_class:
            r["class_name"] = self._class_name(r["class_uid"])
        with self.lock:
            s = self.eng.store
            meta = {
                "rules": {r["kind"]: r["n"] for r in s.q("SELECT kind, COUNT(*) n FROM rules WHERE status='active' GROUP BY kind")},
                "groups": s.q("SELECT COUNT(*) n FROM groups WHERE merged_into IS NULL")[0]["n"],
                "sources": s.q("SELECT COUNT(*) n FROM sources")[0]["n"],
                "queue": {r["name"]: r["n"] for r in s.q("SELECT name, COUNT(*) n FROM queue WHERE status='open' GROUP BY name")},
            }
        return {"events": int(ev["n"]), "event_sources": int(ev["sources"]), "invalid": int(ev["invalid"]),
                "unparsed": int(un["n"]), "ingests": ingests, "by_class": by_class, "meta": meta,
                "streams": [self._pub(x) for x in self.streams.values()]}

    def _class_name(self, uid) -> str:
        try:
            uid = int(uid)
        except (TypeError, ValueError):
            return ""
        if uid == 0:
            return "Base Event"
        name = self.eng.schema.by_uid.get(uid)
        c = self.eng.schema.classes.get(name) if name else None
        return (c.get("caption") or name) if c else str(uid)

    # ------------------------------------------------------------------ reads: rule database
    @staticmethod
    def _key(source: str) -> str:
        """Format/program part of a source key, without the stream label: lines from a labelled and an
        unlabelled stream with the same content share their groups."""
        return source.split("|", 1)[1] if "|" in source else source

    def sources(self) -> list:
        with self.lock:
            s = self.eng.store
            groups: dict = {}
            for r in s.q("SELECT source, count, parser_rule, mapping_rule FROM groups WHERE merged_into IS NULL"):
                g = groups.setdefault(self._key(r["source"]), {"groups": 0, "parsed": 0, "mapped": 0})
                g["groups"] += 1
                g["parsed"] += r["parser_rule"] is not None
                g["mapped"] += r["mapping_rule"] is not None
            merged: dict = {}
            for src in s.sources():
                k = self._key(src["source"])
                m = merged.setdefault(k, {"source": k, "vendor": None, "product": None, "source_rule": None,
                                          "lines": 0, "keys": [], "quarantined": False})
                m["lines"] += src["lines"] or 0
                m["keys"].append(src["source"])
                m["quarantined"] |= bool(src["quarantined"])
                if src.get("vendor") and not m["vendor"]:
                    m.update(vendor=src["vendor"], product=src.get("product"), source_rule=src.get("source_rule"))
        out = []
        for k, m in merged.items():
            g = groups.get(k, {})
            out.append({**m, "groups": g.get("groups", 0), "parsed_groups": g.get("parsed", 0),
                        "mapped_groups": g.get("mapped", 0)})
        out.sort(key=lambda r: -(r["lines"] or 0))
        return out

    def groups(self, key: str) -> list:
        with self.lock:
            rows = [g for g in self.eng.store.groups("merged_into IS NULL") if self._key(g["source"]) == key]
        return sorted([{k: g[k] for k in ("signature", "source", "template", "count", "status", "format",
                                          "parser_rule", "mapping_rule", "parse_failures")} for g in rows],
                      key=lambda g: -g["count"])

    def group(self, sig: str) -> dict:
        with self.lock:
            s = self.eng.store
            g = s.group(sig)
            if not g:
                return {"error": "no such group"}
            while g.get("merged_into"):
                g = s.group(g["merged_into"])
            out = {k: g[k] for k in ("signature", "source", "bucket", "format", "template", "count", "status",
                                     "parser_rule", "mapping_rule", "parse_failures", "labels")}
            out["detail"] = {k: v for k, v in g["detail"].items() if not k.startswith("_")}
            out["signatures"] = [r["signature"] for r in s.q("SELECT signature FROM group_signatures WHERE group_id=?",
                                                              (g["signature"],))]
            out["samples"] = [{"raw": r["raw"], "tag": r.get("tag")} for r in s.samples(g["signature"], tags=True)][:20]
            out["stats"] = s.stats(g["signature"])
            out["rules"] = {}
            for rid in (g["parser_rule"], g["mapping_rule"]):
                if rid:
                    out["rules"][rid] = self._rule_chain(rid)
            out["decisions"] = [dict(r) for r in s.q("SELECT at, scope, question, answer, answered_by, tier FROM decisions "
                                                     "WHERE scope LIKE ? ORDER BY at DESC LIMIT 20",
                                                     (f"%{g['signature']}%",))]
            out["operations"] = [dict(r) for r in s.q("SELECT at, op, target, params, tier, by, status FROM operations "
                                                      "WHERE target LIKE ? ORDER BY at DESC LIMIT 20",
                                                      (f"%{g['signature']}%",))]
        return out

    def _rule_chain(self, rid: str) -> list:
        """The rule with all its versions, then any base rule it extends."""
        s = self.eng.store
        chain, seen = [], set()
        while rid and rid not in seen:
            seen.add(rid)
            vers = s.rule_versions(rid)
            if not vers:
                break
            chain.append({"rule_id": rid, "versions": vers})
            active = next((v for v in vers if v["status"] == "active"), vers[-1])
            body = active["body"] if isinstance(active["body"], dict) else {}
            rid = body.get("extends") or body.get("base")
        return chain

    def rules(self, kind: str | None, q: str | None) -> list:
        with self.lock:
            rows = self.eng.store.rules(kind or None)
        out = []
        for r in rows:
            txt = json.dumps(r["body"])
            if q and q.lower() not in (r["rule_id"] + txt).lower():
                continue
            out.append({"rule_id": r["rule_id"], "kind": r["kind"], "version": r["version"],
                        "created_by": r["meta"].get("created_by"), "created_at": r["created_at"],
                        "summary": txt[:160]})
        out.sort(key=lambda r: (r["kind"], r["rule_id"]))
        return out[:1000]

    def rule(self, rid: str) -> dict:
        with self.lock:
            vers = self.eng.store.rule_versions(rid)
            used = [g["signature"] for g in self.eng.store.groups(
                "(parser_rule=? OR mapping_rule=?) AND merged_into IS NULL", (rid, rid))][:200]
        return {"rule_id": rid, "versions": vers, "used_by_groups": used}

    def queue(self) -> list:
        with self.lock:
            return [dict(r) | {"payload": json.loads(r["payload"])} for r in self.eng.store.q(
                "SELECT name, key, status, payload, created_at, attempts FROM queue WHERE status='open' "
                "ORDER BY created_at DESC LIMIT 300")]


def make_handler(app: App):
    class H(BaseHTTPRequestHandler):
        def _send(self, code: int, body: bytes, ctype: str) -> None:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _json(self, obj, code: int = 200) -> None:
            self._send(code, json.dumps(obj, default=str).encode(), "application/json")

        def _body(self) -> bytes:
            return self.rfile.read(int(self.headers.get("Content-Length") or 0))

        def do_GET(self):
            u = urllib.parse.urlparse(self.path)
            p = {k: v[0] for k, v in urllib.parse.parse_qs(u.query).items()}
            try:
                if u.path == "/":
                    with open(os.path.join(HERE, "web", "index.html"), "rb") as fh:
                        return self._send(200, fh.read(), "text/html; charset=utf-8")
                routes = {
                    "/api/overview": lambda: app.overview(),
                    "/api/events": lambda: app.events(p),
                    "/api/unparsed": lambda: app.unparsed(p),
                    "/api/sources": lambda: app.sources(),
                    "/api/groups": lambda: app.groups(p.get("source", "")),
                    "/api/group": lambda: app.group(p.get("signature", "")),
                    "/api/rules": lambda: app.rules(p.get("kind"), p.get("q")),
                    "/api/rule": lambda: app.rule(p.get("rule_id", "")),
                    "/api/queue": lambda: app.queue(),
                    "/api/streams": lambda: [app._pub(x) for x in app.streams.values()],
                }
                if u.path in routes:
                    return self._json(routes[u.path]())
                self._json({"error": "not found"}, 404)
            except Exception as exc:
                traceback.print_exc()
                self._json({"error": str(exc)}, 500)

        def do_POST(self):
            u = urllib.parse.urlparse(self.path)
            p = {k: v[0] for k, v in urllib.parse.parse_qs(u.query).items()}
            try:
                if u.path == "/api/ingest":
                    text = self._body().decode("utf-8", "replace")
                    return self._json(app.ingest(text.split("\n"), p.get("ingest_id") or None, p.get("label") or None))
                if u.path == "/api/streams":
                    b = json.loads(self._body() or b"{}")
                    return self._json(app.start_stream(b.get("kind", "file"), b["target"], b.get("label") or None))
                if u.path == "/api/streams/stop":
                    return self._json(app.stop_stream(p.get("id", "")))
                self._json({"error": "not found"}, 404)
            except Exception as exc:
                traceback.print_exc()
                self._json({"error": str(exc)}, 500)

        def log_message(self, *a):
            pass
    return H


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", required=True)
    ap.add_argument("--settings")
    ap.add_argument("--port", type=int, default=8090)
    ap.add_argument("--clickhouse", default="http://localhost:8123")
    a = ap.parse_args()
    app = App(a.db, a.settings, a.clickhouse)
    srv = ThreadingHTTPServer(("127.0.0.1", a.port), make_handler(app))
    print(f"UI on http://127.0.0.1:{a.port}", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
