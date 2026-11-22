"""Event store sinks. The engine calls sink.write(rows) for each batch before it commits the
read offset, and sink.resolved(raw_ids) when lines that were waiting get parsed by a new rule."""
from __future__ import annotations

import datetime as dt
import json
import urllib.parse
import urllib.request

_EPOCH = dt.datetime(1970, 1, 1, tzinfo=dt.timezone.utc)


def _dig(o, *ks):
    for k in ks:
        if not isinstance(o, dict):
            return None
        o = o.get(k)
    return o


def _time(ev: dict) -> str:
    t = ev.get("time")
    try:
        d = _EPOCH + dt.timedelta(milliseconds=int(t))
    except (TypeError, ValueError, OverflowError):
        d = dt.datetime.now(dt.timezone.utc)
    return d.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


def event_row(r: dict) -> dict:
    ev = r.get("event") or {}
    num = lambda k: ev.get(k) if isinstance(ev.get(k), int) else 0
    return {
        "time": _time(ev),
        **{k: num(k) for k in ("class_uid", "category_uid", "activity_id", "type_uid", "severity_id",
                               "status_id", "action_id", "disposition_id")},
        "src_ip": str(_dig(ev, "src_endpoint", "ip") or ""),
        "dst_ip": str(_dig(ev, "dst_endpoint", "ip") or ""),
        "user_name": str(_dig(ev, "actor", "user", "name") or _dig(ev, "user", "name") or ""),
        "vendor_name": str(_dig(ev, "metadata", "product", "vendor_name") or ""),
        "product_name": str(_dig(ev, "metadata", "product", "name") or ""),
        "lp_source": r["lp_source"], "lp_group_id": r["lp_group_id"],
        "parser_rule": r.get("parser_rule", ""), "mapping_rule": r.get("mapping_rule", ""),
        "lp_parser_version": r.get("parser_version") or 0, "lp_mapping_version": r.get("mapping_version") or 0,
        "valid": 1 if r.get("valid") else 0, "errors": json.dumps(r.get("errors") or []),
        "ingest_id": r["ingest_id"], "raw_id": r["raw_id"],
        "fields_json": json.dumps(r.get("fields") or {}, default=str),
        "event_json": json.dumps(ev, default=str), "message": r["message"],
    }


def unparsed_row(r: dict) -> dict:
    return {k: r[k] for k in ("ingest_id", "raw_id", "lp_source", "lp_group_id", "status", "reason", "message")}


class ClickHouseSink:
    def __init__(self, url: str = "http://localhost:8123", database: str = "logs"):
        self.url = url.rstrip("/")
        self.db = database

    def _post(self, sql: str, body: bytes | None = None) -> str:
        url = f"{self.url}/?" + urllib.parse.urlencode({"query": sql, "input_format_skip_unknown_fields": 1})
        with urllib.request.urlopen(urllib.request.Request(url, data=body if body is not None else b""),
                                    timeout=120) as r:
            return r.read().decode()

    def query(self, sql: str) -> list:
        out = self._post(sql + " FORMAT JSONEachRow")
        return [json.loads(x) for x in out.splitlines() if x.strip()]

    def _insert(self, table: str, rows: list) -> None:
        if rows:
            body = "\n".join(json.dumps(x, default=str) for x in rows).encode()
            self._post(f"INSERT INTO {self.db}.{table} FORMAT JSONEachRow", body)

    def write(self, rows: list) -> None:
        self._insert("ocsf_events", [event_row(r) for r in rows if r["status"] == "parsed"])
        self._insert("unparsed", [unparsed_row(r) for r in rows if r["status"] != "parsed"])

    def resolved(self, raw_ids: list) -> None:
        for i in range(0, len(raw_ids), 5000):
            ids = ",".join(str(int(x)) for x in raw_ids[i:i + 5000])
            # a replayed line replaces its earlier row in either table
            self._post(f"DELETE FROM {self.db}.unparsed WHERE raw_id IN ({ids})")
            self._post(f"DELETE FROM {self.db}.ocsf_events WHERE raw_id IN ({ids})")
