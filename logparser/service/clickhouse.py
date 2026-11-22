"""ClickHouse side of the service: the event tables, and ingestion of the parsed topic.

  parsed topic (JSON per OCSF event, flattened by the Logstash sink)
     -> <db>.parsed_queue   ENGINE = Kafka (ClickHouse consumes the topic itself)
     -> <db>.parsed_mv      materialized view
     -> <db>.ocsf_events    MergeTree (deploy/clickhouse/schema.sql)

Statements are sent one at a time over HTTP. Production uses the same statements with its own
broker, topic and database in the service configuration.
"""
from __future__ import annotations

import os
import re
import urllib.parse
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# columns the Logstash sink writes (the rest of ocsf_events take their defaults)
QUEUE_COLUMNS = [
    ("time", "String"), ("class_uid", "UInt32"), ("category_uid", "UInt8"), ("activity_id", "Int32"),
    ("type_uid", "UInt64"), ("severity_id", "UInt8"), ("status_id", "UInt8"), ("action_id", "UInt8"),
    ("disposition_id", "UInt16"), ("src_ip", "String"), ("dst_ip", "String"), ("user_name", "String"),
    ("vendor_name", "String"), ("product_name", "String"), ("lp_source", "String"), ("lp_group_id", "String"),
    ("lp_parser_version", "UInt32"), ("lp_mapping_version", "UInt32"), ("valid", "UInt8"), ("ingest_id", "String"),
    ("event_json", "String"), ("message", "String"),
]


def _post(url: str, sql: str) -> str:
    req = urllib.request.Request(url.rstrip("/") + "/", data=sql.encode(), method="POST")
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.read().decode()


def query(url: str, sql: str) -> str:
    return _post(url, sql)


def _q(s: str) -> str:
    return "'" + s.replace("\\", "\\\\").replace("'", "\\'") + "'"


def statements(db: str, bootstrap: str, topic: str, group: str) -> list:
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", db):
        raise ValueError(f"clickhouse database name {db!r}")
    with open(os.path.join(ROOT, "deploy", "clickhouse", "schema.sql")) as fh:
        schema = fh.read()
    schema = re.sub(r"--[^\n]*", "", schema).replace("logs.", f"{db}.").replace("EXISTS logs;", f"EXISTS {db};")
    out = [s.strip() for s in schema.split(";") if s.strip()]
    cols = ",\n  ".join(f"{c} {t}" for c, t in QUEUE_COLUMNS)
    out.append(f"CREATE TABLE IF NOT EXISTS {db}.parsed_queue (\n  {cols}\n) ENGINE = Kafka SETTINGS "
               f"kafka_broker_list = {_q(bootstrap)}, kafka_topic_list = {_q(topic)}, kafka_group_name = {_q(group)}, "
               f"kafka_format = 'JSONEachRow', kafka_num_consumers = 1, kafka_skip_broken_messages = 100, "
               f"input_format_skip_unknown_fields = 1")
    sel = ", ".join(("parseDateTime64BestEffortOrZero(time, 3, 'UTC') AS time" if c == "time" else c)
                    for c, _ in QUEUE_COLUMNS)
    out.append(f"CREATE MATERIALIZED VIEW IF NOT EXISTS {db}.parsed_mv TO {db}.ocsf_events AS SELECT {sel} "
               f"FROM {db}.parsed_queue")
    return out


def ensure_ingest(url: str, db: str, bootstrap: str, topic: str, group: str = "clickhouse-ocsf") -> int:
    """Create the database, the event tables and the topic ingestion if missing. Returns statements run."""
    sts = statements(db, bootstrap, topic, group)
    for s in sts:
        _post(url, s)
    return len(sts)


def count(url: str, db: str, table: str = "ocsf_events", where: str = "1") -> int:
    return int(query(url, f"SELECT count() FROM {db}.{table} WHERE {where}").strip() or 0)
