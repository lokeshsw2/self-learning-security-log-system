-- OCSF events and unparsed lines. Written by the logparser engine (default) or by a
-- Logstash pipeline compiled from the same rules. Common OCSF fields are columns for fast
-- filtering; the full event and the parsed fields are kept as JSON text.
CREATE DATABASE IF NOT EXISTS logs;

CREATE TABLE IF NOT EXISTS logs.ocsf_events
(
    time               DateTime64(3, 'UTC'),
    class_uid          UInt32,
    category_uid       UInt8,
    activity_id        Int32,
    type_uid           UInt64,
    severity_id        UInt8,
    status_id          UInt8,
    action_id          UInt8,
    disposition_id     UInt16,
    src_ip             String,
    dst_ip             String,
    user_name          String,
    vendor_name        LowCardinality(String),
    product_name       LowCardinality(String),
    lp_source          LowCardinality(String),
    lp_group_id        LowCardinality(String),
    parser_rule        LowCardinality(String),
    mapping_rule       LowCardinality(String),
    lp_parser_version  UInt32,
    lp_mapping_version UInt32,
    valid              UInt8,
    errors             String,
    ingest_id          LowCardinality(String),
    raw_id             UInt64,
    fields_json        String CODEC(ZSTD(3)),
    event_json         String CODEC(ZSTD(3)),
    message            String CODEC(ZSTD(3)),
    ingested_at        DateTime64(3, 'UTC') DEFAULT now64(3)
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(time)
ORDER BY (class_uid, lp_source, time)
TTL toDateTime(time) + INTERVAL 90 DAY;

-- Lines with no event yet. When a new rule parses them, they are removed from here
-- and their events are written to logs.ocsf_events.
CREATE TABLE IF NOT EXISTS logs.unparsed
(
    received_at  DateTime64(3, 'UTC') DEFAULT now64(3),
    ingest_id    LowCardinality(String),
    raw_id       UInt64,
    lp_source    LowCardinality(String),
    lp_group_id  LowCardinality(String),
    status       LowCardinality(String),
    reason       LowCardinality(String),
    message      String CODEC(ZSTD(3))
)
ENGINE = MergeTree
ORDER BY (received_at, raw_id)
TTL toDateTime(received_at) + INTERVAL 14 DAY;
