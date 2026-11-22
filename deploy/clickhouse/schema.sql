-- OCSF events written by Logstash (pipeline compiled from the learned rules).
-- Common OCSF fields are columns for fast filtering; the whole event is kept as JSON.
CREATE DATABASE IF NOT EXISTS logs;

CREATE TABLE IF NOT EXISTS logs.ocsf_events
(
    time             DateTime64(3, 'UTC'),
    class_uid        UInt32,
    category_uid     UInt8,
    activity_id      Int32,
    type_uid         UInt64,
    severity_id      UInt8,
    status_id        UInt8,
    action_id        UInt8,
    disposition_id   UInt16,
    src_ip           String,
    dst_ip           String,
    user_name        String,
    vendor_name      LowCardinality(String),
    product_name     LowCardinality(String),
    lp_source        LowCardinality(String),
    lp_group_id      LowCardinality(String),
    lp_parser_version  UInt32,
    lp_mapping_version UInt32,
    event_json       String CODEC(ZSTD(3)),
    message          String CODEC(ZSTD(3)),
    ingested_at      DateTime64(3, 'UTC') DEFAULT now64(3)
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(time)
ORDER BY (class_uid, lp_source, time)
TTL toDateTime(time) + INTERVAL 90 DAY;

-- Lines Logstash could not parse or route: they go back to the learner (and stay searchable).
CREATE TABLE IF NOT EXISTS logs.unparsed
(
    received_at  DateTime64(3, 'UTC') DEFAULT now64(3),
    reason       LowCardinality(String),
    message      String CODEC(ZSTD(3))
)
ENGINE = MergeTree
ORDER BY received_at
TTL toDateTime(received_at) + INTERVAL 14 DAY;
