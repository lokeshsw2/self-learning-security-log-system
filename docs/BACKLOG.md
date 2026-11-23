# Backlog

Items agreed for later. Newest first.

**Before production on GRA** (from the readiness review, 2026-11-22):

- Secured Kafka (SASL/TLS) has not been tested: run the local broker with SASL and test the learner,
  Logstash and ClickHouse against it.
- ClickHouse's Kafka-engine tables (`parsed_queue`, `ls_failures_queue`) have no SASL settings: add them
  from the service config.
- One deployed set with both variants (B for new formats, A for split groups) is not built; a deploy writes
  one variant's set. Build it, or keep one variant per deployment.
- Learner throughput (about 1,500 lines/s per process) against GRA's volume on the unparsed topic: sample
  lines for learning, or run several learner instances.
- GRA's model gateway: route model calls via `ANTHROPIC_BASE_URL`; add switches to turn off the model-call
  rows in `tool_calls` (the gateway stores them) and the server-side fallback beta (if the gateway does not
  pass beta headers); add a retention period for `tool_calls` (about 30 days).
- Service units, metrics and alerting; a login in front of the review UI.
- First step on GRA: a shadow pilot (own consumer group, separate parsed topic and ClickHouse database,
  learning off, then small capped runs).

- **Hourly audit in the service** (agreed 2026-11-22). Run the Variant B audit (`logparser/lsaudit.py`:
  newest stored lines through each saved filter, plus ClickHouse events read back) and the drift report on a
  timer, without model calls. Today they run after learning cycles and from the Review page.
- Paid re-run for Brivo access control (mapped as Base Event only).
- Variant A: auditd `\x1d` separator in the kv dialect; Base Event time from the header in Logstash fallback.
- Variant A drift (parse failures reopen the parser) was not part of the end-to-end drift test.
