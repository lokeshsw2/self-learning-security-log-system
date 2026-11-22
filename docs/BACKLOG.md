# Backlog

Items agreed for later. Newest first.

- **Hourly audit in the service** (agreed 2026-11-22). Run the Variant B audit (`logparser/lsaudit.py`:
  newest stored lines through each saved filter, plus ClickHouse events read back) and the drift report on a
  timer, without model calls. Today they run after learning cycles and from the Review page.
- Paid re-run for Brivo access control (mapped as Base Event only).
- Variant A: auditd `\x1d` separator in the kv dialect; Base Event time from the header in Logstash fallback.
- Variant A drift (parse failures reopen the parser) was not part of the end-to-end drift test.
