# Variant A vs Variant B on one mixed stream

Phase 5 result, 2026-11-22. Reproduce with:

    python -m logparser.compare --a A_STORE --b B_STORE --files "logs data/*.log" --lines 20000 --out report.json

## The two variants

- **A, rules compiled to Logstash.** One agent writes a parser rule, another writes an OCSF mapping, both in
  our rule language. Code compiles them to Logstash and keeps a group only where Logstash produces exactly
  the engine's event.
- **B, the AI writes Logstash filters.** One agent writes the whole filter (grok / dissect / kv / json / xml /
  csv, date, mapping) as checked steps; code renders it and tests it in a warm Logstash. A group is kept when
  every tested line passes the gate.

Both share detection, grouping, the router, the sink, the parsed topic and ClickHouse.

## Method

- 20,000 lines sampled across the 42 files of the test data (every k-th line of each file, shuffled).
- Each variant's set built and verified exactly as a deploy builds it, then run in Logstash on the same lines.
- The same checks for both: schema, every copied value present in its line, time from the line (not arrival),
  outcome words (denied / failed ...) agreeing with the event, read from the line's own fields.
- The formats compared: the 18 groups Variant B learned. Variant A was given OCSF mappings for the same groups
  in a separate paid run ($1.72) so both cover the same formats.

## Results

|                                   | Variant A                          | Variant B          |
|-----------------------------------|------------------------------------|--------------------|
| Groups deployed after verification | 15 of 18                           | 18 of 18           |
| Lines parsed (of 20,000)           | 4,205 (21.0%)                      | 4,781 (23.9%)      |
| Correct (same checks for both)     | 100% of parsed                     | 100% of parsed     |
| Mapped attributes per event        | 23.3                               | 21.5               |
| Logstash throughput (same lines)   | ~5,600 events/s                    | ~3,900 events/s    |
| Learning cost per format           | $0.10 mapping + parser where learned | $0.12, all in one |

On the 14 formats both deploy, coverage is identical line for line. The difference is three groups that
Variant A does not parse:

- **Firebox https-proxy and Sysmon file events**: A's generic parsers (auto-kv, auto-json) leave the
  important data inside one string (the positional `Allow|Deny … src dst ports` part; Sysmon's multi-line
  `Message`). A's mapping agent correctly refused to map them and handed them to the parser agent: in A this
  takes two agents and two passes. B's single agent parsed and mapped them in one filter.
- **Cisco WSA**: A's compiled rule also read lines of another group, so verification left it out. B's test
  rejects such filters before saving, and its filter is specific.

## Where both parse a line, who is right

2,401 of 4,205 lines differ on at least one key field. Judged against the raw lines:

| Group | Field | Better |
|---|---|---|
| Sysmon network (EventID 3) | src / dst IP, user | **B** (A has none: data stuck in `Message`) |
| PAN-OS traffic `end` | activity | **A** (Close, for a session-end record; B says Traffic) |
| Windows DHCP via NXLog | time | **A** (the record's own time; B used NXLog's receive time, same second here) |
| Windows DHCP via NXLog | dst IP | **B** (A put the log sender's address in `dst_endpoint`) |
| Sophos Denied, Sysmon DNS | status | **B** (fills Failure / Success; A leaves it empty) |
| Falcon `SuspiciousRegAsepUpdate` | class | either (A: Detection Finding, B: Registry Value Activity) |
| Defender incidents, Brivo | activity | equal (Unknown 0 vs Other 99) |

## Conclusion

Variant B is the better default writer for new formats: one agent owns a format end to end, so data hidden
inside a field (a JSON `Message`, a positional tail after key=value pairs) is handled in the same filter,
where Variant A needs a second agent and a second pass. Coverage and correctness are otherwise equal, and the
cost per format is similar.

Variant A keeps two advantages: its rules run in our own engine as well as in Logstash (exact verification,
offline audit without a Logstash), and its compiled Logstash was faster on this run. It also handles split
groups, which Variant B leaves to it.

Recommended setup: **B writes the filters for new formats; A stays for split groups and as the engine-side
reference.** Both can be deployed together because they share the router.

## Limits of this test

- One sample of 20,000 lines from one data set, 18 formats; the throughput numbers come from short runs.
- Field meaning (e.g. which of two times is the event time) was judged by hand for the main disagreements.
- Variant A's parser agent was not run on the two groups its mapper handed back.
