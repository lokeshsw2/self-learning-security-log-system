# Self-learning security log parser: design spec and build brief

This file is a handoff from a design conversation. It contains everything agreed so far.
Nothing has been built yet. Read it fully, then start at "Build order".

## Goal

A generic system that reads a mixed stream of security logs from many vendors
(Kafka topic or file), groups lines by format, parses them into fields, and maps
them to OCSF. Deterministic code does all per-event work. AI is used only to
create or repair rules, and every AI output is saved as data that the
deterministic engine then runs.

## Scope

- In scope: all text logs. Syslog (RFC 3164/5424), CEF, LEEF, key-value, JSON,
  XML, CSV/delimited, W3C/CLF web logs, unstructured text, and hybrids
  (for example a syslog header wrapping CEF wrapping JSON).
- Out of scope for now: binary formats (NetFlow/IPFIX, protobuf, EVTX, pcap,
  compressed or encrypted blobs). Detect them and route them aside; do not parse.
- OCSF mapping is partial by design. Events with a clear class get a full
  mapping. Events with no fitting class use Base Event. Fields with no OCSF home
  go in the `unmapped` object. Noise (debug, heartbeats) may stay unmapped.

## Core principles

1. The engine code is fixed. Everything format-specific is data in a registry
   (database, with JSON export): detection checks, mask rules, signatures,
   parsers, OCSF mappings. Adding or changing a format means editing data, not code.
2. Rules are a restricted config language, not code: patterns, key lists, field
   paths, and a fixed library of transform functions (timestamp parsing, enum
   lookup, type casts). A new transform function is a code change and should be rare.
3. Every rule is schema-validated on load, versioned, and can be rolled back.
4. Patterns run on a linear-time regex engine (RE2 or equivalent) so an
   AI-written pattern cannot hang a worker.
5. AI never runs per event on the main path. AI cost must grow with the number
   of distinct formats, not with event volume.
6. Code detects, AI proposes, code verifies. A rule is saved only if a
   deterministic check passes; the save gate is in code, not in the model.
7. Raw lines are always kept so they can be re-parsed when a rule appears or changes.
8. Log content is untrusted input. Attackers control what gets logged, so lines
   may contain instructions aimed at the agents. Log text must never change agent
   behavior.

## Pipeline

1. Batch reader. One interface, two sources: file and Kafka. Grouping state
   lives in the store, so each batch continues from the previous one. Commit the
   offset after the batch state is written.
2. Record framing. Newlines, multiline events (stack traces, XML),
   length-prefixed syslog.
3. Format detection per record, cheap ordered checks loaded from the registry:
   starts with `{` -> JSON; starts with `<` plus a tag -> XML; contains `CEF:` or
   `LEEF:`; syslog header -> strip it and detect again on the payload (recursive);
   many `key=value` pairs -> key-value; consistent delimiter count -> delimited;
   otherwise unstructured.
4. Coarse bucket key (stateless): source metadata (Kafka headers, sender IP,
   syslog hostname/app name) plus structural shape.
5. Template signature:
   - Unstructured: mask variables (timestamps, IPs, numbers, hex, UUIDs, quoted
     strings) with placeholders, keep punctuation, hash the result.
   - JSON / key-value: hash the sorted key set. For sources with optional keys,
     sign on core keys only (those present in most lines).
6. Group store. Per signature: count, 10-20 sample raw lines chosen for
   diversity, status, linked rule. TTL on idle signatures.
7. Lookup. Known signature -> parse with its rule (direct lookup by signature,
   never try-all-patterns). Unknown signature -> new group; once it passes a
   count threshold (for example 50) emit it with samples to a `needs-parser` queue.
8. Near-duplicate merge. Run Drain (Drain3 library) on signatures, not on raw
   lines, to merge templates split by an unmasked variable.
9. Template-explosion guard (deterministic). Track distinct signatures per
   source against lines seen. Cap signatures per source (for example 500). Past
   the cap, quarantine that source and queue it for mask repair.
10. Parse, then normalize basics: timestamps without timezone or year,
    encodings, truncated lines.
11. OCSF mapping and schema validation.
12. Dead-letter queue for failures; replay of affected raw lines whenever a rule
    is created or patched.

## Format drift

A changed format shows up as a new signature with high overlap to an existing
group (for example a key-value source gains one key), or as parse failures on an
existing group. Treat it as a new version of that group's rule, not a new group.
The engine hot-reloads rules.

## AI agents (each a bounded tool-calling loop, 5-8 iterations, then flag for a human)

1. Mask repair. Tools: `get_samples(source)`, `test_mask(rule)` (re-hash, return
   signature count), `save_mask(rule)` (only if the count collapsed).
2. Parser generation. Tools: `get_samples(group)`, `test_parser(pattern)` (match
   rate plus failing lines), `save_parser(pattern)` (only at ~100% match, and
   every extracted value must appear literally in the raw line).
3. OCSF mapping. Tools: `search_ocsf(query)`, `get_class(name)`,
   `validate_event(mapped)`, `fetch_vendor_docs(vendor, product)` (cached),
   `save_mapping(mapping)`. The agent must read the real schema, not map from
   memory. Record a confidence note per mapped field.
4. Long-tail extraction. For free text and rare events that timed out below the
   threshold. Direct extraction of a small fixed field set (timestamp, host, user,
   IPs, action, outcome, severity) plus a one-line summary. Code drops any value
   not literally present in the line. Tag output `ai_extracted`. Cache by masked
   hash, batch lines per call, use a small model, enforce a daily budget, and
   promote recurring lines back to the template path.

Parser generation must finish before mapping starts. Agents also label each
group with vendor, product, and event type.

During the first build phase the agent harness is not written. Subagents stand
in for these four agents and write their output to the registry as rules only.
The real agent-loop harness comes after the deterministic core is verified.

## Operational layer

- Evaluation set: a few hundred labeled lines across vendors with correct
  groups, fields, and OCSF mappings. Build this first; it is the regression test
  for every mask, prompt, or model change.
- Seeded registry: preload rules for popular vendors from existing open-source
  parsers and OCSF mappings. Record the source and license on every seeded rule
  and prefer permissive licenses.
- Shadow mode: a new rule runs against live traffic without publishing output
  and is activated only after it holds on a few thousand real lines.
- Review loop: human corrections are stored as examples the agents see next time.
- Metrics per source: parse rate, unmapped ratio, signature growth, AI spend,
  queue lag.

## Defaults agreed

- Python.
- SQLite with JSON export behind a storage interface (Postgres later).
- Current stable OCSF version (check the OCSF schema repository).
- Text logs only.

## Build order

1. Collect public log datasets (for example the Loghub collection), the OCSF
   schema, and existing vendor parsers. Build the evaluation set.
2. Build the engine: batch reader, framing, detector, masking, signatures, group
   store, explosion guard, Drain merge, parser runner, OCSF mapper and validator,
   replay.
3. Seed the registry with popular vendors.
4. Run batches over the datasets. Use subagents as stand-ins for the four agents.
5. Have a separate subagent that did not write the code evaluate the results
   against the evaluation set. Report numbers and gaps.
6. Then write the agent-loop harness, shadow mode, and metrics.

## Known risks

- Masking quality decides everything downstream. Measure distinct signatures on
  real samples before building streaming.
- OCSF field meaning cannot be fully verified by code. Schema validation proves
  types fit, not that the meaning is right. AI-made mappings that feed detections
  need human review.
- The Kafka adapter needs a real broker and a load test.
- The system is not production-ready until it has run on the owner's real logs.

## Prior work worth reading

- LILAC: LLM log parsing with an adaptive template cache.
- LogBatcher: clustering, diverse sampling, and cache matching.
- Matryoshka (Berkeley): generates deterministic parsers and OCSF mappings from
  unlabeled samples; closest to this design.
- EFParser: validates templates before they enter the cache.
