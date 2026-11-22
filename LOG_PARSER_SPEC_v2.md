# Self-learning security log parser: design spec and build brief

This file is a handoff from a design conversation. It contains everything agreed so far.
Read it fully, then start at "Build order".

## Revision 2: what changed

If you already built from revision 1, iterate on the existing code to cover these
additions. Do not start over.

- Pipeline step 5: outcome and action words are never masked.
- Pipeline step 6: samples follow the new "Sample storage" section.
- Agent 1 is widened from mask repair to grouping repair (remask, merge, split).
- New sections: "Grouping errors", "Self-correcting grouping loop",
  "Sample storage", "Confidence tiers and human review", "Guarantees",
  "Registry schema".
- Every parsed event carries `group_id`, `parser_version`, `mapping_version`.
- Build order step 2 now includes group statistics and the repair loop.

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
   - Never mask outcome or action words (`failed`, `denied`, `accepted`,
     `blocked`, `allowed`, and similar). They stay as fixed text in the signature
     so that different event types split into different groups. Keep this word
     list in the registry, not in code.
6. Group store. Per signature: count, samples (see "Sample storage"), per-field
   statistics, status, linked rule. TTL on idle signatures.
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

## Grouping errors

Grouping can go wrong in two ways.

- Over-splitting: one format becomes many groups, usually because a variable is
  not masked. Caught by signature growth per source and by Drain finding
  near-duplicates. If missed, the cost is duplicate parsers and extra AI calls;
  the data stays correct.
- Over-merging: different event types land in one group. Caught when the parser
  cannot reach a full match rate, or when a field shows mixed types or a few
  recurring values. If missed, this is the dangerous case: one parser matches
  both and nothing fails (for example login success and login failure treated as
  one event with the wrong OCSF outcome).

## Self-correcting grouping loop

Runs after every batch. Code detects, AI proposes, code verifies.

1. Statistics. For every group, per token position or field, update cheap
   counters: cardinality (distinct values, approximate is fine), type mix
   (IP, number, word, ...), top values. Also parse success rate and similarity to
   neighbouring groups.
2. Classify each position by cardinality. One value -> fixed text. Many values
   -> variable, mask it. A few recurring values -> ambiguous: either an enum
   field (`protocol=tcp/udp`) or event-defining (`accepted/failed`). Ambiguous
   positions go to AI.
3. Symptoms map to a fixed set of repair operations (in code):
   - Signatures keep growing for a source -> REMASK.
   - Two groups differ in one position -> MERGE.
   - Ambiguous position, or mixed types in a field -> SPLIT.
   - Parse failures rise on a group -> PATCH (new rule version).
   - Group idle past its TTL -> RETIRE.
4. AI answers one narrow question per symptom (for example "is position 5 an
   event type or a field value?") and returns an operation with parameters.
   Never free-form changes.
5. Code verifies by replay on the stored samples plus the latest batch. Accept
   only on measurable improvement: signature count drops (REMASK, MERGE); each
   new sub-group reaches a full parser match with consistent field types (SPLIT);
   failure rate returns to baseline (PATCH).
6. Apply as a new registry version, then replay the affected raw lines. The
   correction is active from the next batch.
7. Stability rules:
   - Lineage: split and merged groups keep a parent ID and inherit the parent's
     parser and mapping as a starting version.
   - Decision memory: store every AI or human answer so the same question is
     never asked twice.
   - Cooldown: a group that was just changed cannot be changed again for N
     batches, to prevent merge-split flip-flopping.
   - Auto-rollback: if a group's health worsens after a change, revert it.

Known residual errors: lines that are structurally identical and differ only in
meaning inside a high-cardinality field; and wrong AI answers that still pass
replay. The evaluation set and human review cover these.

## Sample storage

- Choose samples for diversity, not the first N.
- For every ambiguous position, keep a few lines per recurring value so rare
  values are represented.
- Reservoir-sample so recent batches replace old lines and drift shows up.
- Store the raw line next to the masked template.
- Keep failures (parse failures, odd lines) in a separate tagged set; they are
  the most useful input for repair.

## Confidence tiers and human review

Every AI decision is tagged with one tier:

- Verified by code -> apply automatically.
- Plausible but unverified -> apply and queue for a spot check.
- Uncertain -> hold for a human. Only this tier blocks.

Human review questions are as narrow as the AI ones (one question plus samples).
Every human answer goes into decision memory and into the agents' examples.
Track the share of decisions per tier over time; the "hold for a human" share
should fall as batches go by.

## Guarantees

- Self-describing formats (JSON, key-value, CEF, LEEF, XML, CSV): extraction is
  complete from the first line with no AI. Worst case is a field that is
  extracted but unmapped.
- Templated text: fields are inferred, so extraction starts possibly incomplete
  (a variable that showed one value in all samples looks like fixed text) and is
  corrected when the cardinality statistics change.
- All text: accounting is guaranteed. Every line ends in exactly one state:
  parsed by a rule, pending in a group, AI-extracted, or stored raw. No line is
  silently dropped, and a line that does not fit surfaces as a parse failure.

## Registry schema

Parsers and mappings live in their own tables, separate from groups. Nothing is
patched in place: a patch inserts a new version row and moves the group's active
pointer. Old versions stay for rollback and shadow comparison.

- `sources`: vendor, product, bucket key, signature cap, quarantine flag.
- `detector_rules`: the ordered format checks.
- `mask_rules`: pattern, placeholder, scope (global or one source), version, status.
- `protected_words`: outcome and action words that are never masked.
- `groups`: group ID, source, template, shape, parent group ID, status, counts,
  first and last seen, active parser ID, active mapping ID, cooldown-until.
- `group_signatures`: signature hash -> group ID. The hot-path lookup.
  Many-to-one, because merged or drifted formats give one group several signatures.
- `group_samples`: raw line, masked form, tag (diverse, recent, failure).
- `group_stats`: per position or field: cardinality, type mix, top values.
- `parsers`: parser ID, group ID, version, type, pattern or config as JSON,
  output field names, status (shadow, active, retired), origin (seeded, AI,
  human), source and license for seeded rules.
- `mappings`: mapping ID, group ID, parser version it was built for, OCSF class,
  field map as JSON, per-field confidence, version, status.
- `decisions`: scope, question, answer, answered by (AI or human), tier.
- `operations`: audit log of every remask, merge, split, patch, retire, and
  rollback, with the verification result.

What changes when a format changes:

- Log format drift (for example a new key): a new `group_signatures` row points
  to the same group; `parsers` gets a new version.
- The mapping gets a new version only if the fields changed; the rest carries over.
- A mask rule changes: re-hash that source and rebuild its `group_signatures`
  rows. Groups keep their IDs, so parsers and mappings survive.
- Split or merge: new groups with the parent ID set, inheriting parser and mapping.

Every parsed event carries `group_id`, `parser_version`, and `mapping_version`,
so replay knows exactly what to re-parse after a fix.

## AI agents (each a bounded tool-calling loop, 5-8 iterations, then flag for a human)

1. Grouping repair (remask, merge, split). Tools: `get_samples(source_or_group)`,
   `get_stats(group)`, `get_decisions(source)`, `test_operation(op)` (replay on
   samples; returns signature counts, per-sub-group match rates and field type
   consistency), `save_operation(op)` (only if the replay check passed).
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
   store, group statistics, explosion guard, Drain merge, the self-correcting
   grouping loop (symptoms, operations, replay verification, lineage, decision
   memory, cooldown, auto-rollback), parser runner, OCSF mapper and validator,
   replay. Use the tables in "Registry schema".
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
