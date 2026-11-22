# Self-learning security log parser

Built from `LOG_PARSER_SPEC.md`. A fixed deterministic engine reads mixed
security logs, groups lines by format, parses them and maps them to OCSF 1.10.0.
Everything format-specific is data in a registry. AI only writes or repairs
rules, and a rule is saved only when a check in code passes.

Results of both dataset runs are in `docs/RESULTS.md`.

## Layout

```
logparser/
  engine.py      the pipeline: detect, sign, group, parse, map, validate, merge, guard, replay, metrics
  reader.py      file and Kafka sources, record framing (multiline, octet counting), binary detection
  detect.py      ordered format checks and envelopes, loaded from the registry
  signature.py   masking and template signatures
  formats.py     decoders: JSON, key=value, CEF, LEEF, delimited, XML
  parsers.py     runs one parser rule; literal-value check
  ocsf.py        OCSF schema access, mapper, validator
  transforms.py  the fixed transform library mapping rules may call
  registry.py    rule schemas, validation, versions, rollback, JSON export/import
  store.py       storage interface and the SQLite implementation
  tools.py       the agents' tools and the save gates
  harness.py     bounded agent loop on the Claude API
  shadow.py      shadow mode for new rule versions
  review.py      human corrections, shown to agents next time
  prompts/       the four agent prompts
registry/
  builtin.json   generic rules: framing, detection checks, masks, dialects, default mapping
  seeds/         vendor rules from open-source parsers, each with source and licence
docs/RULES.md    the rule language
eval/labels.jsonl  the evaluation set
scripts/         corpus, evaluation set, builtin and seed generators, grouping benchmark
tests/           pytest suite
```

## Run it

```sh
uv venv --python 3.12 .venv && uv pip install --python .venv/bin/python google-re2 drain3 jsonschema anthropic pytest
.venv/bin/python -m pytest tests -q

# data (public datasets are cloned under data/raw; see scripts/build_corpus.py for the list)
.venv/bin/python scripts/build_corpus.py && .venv/bin/python scripts/build_eval.py

# a run
.venv/bin/python -m logparser.cli --db work/run.db init
.venv/bin/python -m logparser.cli --db work/run.db run data/corpus/cisco_asa.log --label cisco_asa --finalize
.venv/bin/python -m logparser.cli --db work/run.db status
.venv/bin/python -m logparser.cli --db work/run.db metrics

# agents (needs Claude API credentials)
.venv/bin/python -m logparser.harness --db work/run.db parser-gen --limit 20
.venv/bin/python -m logparser.harness --db work/run.db ocsf-mapping --limit 20
.venv/bin/python -m logparser.harness --db work/run.db mask-repair
.venv/bin/python -m logparser.harness --db work/run.db longtail --limit 80

# operations
.venv/bin/python -m logparser.cli --db work/run.db export registry.json
.venv/bin/python -m logparser.cli --db work/run.db rollback parser:SIGNATURE
.venv/bin/python -m logparser.shadow --db work/run.db review
.venv/bin/python -m logparser.review --db work/run.db pending
```

Settings (thresholds, caps) are in `logparser/config.py`; `init --set name=value`
stores overrides in the database.

## How the spec's principles are enforced

| Principle | Where |
|---|---|
| Engine fixed, formats are data | `registry/*.json`; the engine has no vendor names in code |
| Restricted rule language | JSON Schema per rule kind in `registry.py`; transforms only from `transforms.py` |
| Validated, versioned, rollback | `registry.save_rule`, `registry.rollback`; invalid rules are never loaded |
| Linear-time patterns | every rule pattern compiles through `rx.py` (RE2) |
| No AI per event | `engine.py` imports no model client; agents work from queues |
| Code verifies, gate in code | `Tools.save_mask`, `save_parser`, `save_mapping`, `save_longtail` |
| Raw lines kept, replay | `raw` table; `Engine.replay_signatures`, `Engine.replay_source` |
| Log text is untrusted | samples travel as data in tool results; agent can only write rules that pass the gates |

## Deviations from the spec, and why

- **Near-duplicate merge.** Drain3 alone merged different events that share a
  header (short messages with the same token count). Measured on Loghub, Drain
  clusters with a distinct-value test gave mean grouping accuracy 0.69. The
  default is now an exact check: templates are merged only when they are equal
  everywhere but one position (or two positions that change together), with
  enough distinct values there. That gave 0.76. Drain3 stays available as the
  candidate generator with `merge_candidates = "drain"`.
- **Structured signatures.** Besides hashing the key set, a record that names
  its own event type (`type`, `eventName`, `event_type`, ...) is signed on that
  value and its optional keys are ignored. A new key set that overlaps an
  existing group by 80% joins it as a variant (format drift).
- **Group threshold and signature cap.** The public samples are small, so the
  dataset run used a threshold of 5 lines and a cap of 150 signatures per source
  instead of the spec's examples of 50 and 500. Both are settings.
- **Regrouping by agents.** Not in the spec. A mapping or parser agent can
  split one group (`save-split`), choose the OCSF class per line (`switch`), or
  hand a group to the other agent's queue (`report-problem`). A code-side check
  (`cli diagnose`) finds mixed groups without calling a model. All of it is
  gated in code; see `docs/RULES.md` and round 2 in `docs/RESULTS.md`.
- **Parser-assisted grouping.** A new signature that an existing group's
  AI-written parser already matches (and that differs in at most two tokens)
  joins that group. It is checked once per new signature, never per event.

## Not done, or not verified

- The Kafka source is written but has never run against a broker.
- The agent harness is tested with a scripted fake model only. No real Claude
  API call was made in this build; the first-phase agents were subagents.
- `fetch_vendor_docs` is a cache with no fetcher behind it yet.
- Storage is SQLite only. Groups are held in memory; a large deployment needs
  an LRU and the Postgres store.
- AI-written mappings are marked `needs_human_review`. Schema validation shows
  the types fit, not that the meaning is right.
- Nothing here has run on the owner's real logs.
