# Results of the first dataset run

Run date 2026-11-22. Database `work/run.db`; registry export
`registry/exports/dataset-run-1.json`; evaluator's full report
`work/evaluator/REPORT.md`.

## What was run

- Corpus: 26,660 lines from 52 public sources (Loghub, Elastic Beats test logs,
  Azure Sentinel samples, Apache Metron samples, ocsf/examples) plus one binary
  EVTX file. Licences per source are in `data/corpus/manifest.json`. Beats
  x-pack logs are under the Elastic License and were used as test input only.
- Evaluation set: 492 labelled lines from 51 sources (`eval/labels.jsonl`).
  Labels come from the datasets' own ground truth, not from this system.
- Settings: group threshold 5 lines, signature cap 150 per source (the public
  samples are small; the spec's examples are 50 and 500).
- Rules at the start: 31 generic builtin rules and 50 seeded rules (Cisco ASA,
  HTTP access logs, HAProxy, Squid from Logstash grok patterns; Zeek, CloudTrail
  and VPC Flow mappings after ocsf/examples; all Apache-2.0).
- AI stage: 11 subagents stood in for the four agents and worked only through
  the tool commands. 1 mask repair, 3 parser generation, 6 OCSF mapping, 1
  long-tail. A twelfth subagent, which wrote none of the code, did the evaluation.

## Deterministic stage, before any AI

| Measure | Value |
|---|---|
| Speed (single process, SQLite) | about 3,500 records per second |
| Grouping accuracy on Loghub, 16 datasets, 2,000 lines each, builtin rules only | mean 0.76 |
| Lines parsed with seeds and automatic decoders alone | 8,741 of 26,063 |
| Binary file | routed aside, not parsed |
| Explosion guard | quarantined one source (Blue Gene/L log, 204 signatures against a cap of 150) |

Grouping accuracy per dataset is in `work/bench_grouping.json`. Best: Apache and
HealthApp 1.00, HDFS and Windows 1.00, Android 0.93. Worst: Proxifier 0.00,
OpenStack 0.42, Linux 0.57 (there the engine splits by syslog program and merges
optional `user=` variants, which the Loghub labels do not).

## What the stand-in agents saved

| Agent role | Saved | Refused by a gate | Flagged |
|---|---|---|---|
| Mask repair | 1 mask rule; the quarantined source went from 204 to 137 signatures and was released | 0 | 0 |
| Parser generation | 67 parsers | 0 | 0 |
| OCSF mapping | 210 mappings, including 16 shared bases | 0 | 0 |
| Long-tail extraction | 159 extractions; 10 values dropped by code | 0 | 0 |

No save was refused because the agents ran the test tool first and fixed their
rules before saving. The gates did reject rules in the test suite.

After the agents: 15,809 of 26,063 records parsed, 10,222 pending, 6 in the
dead-letter queue for parse failures, 9 events invalid against the schema.

## Independent evaluation

Numbers are the evaluator's, with denominators.

| Measure | Result |
|---|---|
| Labelled lines found in the store by exact text | 488 of 492 |
| Labelled lines parsed | 396 of 492 (80.5%); 95 pending |
| Grouping, pairwise precision | 136 of 145 (93.8%) |
| Grouping, pairwise recall | 136 of 138 (98.6%) |
| Expected values extracted, exact | 1,015 of 1,085 (93.5%) on parsed lines; 1,015 of 1,317 counting pending lines as misses |
| OCSF class acceptable | 188 of 300 parsed lines (62.7%); 188 of 339 of all class-labelled lines (55.5%) |
| OCSF attributes correct, strict | 535 of 1,079 (49.6%) |
| Events passing schema validation | 15,800 of 15,809 (99.9%) |
| Events that are Base Event | 7,757 of 15,809 |
| Hand check of 47 agent-mapped events | 38 right, 5 debatable, 4 wrong |

By who wrote the mapping:

| Mapping author | Class acceptable | Attributes correct (strict) |
|---|---|---|
| Seed | 54 of 54 | 183 of 195 |
| Agent, specific class | 134 of 135 | 332 of 470 |
| Agent, chose Base Event | 0 of 19 | 20 of 62 |
| No mapping yet (fallback to Base Event) | 0 of 92 | 0 of 352 |

The grouping check has low power: 21 of 31 sources have no two labelled lines
with the same template. Seed results on the ocsf/examples and Zeek lines are not
independent evidence, because those seeds were written from the same project
that supplied the gold labels.

## Gaps, most important first

1. **Too many events end as Base Event.** Only 217 of 492 labelled lines reach a
   specific class. The largest single case: 1,147 PAM "authentication failure"
   lines. The engine groups lines with and without `user=` together, OCSF
   Authentication requires a user, so the mapping agent had to fall back. The
   rule language cannot pick a class per line, and several groups mix event
   types that need different classes (PAN-OS threat subtypes, CyberArk,
   CrowdStrike, osquery). Okta, generic CEF, Snort and half the OCSF gold pairs
   were never queued for mapping because their groups stayed under the threshold.
2. **39% of records have no parser.** 9,934 of the 10,222 pending lines are five
   non-security Loghub sources (HDFS, Zookeeper, Windows CBS, BGL, Mac) that were
   left out of the AI stage on purpose; 178 groups wait in `needs-parser`. Web
   access logs (nginx, ELB, IIS) and VPC flow split into many tiny groups that
   never reach the threshold.
3. **Event time is wrong in places.** Sophos events are stamped at midnight
   (date and time are separate fields and the rule language could not join them
   when the mappings were written). 406 fallback events carry ingest time
   although the line has a timestamp. Syslog lines without a year get the
   current year, so one file mixes 2005 and 2026.
4. **Agent mappings leave known values unmapped** (HAProxy source port,
   FortiGate VPN addresses, GCP status). Schema validation cannot catch this.
5. **Smaller defects.** The seeded Zeek HTTP mapping also binds to 4 SIP
   records. 6 ASA lines fail seeded patterns that reject host names. Stored raw
   text is not byte-exact: NUL bytes and a trailing carriage return are removed.
   In an unlabelled mixed stream, three catch-all sources hit the signature cap,
   which shows the guard needs source metadata to work well.

Labels the evaluator believes are wrong (not fixed yet): one empty raw line,
eight Apache access labels that expect user `-`, 13 Azure/O365 labels that
expect only the local part of the user name, two with port 0 or address 0.0.0.0,
seven CEF values that keep escape sequences, and 41 firewall `status_id` labels
copied from ECS outcome.

## What the stand-in agents reported about the tools

Fixed after the run: `regex_extract` crashed without a capture group;
`enum_lookup` demanded `map`; no way to join fields (`join` added); no way to
keep a secret out of `unmapped` (`drop` added, found via cleartext FTP
passwords); long-tail values inside masked quotes were dropped; test tools said
`ok: true` at a zero match rate (now also report `would_pass_gate_on_samples`).

Not fixed: a mapping cannot choose a class per line; arrays with unstable order
cannot be addressed by name; no hex decoding (auditd); `fetch_vendor_docs` has
no fetcher, so agents mapped vendor fields from memory; the test tools show the
parsed fields of one sample only; a group with fewer than about 20 lines has no
holdout lines, so the save gate checks the samples only.

The mappings saved before these fixes were not rewritten. In particular the
Sophos time mappings and the Zeek FTP password field still need a new version.

No log line in this corpus contained instruction-like text, so the untrusted
input rule was exercised only by the test suite.

---

# Round 2: regrouping tools and a second mapping run

Registry export `registry/exports/dataset-run-2.json`; second evaluator's report
`work/evaluator2/REPORT.md`. The state the first evaluation measured is kept in
`work/run.round1.db`.

## What changed

The first run showed that the mapping agents could see when a group was wrong
but had no way to act on it. Four things were added:

- **Split a group** (`save-split`): by presence of a parsed field or by a
  field's value. It is scoped to one group, so no other group changes. The gate
  refuses a split that separates nothing, gives more than 30 pieces, gives more
  than half as many pieces as lines (a variable, not an event type), or is the
  fourth regroup of the same group.
- **Choose the class per line** (`switch` in a mapping rule).
- **Hand a group to another agent** (`report-problem`), with the reason attached
  and a limit of three hand-offs before it is flagged for a human.
- **Code-side check** (`cli diagnose`, and inside `test-mapping`): finds keys
  present on only some lines and fields with few values, and says which of them
  separate failing lines from passing ones. No model is called.

Also added after agent feedback: `join` (two fields into one value), `drop`
(keep a secret out of `unmapped`), a "Label: value" decoder, a refusal when an
agent reuses another agent's base-mapping name, and a 50-times faster rule load.

## The run

Sonnet subagents, at most three at a time: seven mapping agents, one parser
agent for the 33 groups the mappers handed back, and one last mapping pass for
those groups. They made 7 splits and saved 61 mappings with a `switch`. The
gates refused 24 mapping saves and 3 split saves.

## Before and after (second independent evaluator, same scoring scripts)

| Measure | Round 1 | Round 2 | Out of |
|---|---|---|---|
| Labelled lines parsed | 396 | 396 | 492 |
| Expected values extracted, exact | 1,015 | 1,026 | 1,085 |
| OCSF class acceptable | 188 (55.5%) | 258 (76.1%) | 339 class-labelled lines |
| OCSF class acceptable, parsed lines only | 188 (62.7%) | 258 (86.0%) | 300 |
| OCSF attributes correct, strict | 535 (49.6%) | 753 (69.8%) | 1,079 |
| Events passing schema validation | 15,800 | 15,802 | 15,809 |
| Events that are Base Event | 7,757 (49.1%) | 5,539 (35.0%) | 15,809 |
| Events with no mapping at all | 785 | 257 | 15,809 |

- 70 labelled lines improved their class result; none got worse.
- PAM "authentication failure": 926 of 1,162 lines are now Authentication (15
  before). The other 236 have no `user=`, which OCSF Authentication requires.
- All 7 splits are coherent; none cuts on a variable.
- Hand check of 42 events mapped in this round: 26 right, 13 debatable, 3 wrong
  (Santa process execution still Base Event; one Sophos time 5.5 hours off
  because the `timezone` field is ignored; one GitHub SSO event left as Base).
- Event time: auditd exact on 542 of 542, IIS on 14 of 14; Sophos midnight
  stamps fell from 55 to 17.

The gain is in reaching the right class. Attribute accuracy inside agent-written
specific-class mappings did not improve (69.9%, was 70.6%).

One point in the evaluator's report is a misreading: it lists 31 handed-back
parser items as unworked. Those have status `handed-off` because the parser
agent fixed them and passed them on to the mapping queue; all 31 have a new
parser and a mapping.

## Remaining gaps

1. **39% of records still have no parser** (10,222 of 26,063). This run did not
   touch them: they are the five non-security Loghub sources plus small web-log
   groups. 178 groups wait in `needs-parser`, 647 in the long-tail queue.
2. **5,539 Base Events remain**, 5,282 chosen by a mapping: Apache error chatter
   1,968, osquery 1,348, auditd 490, CyberArk 298. Some of that is correct
   (worker start-up noise). Some is not: user and process data in auditd SYSCALL
   and EXECVE, osquery and Santa stay in `unmapped` because the lines lack an
   attribute the fitting class requires (for example `device`).
3. **257 events have no mapping**: rare Cisco ASA and FTD messages below the
   threshold, extracted by the long-tail agent only.
4. **Event time**: the Sophos `timezone` field is ignored on all 96 events, and
   5,602 syslog events without a year were given an assumed one.
5. **Attribute accuracy of agent mappings is about 70%** and nothing in the
   system checks meaning. Three GitHub audit lines are API Activity where a more
   specific identity class was expected.
