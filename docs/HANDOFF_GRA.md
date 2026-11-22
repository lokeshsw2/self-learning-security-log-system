# Hand-off: running the learning log parser on GRA

What this system does, what to deploy on GRA (MySQL, Kafka, Logstash, ClickHouse), how to configure it, and
how to operate it. Built and tested locally on 2026-11-22; the same code runs on SQLite (local) and MySQL 8
(GRA). Results of the variant comparison are in [AB_COMPARISON.md](AB_COMPARISON.md); open items in
[BACKLOG.md](BACKLOG.md).

## 1. What it does

```
 logs.unparsed (Kafka) ──► Logstash: router ─► per-format pipelines ─► sink ─► logs.parsed ─► ClickHouse
        │                                                     └─ failed lines ─► logs.ls_failed ─► ClickHouse
        └──► learner service (Python) ── groups lines by format ── stores in MySQL
                   │  new format?  bounded AI agents write rules/filters (data, never code)
                   │  code checks every rule: verified in a throwaway Logstash, then deployed
                   └─► writes Logstash pipelines, Logstash reloads; kept lines replayed via logs.replay
```

- **The learner** reads every unparsed line, detects its header, groups it by format (signature), and keeps
  samples. Formats without a rule are queued for the agents.
- **The agents** (Claude API, Sonnet 5.5 by default) write rules as data. A rule is saved only when code
  checks pass: schema-valid OCSF 1.10.0 events, every copied value present in its line, time from the line,
  outcome words agreeing with the event, no lines of another format read.
- **Two writers** (choose with `logstash.variant`):
  - `direct` (Variant B, recommended): one agent writes the whole Logstash filter (grok, dissect, kv, json,
    xml, csv, date, mapping) as checked steps; code renders it; tested in a warm local Logstash sandbox.
  - `compiled` (Variant A): agents write parser and mapping rules for our engine; code compiles them to
    Logstash and keeps a format only where Logstash equals the engine.
- **Deploy**: rules change → compile → verify in a throwaway Logstash on stored lines of every format →
  write the verified set → swap into the live directory (Logstash reloads automatically) → replay the kept
  lines of newly deployed formats.
- **Self-audit and drift**: saved filters are re-run on the newest stored lines and on events read back from
  ClickHouse; failing formats go back to the agent with examples, then to a person. Lines a deployed pipeline
  fails on are counted per pipeline (`logs.ls_failed`).
- **Review UI** (React + shadcn): items the agents gave up on, audit and drift, answer / ignore / dismiss.

## 2. What to provision on GRA

| Component | Needed | Notes |
|---|---|---|
| Python 3.12 host for the learner | yes | `pip install -r requirements.txt` (tested versions pinned) |
| MySQL 8.0 / 8.4 | yes | one database, utf8mb4 / utf8mb4_bin (section 4) |
| Kafka topics | yes | `logs.unparsed` (exists), `logs.parsed`, `logs.replay`, `logs.ls_failed` |
| Logstash 9.x | yes | the production pipelines; **also on the learner host** for the sandbox and verification |
| ClickHouse | yes | tables created by the service (`clickhouse.ingest: true`) or from section 6 |
| Anthropic API key | for learning | `ANTHROPIC_API_KEY` in the learner's environment, never in files |

The learner host runs short-lived Logstash processes: a throwaway one per deploy verification and a warm
sandbox while agents test filters (127.0.0.1:18080 input, 127.0.0.1:9611 API; started with an environment
holding no secrets). Point `LP_LOGSTASH_BIN` at the executable and `LP_LOGSTASH_HOME` at the install
directory (`/usr/share/logstash` with the Linux package) if they are not found on `PATH`.

## 3. Configuration

Start from [deploy/service/production.example.json](../deploy/service/production.example.json). Secrets are
written as `${ENV_NAME}` and filled from the environment at start:

| Setting | Meaning |
|---|---|
| `kafka.bootstrap`, topics, `group_id` | GRA's brokers and topic names; `create_topics: false` in production |
| `kafka.extra` | Python client settings (librdkafka names: `security.protocol`, `sasl.password` ...) |
| `kafka.logstash_extra` | the same for the Logstash kafka plugins, in **their** names (`security_protocol`, `sasl_jaas_config` ...); `${VAR}` is left for Logstash to read from its own environment |
| `store.url` | `mysql://user:${MYSQL_PASSWORD}@host:3306/database` (or `sqlite:///path` locally) |
| `learning.enabled` | off by default: no model calls until switched on |
| `learning.budget_usd_per_cycle` / `_per_day` | hard caps; each agent gets a share (detection, grouping, filters, ...) |
| `logstash.variant` | `direct` (B) or `compiled` (A) |
| `logstash.config_dir` | where the live pipelines are written; run Logstash with `--path.settings` there |
| `clickhouse.url`, `database`, `ingest` | `ingest: true` creates the tables and the Kafka-engine ingestion |

`--status` prints the configuration with secrets masked.

## 4. MySQL

```sql
CREATE DATABASE logparser CHARACTER SET utf8mb4 COLLATE utf8mb4_bin;
CREATE USER 'lp_learner'@'%' IDENTIFIED BY '...';
GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, INDEX ON logparser.* TO 'lp_learner'@'%';
```

- The service creates its tables on first start (`CREATE TABLE IF NOT EXISTS`); nothing else to run.
- `utf8mb4_bin` keeps text comparisons byte-exact, as the engine expects.
- Size: raw lines are pruned per format (`retain_parsed` 200, `retain_unparsed` 1000 per format in
  `config/production.json`); the store stays in the hundreds of MB for thousands of formats.
- Back it up like any application database: it holds the learned rules, their versions and the review
  history. Rules can also be exported as JSON (`python -m logparser.cli --db URL export rules.json`).
- Tested: the full test suite (213 tests) passes on MySQL 8.4 as on SQLite
  (`scripts/mysql.sh start; LP_TEST_STORE=mysql pytest`). The learner consumed 30,000 mixed lines from
  Kafka into MySQL at about 1,500 lines/s on a laptop, and deploy verification ran from the MySQL store.
- SQL in the code is written once; `logparser/store_mysql.py` translates the few SQLite forms in one place.
  A test fails if code adds SQL the translator cannot handle.

## 5. Bringing what was learned locally

```
python scripts/promote_rules.py --from local.db --to "mysql://lp_learner:${MYSQL_PASSWORD}@host:3306/logparser"
```

Copies the active rules (validated, all or nothing), Variant B filters, grouping decisions and the
operations log. Groups are not copied: GRA builds them from its own traffic and picks up rules by format
signature.

Caveat seen in testing: for text formats the grouping can depend on which lines arrive first, so a group on
GRA may hold more line shapes than the same group locally (e.g. a proxy log's `TCP_HIT` and `TCP_DENIED`
lines). The deploy check then leaves that format out rather than mislabel lines, and the audit hands it back
to the agent. Learning on GRA's own traffic avoids this.

## 6. Kafka and ClickHouse

- Topics: `logs.parsed` (JSON per OCSF event, flattened to ClickHouse columns), `logs.replay` (kept lines
  re-sent when a format is first deployed; read from earliest by its own group), `logs.ls_failed` (lines a
  deployed pipeline failed on, with pipeline and reason; `failed_topic: ""` turns it off).
- ClickHouse objects (created with `ingest: true`, or take the statements from
  `logparser/service/clickhouse.py`): `<db>.ocsf_events` (MergeTree), `<db>.parsed_queue` (Kafka engine) and
  `<db>.parsed_mv`; `<db>.ls_failures` with its queue and view (30-day TTL).

## 7. Running it

```
export MYSQL_PASSWORD=... KAFKA_PASSWORD=... KAFKA_JAAS_CONFIG=... ANTHROPIC_API_KEY=...
python -m logparser.service --config production.json                 # the learner (systemd unit)
python -m logparser.service --config production.json --deploy-now    # compile, verify, deploy, exit
logstash --path.settings /var/lib/logparser/logstash                  # the production pipelines
python -m logparser.web --db "mysql://lp_learner:${MYSQL_PASSWORD}@host:3306/logparser" \
       --clickhouse http://clickhouse:8123 --ch-db logs --port 8090       # review UI (bind / proxy as needed)
python -m logparser.lsaudit --db "mysql://..." --clickhouse http://clickhouse:8123 --ch-db logs
```

The learner commits Kafka offsets only after a batch is stored (restart-safe; redelivered lines are skipped),
holds one lock around the store, and runs learning in a background thread.

## 8. Operating it

- **Spend**: learning is off until enabled; every cycle and day is capped; spend per agent and per format is in
  the `tool_calls` table and on the status page. Measured: about $0.12 per new format with Variant B.
- **Review**: the Review page lists what needs a person. An answer goes back to the agent with the item and is
  kept as a correction for later items; "ignore" leaves a format unparsed on purpose.
- **Audit and drift**: run after each learning cycle and from the Review page. The hourly scheduled audit is on
  the backlog. The drift view shows failing rules, new formats from known sources, new key sets, quiet formats
  and lines the live Logstash failed on.
- **Rollback**: rules are versioned; `python -m logparser.cli --db URL rollback RULE_ID` re-activates the
  previous version, and the next deploy picks it up.

## 9. Security

- Log lines are attacker-controlled. Agents only write data: Variant B filters are structured steps checked
  before rendering (no ruby, exec, file or network plugins; no `${`, line breaks or trailing backslashes in
  values; dissect keys plain names); the sandbox Logstash gets an environment without secrets.
- Secrets come from the environment (`${VAR}`), are masked in status output, and never enter generated
  configs: Logstash resolves its own `${VAR}`.
- The review UI has no login of its own: put it behind GRA's access control.

## 10. Known limits

- Variant B leaves split groups (one format whose lines need different classes by a field value) to Variant A.
- Logstash does no schema checking: a renamed key can yield valid-looking but emptier events until the audit
  runs (the hourly audit closes this).
- Base Event fallback in Variant A takes the time from Logstash, not the header (left out unless
  `base_fallback` is on).
- See [BACKLOG.md](BACKLOG.md).
