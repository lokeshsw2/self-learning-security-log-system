# Machine notes

[README.md](README.md) is the shared document: the same on every machine, about the system itself. This file
holds what is specific to each machine the repository runs on: the operating system, installed versions,
ports, paths, how the local services are started, and what was measured there. Each machine keeps its own
section up to date; the sections use the same headings so they can be compared.

| Machine | Role | Section |
|---|---|---|
| macOS (Apple M4 Pro) | development; the proof of concept was built and tested here | [macOS](#macos-development-machine) |
| GRA (Linux) | integration with GRA and tests on GRA's data | [Linux](#linux-gra-machine) |

When a change made on one machine matters to the other (a core fix, a version that must match), it also goes
into a change note (`changes/`, README section 13). This file records how each machine is set up; change
notes record what changed.

---

## macOS (development machine)

The whole proof of concept was built and tested on this machine (21-23 Nov 2026): engine, agents, both
Logstash writers, the learning service, ClickHouse ingestion, audit and drift, the review UI, the A vs B
comparison and the MySQL store.

### System

| Item | Value |
|---|---|
| OS | macOS 26.3 (build 25D125) |
| Hardware | Apple M4 Pro, arm64, 48 GB memory |
| Shell | zsh |
| Package manager | Homebrew (`/opt/homebrew`) |

### Installed versions

| Tool | Version | Installed with |
|---|---|---|
| Python | 3.12.12 | uv 0.11.19 (`.venv` in the repo) |
| Python packages | see `requirements.txt` (pinned) | `uv pip install -r requirements.txt` |
| Node.js | 24.12.0 (Homebrew also has node 26.0.0) | Homebrew; used to build the UI |
| Kafka | 4.4.0 (KRaft, no ZooKeeper) | Homebrew |
| Logstash | 9.5.6 | Homebrew |
| Java (for Kafka and Logstash) | OpenJDK 21 | Homebrew `openjdk@21` |
| ClickHouse | 26.10.9.12 | Homebrew cask |
| MySQL | 8.4.13 | Homebrew `mysql@8.4` |

### Local services and ports

Every service runs from a script in `scripts/`, listens on 127.0.0.1 only, keeps its data under `work/`
(git-ignored), and is stopped through its own pid file. None runs as a system service.

| Service | Start / stop | Port(s) | Data |
|---|---|---|---|
| Kafka (test broker) | `scripts/kafka.sh start\|stop\|status` | 19092 (broker), 19093 (controller) | `work/kafka` |
| ClickHouse | `scripts/clickhouse.sh start\|stop\|status` | 8123 (HTTP), 9000 (native) | `work/clickhouse` |
| MySQL 8.4 | `scripts/mysql.sh start\|stop\|status` | 13306 | `work/mysql` |
| Logstash (deployed pipelines) | `scripts/logstash.sh start\|stop\|status` | none (Kafka in, Kafka out) | `work/service/logstash` |
| Logstash sandbox (Variant B tests) | started and stopped by the code | 18080 (input), 9611 (API) | `work/sandbox` |
| Throwaway Logstash (deploy verification) | started and stopped by the code | none | `work/service/verify` |
| Web UI | `.venv/bin/python -m logparser.web --db STORE --ch-db lpsvc --port 8090` | 8090 | the store |
| Learner service | `.venv/bin/python -m logparser.service --config deploy/service/local.json` | none | the store |

Notes:

- The test broker uses 19092 on purpose: another Kafka (in Docker, unrelated to this project) uses 9092 on
  this machine. Never point this project at 9092 here.
- ClickHouse databases used: `lpsvc` (the service's events and `ls_failures`) and `logs` (the engine-side UI).
- MySQL root has no password and listens on 127.0.0.1 only: test data on this machine.

### Paths and configuration

| What | Where |
|---|---|
| Service config | `deploy/service/local.json` (bootstrap 127.0.0.1:19092, SQLite store `work/service/learner.db`, ClickHouse `lpsvc`) |
| Engine settings | `config/production.json` |
| API key | `.env` in the repo root (`ANTHROPIC_API_KEY`), git-ignored, mode 600 |
| Logstash | found automatically at `/opt/homebrew/bin/logstash`; config files from the Homebrew Cellar |
| Test logs | a folder of 42 log files outside the repository (not in git) |
| Stores used in tests | `work/*.db` (SQLite) and the `lp_service` database in the local MySQL |

### Start everything (and stop it)

```sh
scripts/kafka.sh start && scripts/clickhouse.sh start
scripts/logstash.sh start                                    # deployed pipelines
.venv/bin/python -m logparser.service --config deploy/service/local.json
# ... work ...
scripts/logstash.sh stop; scripts/kafka.sh stop; scripts/clickhouse.sh stop; scripts/mysql.sh stop
```

Machine heat: keep Logstash `workers` at 1 and the heap at 1-2 GB, run at most a few agents at once, and stop
Logstash, Kafka and MySQL when not testing.

### macOS specifics met during the build

- zsh stops a `&&` chain when a glob matches nothing (`rm work/x.db*`): name the files.
- zsh does not split an unquoted variable into words (use `${=VAR}`); quote `--include='*.py'` in grep.
- BSD `sed -i` needs an empty suffix: `sed -i '' ...`.
- Homebrew's Logstash keeps `jvm.options` under `/opt/homebrew/Cellar/logstash/<version>/libexec/config`;
  `logparser/lsenv.py` finds it.
- Redpanda was not used: it has no native macOS broker (it needs Docker).

### Measured here

| What | Result |
|---|---|
| Test suite | 213 passed, 1 skipped (SQLite); 213 passed, 1 skipped (MySQL 8.4) |
| Fresh clone, no Logstash | 211 passed, 3 skipped |
| Learner, Kafka into MySQL | 30,000 mixed lines in about 20 s (~1,500 lines/s, one process) |
| Logstash, deployed Variant B set (18 formats) | about 3,800 events/s live; 1.48 M lines sent, ~521,000 events into ClickHouse |
| Deploy verification | ~15-30 s (one JVM start plus the run) |
| Variant B sandbox test | ~3-9 s per test (warm Logstash) |
| Learning cost | about $0.12 per format (Variant B, Sonnet 5.5); about $5.76 spent in all paid tests |

---

## Linux (GRA machine)

To be filled in on the GRA machine. Keep the headings so the two sections can be compared.

### System

| Item | Value |
|---|---|
| OS / distribution | |
| Hardware | |
| Shell | |
| Package manager | |

### Installed versions

| Tool | Version | Installed with |
|---|---|---|
| Python | | |
| Python packages | `requirements.txt` | |
| Node.js (UI build) | | |
| Kafka (GRA's) | | |
| Logstash | | |
| Java | | |
| ClickHouse (GRA's) | | |
| MySQL (GRA's) | 8.0 / 8.4 | |

### Services and ports

| Service | How it runs | Host / port | Notes |
|---|---|---|---|
| Kafka | GRA's brokers | | security protocol (SASL / TLS?) |
| ClickHouse | GRA's | | database name |
| MySQL | GRA's | | database `logparser`, user `lp_learner` |
| Logstash (pipelines) | | | `--path.settings` = `logstash.config_dir` |
| Logstash sandbox | started by the code | 127.0.0.1:18080 / 9611 | ports free? |
| Learner service | systemd unit? | | |
| Web UI | | | behind GRA's access control |
| Model gateway | | | `ANTHROPIC_BASE_URL` |

### Paths and configuration

| What | Where |
|---|---|
| Service config | (from `deploy/service/production.example.json`) |
| Engine settings | `config/production.json` |
| Secrets | environment: `MYSQL_PASSWORD`, `KAFKA_PASSWORD`, `KAFKA_JAAS_CONFIG`, `ANTHROPIC_API_KEY` |
| Logstash | `LP_LOGSTASH_BIN` = , `LP_LOGSTASH_HOME` = |
| Data used for tests | |

### Start and stop

```sh
# to be filled in
```

### Linux specifics met during integration

-

### Measured here

| What | Result |
|---|---|
| Test suite | |
| Learner throughput | |
| Logstash throughput | |
| Deploy verification | |
| Learning cost | |
