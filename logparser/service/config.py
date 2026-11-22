"""Configuration of the learning service. Everything that differs between this Mac and a production
system (broker, topics, database, ClickHouse, Logstash paths, budgets) lives here, not in code.

  {
    "kafka": {"bootstrap": "127.0.0.1:19092", "unparsed_topic": "logs.unparsed", "parsed_topic": "logs.parsed",
              "group_id": "lp-learner", "batch_max": 2000, "poll_timeout_s": 1.0, "create_topics": true},
    "store": {"url": "sqlite:///work/service/learner.db"},
    "engine_settings": "config/production.json",
    "learning": {"enabled": false, "interval_s": 300, "model": "claude-sonnet-5-5", "roles": "all",
                 "limit": 20, "fix_rounds": 1, "budget_usd_per_cycle": 0.5, "budget_usd_per_day": 5.0},
    "logstash": {"variant": "compiled", "config_dir": "work/service/logstash"},
    "clickhouse": {"url": "http://localhost:8123", "database": "logs"}
  }
"""
from __future__ import annotations

import copy
import json
import os
import re
from dataclasses import asdict, dataclass, field

_ENV = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")
SECRET_KEYS = re.compile(r"pass|secret|token|key|sasl\.jaas", re.I)


def _env(value):
    """"${NAME}" in a config string is replaced by the environment variable NAME (secrets stay out of files)."""
    if isinstance(value, str):
        return _ENV.sub(lambda m: os.environ.get(m.group(1), ""), value)
    return value


@dataclass
class KafkaConfig:
    bootstrap: str = "127.0.0.1:19092"     # local test broker; production sets its own
    unparsed_topic: str = "logs.unparsed"
    parsed_topic: str = "logs.parsed"
    replay_topic: str = "logs.replay"     # kept lines re-sent to Logstash when their format is first deployed
    failed_topic: str = "logs.ls_failed"  # lines a deployed Logstash pipeline failed on (drift signal); "" = off
    group_id: str = "lp-learner"
    logstash_group: str = "lp-logstash"   # the deployed pipelines' consumer group
    batch_max: int = 2000
    poll_timeout_s: float = 1.0
    create_topics: bool = False          # local testing only; production topics are managed elsewhere
    partitions: int = 4
    idle_flush_s: float = 60.0            # quiet this long: small groups still without a rule go to the long tail
    extra: dict = field(default_factory=dict)   # client settings (security, SASL...); "${ENV}" values allowed

    def client_extra(self) -> dict:
        return {k: _env(v) for k, v in self.extra.items()}


@dataclass
class LearningConfig:
    enabled: bool = False                # no model calls unless switched on
    interval_s: int = 300                # at most one learning cycle per interval
    model: str = "claude-sonnet-5-5"
    roles: str | list = "all"
    limit: int = 20                      # items per agent per cycle
    fix_rounds: int = 1
    budget_usd_per_cycle: float = 0.5
    budget_usd_per_day: float = 5.0


@dataclass
class LogstashConfig:
    variant: str = "compiled"            # "compiled" (rules -> Logstash) or "direct" (agents write filters)
    config_dir: str = "work/service/logstash"   # Logstash runs with --path.settings here and reloads on change
    deploy: bool = True                   # compile, verify and deploy when the rules change
    verify_per_group: int = 8             # stored lines per group in the verification run
    verify_max_iter: int = 3
    workers: int = 1
    heap: str = "2g"
    base_fallback: bool = False           # also deploy parsed groups with no mapping yet, as OCSF Base Event


@dataclass
class ClickHouseConfig:
    url: str = "http://localhost:8123"
    database: str = "logs"
    ingest: bool = False                  # create the tables and the Kafka ingestion of the parsed topic


@dataclass
class ServiceConfig:
    kafka: KafkaConfig = field(default_factory=KafkaConfig)
    store: dict = field(default_factory=lambda: {"url": "sqlite:///work/service/learner.db"})
    engine_settings: str | None = "config/production.json"
    learning: LearningConfig = field(default_factory=LearningConfig)
    logstash: LogstashConfig = field(default_factory=LogstashConfig)
    clickhouse: ClickHouseConfig = field(default_factory=ClickHouseConfig)

    @classmethod
    def load(cls, path: str | None) -> "ServiceConfig":
        cfg = cls()
        if not path:
            return cfg
        with open(path) as fh:
            data = json.load(fh)
        parts = {"kafka": KafkaConfig, "learning": LearningConfig, "logstash": LogstashConfig,
                 "clickhouse": ClickHouseConfig}
        for k, v in data.items():
            if k in parts:
                known = set(parts[k].__dataclass_fields__)
                unknown = set(v) - known
                if unknown:
                    raise ValueError(f"unknown {k} settings: {sorted(unknown)}")
                setattr(cfg, k, parts[k](**v))
            elif k in ("store", "engine_settings"):
                setattr(cfg, k, v)
            else:
                raise ValueError(f"unknown setting: {k}")
        if cfg.logstash.variant not in ("compiled", "direct"):
            raise ValueError("logstash.variant must be 'compiled' or 'direct'")
        cfg.validate()
        return cfg

    def validate(self) -> None:
        from ..harness import ORDER
        lc = self.learning
        if lc.roles != "all":
            bad = [r for r in lc.roles if r not in ORDER + ["longtail", "ls-direct"]]
            if bad:
                raise ValueError(f"learning.roles: unknown roles {bad}; known: {ORDER + ['longtail', 'ls-direct']}")
        if lc.interval_s <= 0 or lc.limit <= 0 or lc.fix_rounds < 0:
            raise ValueError("learning.interval_s and learning.limit must be positive, fix_rounds >= 0")
        if lc.budget_usd_per_cycle < 0 or lc.budget_usd_per_day < 0:
            raise ValueError("learning budgets cannot be negative")
        if self.kafka.batch_max <= 0 or self.kafka.idle_flush_s < 0:
            raise ValueError("kafka.batch_max must be positive and idle_flush_s >= 0")
        unknown = set(self.store) - {"url"}
        if unknown:
            raise ValueError(f"unknown store settings: {sorted(unknown)}")

    def redacted(self) -> dict:
        """The configuration with secret-looking client settings hidden (for status pages and logs)."""
        d = copy.deepcopy(asdict(self))
        d["kafka"]["extra"] = {k: ("***" if SECRET_KEYS.search(k) else v) for k, v in d["kafka"]["extra"].items()}
        d["store"] = {"url": re.sub(r"//([^:/@]+):[^@]+@", r"//\1:***@", d["store"].get("url", ""))}
        return d

    def sqlite_path(self) -> str:
        url = self.store.get("url", "")
        if not url.startswith("sqlite:///"):
            raise ValueError(f"store url {url!r}: only sqlite:/// is implemented so far (MySQL comes in phase 6)")
        path = url[len("sqlite:///"):]
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        return path

    def to_dict(self) -> dict:
        return asdict(self)
