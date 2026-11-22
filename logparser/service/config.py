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

import json
import os
from dataclasses import asdict, dataclass, field


@dataclass
class KafkaConfig:
    bootstrap: str = "127.0.0.1:19092"     # local test broker; production sets its own
    unparsed_topic: str = "logs.unparsed"
    parsed_topic: str = "logs.parsed"
    group_id: str = "lp-learner"
    batch_max: int = 2000
    poll_timeout_s: float = 1.0
    create_topics: bool = False          # local testing only; production topics are managed elsewhere
    partitions: int = 4
    extra: dict = field(default_factory=dict)   # passed to the client as is (security, SASL, ...)


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
    config_dir: str = "work/service/logstash"


@dataclass
class ClickHouseConfig:
    url: str = "http://localhost:8123"
    database: str = "logs"


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
        return cfg

    def sqlite_path(self) -> str:
        url = self.store.get("url", "")
        if not url.startswith("sqlite:///"):
            raise ValueError(f"store url {url!r}: only sqlite:/// is implemented so far (MySQL comes in phase 6)")
        path = url[len("sqlite:///"):]
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        return path

    def to_dict(self) -> dict:
        return asdict(self)
