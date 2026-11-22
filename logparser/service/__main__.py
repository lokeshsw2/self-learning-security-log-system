"""Run the learning service.

  python -m logparser.service --config deploy/service/local.json            # until Ctrl-C
  python -m logparser.service --config deploy/service/local.json --idle-exit 20 --status
"""
import argparse
import json
import logging

from ..envfile import load_env
from .config import ServiceConfig
from .runner import KafkaConsumer, LearnerService, ensure_topics


def main() -> None:
    load_env()
    ap = argparse.ArgumentParser(prog="logparser.service")
    ap.add_argument("--config", required=True)
    ap.add_argument("--max-batches", type=int)
    ap.add_argument("--idle-exit", type=float, help="stop after this many seconds without messages")
    ap.add_argument("--status", action="store_true", help="print the status as JSON when stopping")
    ap.add_argument("--deploy-now", action="store_true", help="compile, verify and deploy the current rules, then exit")
    a = ap.parse_args()
    cfg = ServiceConfig.load(a.config)
    if cfg.kafka.create_topics:
        made = ensure_topics(cfg)
        if made:
            print("created topics:", made, flush=True)
    if cfg.clickhouse.ingest:
        from .clickhouse import ensure_ingest
        ensure_ingest(cfg.clickhouse.url, cfg.clickhouse.database, cfg.kafka.bootstrap, cfg.kafka.parsed_topic)
    svc = LearnerService(cfg)
    deployer = None
    if cfg.logstash.variant == "compiled" and cfg.logstash.deploy:
        from .deploy import Deployer
        deployer = Deployer(svc)
        svc.on_rules_changed = deployer.deploy
    if a.deploy_now:
        print(json.dumps(deployer.deploy() if deployer else {"note": "deploy is off"}, indent=1, default=str))
        return
    svc.consumer = KafkaConsumer(cfg, on_revoke=svc.on_revoke)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    svc.install_signal_handlers()
    print(f"learning service: {cfg.kafka.bootstrap} {cfg.kafka.unparsed_topic} -> store "
          f"{cfg.store['url']} (learning {'on' if cfg.learning.enabled else 'off'})", flush=True)
    try:
        st = svc.run(max_batches=a.max_batches, idle_exit_s=a.idle_exit)
    finally:
        svc.consumer.close()
    if a.status:
        print(json.dumps(st, indent=1, default=str))


if __name__ == "__main__":
    main()
