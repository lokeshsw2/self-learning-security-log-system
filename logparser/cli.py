"""Operator command line.

  python -m logparser.cli --db run.db init
  python -m logparser.cli --db run.db run data/corpus/cisco_asa.log --label cisco_asa
  python -m logparser.cli --db run.db status
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time

from . import registry
from .config import Settings
from .engine import Engine, metrics
from .store import SqliteStore, open_store

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def open_engine(args) -> Engine:
    store = open_store(args.db)
    settings = Settings.load(args.settings) if args.settings else Settings()
    saved = store.get_state("settings")
    if saved and not args.settings:
        for k, v in saved.items():
            if hasattr(settings, k):
                setattr(settings, k, v)
    return Engine(store, settings)


def cmd_init(args) -> None:
    store = open_store(args.db)
    settings = Settings.load(args.settings) if args.settings else Settings()
    for kv in args.set or []:
        k, v = kv.split("=", 1)
        cur = getattr(settings, k)
        setattr(settings, k, type(cur)(v) if not isinstance(cur, bool) else v.lower() in ("1", "true"))
    store.set_state("settings", settings.to_dict())
    print("builtin:", registry.import_rules(store, os.path.join(ROOT, "registry", "builtin.json")))
    seeds = os.path.join(ROOT, "registry", "seeds")
    if os.path.isdir(seeds) and not args.no_seeds:
        for name, res in registry.load_dir(store, seeds).items():
            print(f"seed {name}: saved {res[0]}, unchanged {res[1]}")


def cmd_run(args) -> None:
    eng = open_engine(args)
    t0 = time.time()
    grand = {}
    for path in args.paths:
        label = args.label
        if args.label_from_name:
            label = os.path.splitext(os.path.basename(path))[0]
        tot = eng.run_file(path, label=label, batch_size=args.batch)
        for k, v in tot.items():
            grand[k] = grand.get(k, 0) + v
        if not args.quiet:
            print(f"{os.path.basename(path):28s} {json.dumps(tot)}")
    if args.finalize:
        eng.finalize()
    dt = time.time() - t0
    print(f"total {json.dumps(grand)} in {dt:.1f}s ({grand.get('records', 0) / max(dt, 1e-9):.0f} records/s)")


def cmd_status(args) -> None:
    store = open_store(args.db)
    print("raw lines by status:", {r["status"]: r["n"] for r in store.q("SELECT status, COUNT(*) n FROM raw GROUP BY status")})
    print("groups by status:  ", {r["status"]: r["n"] for r in store.q("SELECT status, COUNT(*) n FROM groups GROUP BY status")})
    print("events:            ", {("valid" if r["valid"] else "invalid" if r["valid"] is not None else "unmapped"): r["n"]
                                  for r in store.q("SELECT valid, COUNT(*) n FROM events GROUP BY valid")})
    print("queues:            ", {f"{r['name']}/{r['status']}": r["n"] for r in store.q(
        "SELECT name, status, COUNT(*) n FROM queue GROUP BY name, status")})
    print("dlq by stage:      ", {r["stage"]: r["n"] for r in store.q("SELECT stage, COUNT(*) n FROM dlq GROUP BY stage")})
    print("rules by kind:     ", {r["kind"]: r["n"] for r in store.q(
        "SELECT kind, COUNT(*) n FROM rules WHERE status='active' GROUP BY kind")})
    q = [dict(r) for r in store.q("SELECT source, lines, signatures, reason FROM sources WHERE quarantined=1")]
    print("quarantined sources:", q)


def cmd_metrics(args) -> None:
    json.dump(metrics(open_store(args.db)), sys.stdout, indent=1)
    print()


def cmd_export(args) -> None:
    print(registry.export_rules(open_store(args.db), args.path, history=args.history), "rules exported")


def cmd_import(args) -> None:
    print(registry.import_rules(open_store(args.db), args.path, created_by="import"))


def cmd_rollback(args) -> None:
    eng = open_engine(args)
    v = registry.rollback(eng.store, args.rule_id, args.version)
    print(f"{args.rule_id} is now at version {v}")
    sigs = [g["signature"] for g in eng.store.groups("parser_rule=? OR mapping_rule=?", (args.rule_id, args.rule_id))]
    if sigs:
        print("replayed:", eng.replay_signatures(sigs))


def learn_zones(eng) -> None:
    """Fill the deployment time-zone counter from stored lines (for databases made before it existed)."""
    from .reader import Record
    for r in eng.store.q("SELECT raw FROM raw WHERE raw IS NOT NULL AND id % 20 = 0"):
        eng._see_zone(eng.analyse(Record("zones", 0, text=r["raw"]))[0])
    eng.store.set_state("zones", dict(eng._zones))


def cmd_replay(args) -> None:
    eng = open_engine(args)
    if eng.settings.default_tz == "auto" and not eng._zones:
        learn_zones(eng)
        print("deployment time zone:", eng.deployment_tz())
    if args.source:
        print(eng.replay_source(args.source))
    else:
        sigs = args.signature or [g["signature"] for g in eng.store.groups("merged_into IS NULL")]
        print(eng.replay_signatures(sigs))


def cmd_diagnose(args) -> None:
    """Find groups that look mixed and hand them back to the mapping queue with
    the evidence attached. Pure code: no model is called."""
    from . import ocsf
    from .tools import Tools
    eng = open_engine(args)
    t = Tools(eng, "code-check")
    found = 0
    for g in eng.store.groups("merged_into IS NULL AND parser_rule IS NOT NULL AND count >= 4 AND status != 'split'"):
        if g["detail"].get("parent"):
            continue
        r = eng.snap.rule(g["mapping_rule"])
        if not r:
            continue
        resolved = ocsf.resolve_mapping(r["body"], eng.snap.rule)
        is_base = resolved["class"] in ("base_event", "0", 0) and not resolved["switch"]
        invalid = eng.store.q("SELECT COUNT(*) n FROM events WHERE signature=? AND valid=0", (g["signature"],))[0]["n"]
        if not is_base and not invalid:
            continue
        d = t.diagnose(g["signature"], resolved if invalid else None)
        evidence = {k: d[k] for k in ("keys_present_on_only_some_lines", "fields_with_few_values", "split_suggestions")
                    if d.get(k)}
        if not evidence:
            continue
        found += 1
        reason = (f"{invalid} events of this group fail validation" if invalid else
                  "this group is mapped to Base Event, and its lines are not uniform: it may hold several event types")
        if args.enqueue:
            eng.store.reopen("needs-mapping", g["signature"], {
                "signature": g["signature"], "bucket": g["bucket"], "source": g["source"], "count": g["count"],
                "reason": reason, "reported_by": "code-check", "code_check": evidence,
                "current_rule": g["mapping_rule"]})
        elif not args.quiet:
            print(g["signature"], g["source"], g["count"], reason, json.dumps(evidence)[:300])
    print(f"{found} groups look mixed" + (" and were re-queued for mapping" if args.enqueue else ""))


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(prog="logparser")
    ap.add_argument("--db", required=True)
    ap.add_argument("--settings")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("init")
    p.add_argument("--no-seeds", action="store_true")
    p.add_argument("--set", action="append", help="setting=value, stored in the database")
    p.set_defaults(fn=cmd_init)
    p = sub.add_parser("run")
    p.add_argument("paths", nargs="+")
    p.add_argument("--label")
    p.add_argument("--label-from-name", action="store_true")
    p.add_argument("--batch", type=int, default=2000)
    p.add_argument("--finalize", action="store_true")
    p.add_argument("--quiet", action="store_true")
    p.set_defaults(fn=cmd_run)
    sub.add_parser("status").set_defaults(fn=cmd_status)
    sub.add_parser("metrics").set_defaults(fn=cmd_metrics)
    p = sub.add_parser("export")
    p.add_argument("path")
    p.add_argument("--history", action="store_true")
    p.set_defaults(fn=cmd_export)
    p = sub.add_parser("import")
    p.add_argument("path")
    p.set_defaults(fn=cmd_import)
    p = sub.add_parser("rollback")
    p.add_argument("rule_id")
    p.add_argument("--version", type=int)
    p.set_defaults(fn=cmd_rollback)
    p = sub.add_parser("diagnose")
    p.add_argument("--enqueue", action="store_true")
    p.add_argument("--quiet", action="store_true")
    p.set_defaults(fn=cmd_diagnose)
    p = sub.add_parser("repair", help="run the grouping repair scan and the rollback review now")
    p.set_defaults(fn=lambda a: print(json.dumps(__import__("logparser.repair", fromlist=["x"]).after_batch(
        open_engine(a), None))))
    p = sub.add_parser("tiers")
    p.set_defaults(fn=lambda a: print(json.dumps(__import__("logparser.repair", fromlist=["x"]).tiers(
        open_store(a.db)), indent=1)))
    p = sub.add_parser("audit", help="run the meaning checks over saved mappings")
    p.add_argument("--enqueue", action="store_true")
    p.set_defaults(fn=lambda a: print(json.dumps(__import__("logparser.tools", fromlist=["x"]).Tools(
        open_engine(a), "audit").audit_mappings(a.enqueue), indent=1)))
    p = sub.add_parser("finalize")
    p.set_defaults(fn=lambda a: (open_engine(a).finalize(), print("finalized")))
    p = sub.add_parser("replay")
    p.add_argument("--source")
    p.add_argument("--signature", action="append")
    p.set_defaults(fn=cmd_replay)
    argv = list(sys.argv[1:] if argv is None else argv)
    for i in range(len(argv) - 1):          # source keys start with "-": keep them as values, not options
        if argv[i] in ("--source", "--signature") and argv[i + 1].startswith("-"):
            argv[i], argv[i + 1] = f"{argv[i]}={argv[i + 1]}", ""
    args = ap.parse_args([x for x in argv if x != ""])
    args.fn(args)


if __name__ == "__main__":
    main()
