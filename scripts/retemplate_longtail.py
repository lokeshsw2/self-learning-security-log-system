"""Rebuild the summary slots of every saved long-tail rule with the current code (no model calls),
then re-parse the affected groups so stored events and ClickHouse carry the corrected messages.

  python scripts/retemplate_longtail.py --db work/app.db [--clickhouse http://localhost:8123] [--dry-run]

Stop the UI server first: both would write the same database.
"""
import argparse
import os
import sys
import tempfile
import types

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from logparser.cli import open_engine  # noqa: E402
from logparser.tools import Tools  # noqa: E402


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", required=True)
    ap.add_argument("--settings")
    ap.add_argument("--clickhouse")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()
    db = a.db
    if a.dry_run:                       # work on a throwaway copy
        import sqlite3
        tmp = tempfile.mkdtemp()
        db = os.path.join(tmp, "copy.db")
        with sqlite3.connect(a.db) as src, sqlite3.connect(db) as dst:
            src.backup(dst)            # includes writes still in the -wal file; a file copy would not
    eng = open_engine(types.SimpleNamespace(db=db, settings=a.settings))
    if a.clickhouse and not a.dry_run:
        from logparser.sink import ClickHouseSink
        eng.sink = ClickHouseSink(a.clickhouse)
    t = Tools(eng, "retemplate")
    changed, kept, dropped = [], 0, 0
    for r in eng.store.rules(kind="longtail"):
        sig = r["rule_id"].split(":", 1)[1]
        before = r["body"].get("summary_t") or r["body"].get("summary") or "(none)"
        res = t.retemplate_longtail(sig)
        if not res["changed"]:
            continue
        after = eng.store.active_rule(r["rule_id"])["body"]
        now = after.get("summary_t") or after.get("summary") or "(the line itself)"
        changed.append(sig)
        kept += res["summary"]
        dropped += not res["summary"]
        print(f"{r['rule_id']}\n   before: {before}\n   after:  {now}")
    eng.reload()
    live = [s for s in changed if eng.canonical(s)]
    replay = eng.replay_signatures(live) if live else {}
    print(f"\n{len(changed)} rules rebuilt ({kept} with slots, {dropped} fall back to the line); "
          f"re-parsed {len(live)} groups: {replay}" + ("  [dry run: nothing written]" if a.dry_run else ""))


if __name__ == "__main__":
    main()
