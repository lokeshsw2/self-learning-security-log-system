#!/bin/sh
# Deterministic stage on the owner's log sample, from a clean database.
#   scripts/run_owner.sh [db] [sample dir]
DB="${1:-work/own.db}"; DIR="${2:-data/owner_sample}"
cd "$(dirname "$0")/.." || exit 1
rm -f "$DB" "$DB-wal" "$DB-shm"
# learned rules from the earlier public-dataset runs first, then the current builtin and
# seed rules on top, so an old copy of a builtin rule in the export never wins
.venv/bin/python -m logparser.cli --db "$DB" import registry/exports/dataset-run-2.json >/dev/null
.venv/bin/python -m logparser.cli --db "$DB" init >/dev/null
.venv/bin/python -m logparser.cli --db "$DB" run "$DIR"/*.log --label-from-name --finalize --quiet | tail -1
.venv/bin/python scripts/owner_report.py "$DB"
