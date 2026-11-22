"""Show how engine groups differ from Loghub templates for one dataset."""
import csv, os, sys, tempfile, collections
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from logparser import registry
from logparser.config import Settings
from logparser.engine import Engine
from logparser.store import SqliteStore
name = sys.argv[1]; limit = int(sys.argv[2]) if len(sys.argv) > 2 else 8
log = os.path.join(ROOT, "data/raw/loghub", name, f"{name}_2k.log")
rows = list(csv.DictReader(open(log + "_structured.csv", encoding="utf-8", errors="replace")))
with tempfile.TemporaryDirectory() as tmp:
    store = SqliteStore(os.path.join(tmp, "b.db"))
    registry.import_rules(store, os.path.join(ROOT, "registry", "builtin.json"))
    eng = Engine(store, Settings(signature_cap=10**9, explosion_ratio=2.0))
    eng.run_file(log, label=name)
    pred = [eng.canonical(r["signature"]) for r in store.q("SELECT signature FROM raw ORDER BY id")]
t2p = collections.defaultdict(collections.Counter); p2t = collections.defaultdict(collections.Counter)
for r, g in zip(rows, pred):
    t2p[(r["EventId"], r["EventTemplate"])][(g["bucket"], g["template"][:110])] += 1
    p2t[(g["bucket"], g["template"][:110])][(r["EventId"], r["EventTemplate"][:90])] += 1
print("== truth templates split across several groups")
for (eid, tpl), c in sorted(t2p.items(), key=lambda kv: -sum(kv[1].values())):
    if len(c) > 1 and limit:
        limit -= 1
        print(f"{eid} [{sum(c.values())}] {tpl[:100]}")
        for k, v in c.most_common(4): print(f"     {v:5d} {k}")
print("== groups that hold several truth templates")
n = 6
for k, c in sorted(p2t.items(), key=lambda kv: -sum(kv[1].values())):
    if len(c) > 1 and n:
        n -= 1
        print(f"{k} [{sum(c.values())}]")
        for kk, v in c.most_common(4): print(f"     {v:5d} {kk}")
