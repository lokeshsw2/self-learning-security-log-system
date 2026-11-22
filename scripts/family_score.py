"""How well source families recover the true source of each line (unlabelled mixed run).

  python scripts/family_score.py RUN.db data/owner_mixed/_origin.jsonl

A source here is the engine's source key with the label removed: the detection
bucket, plus the family for structured records without a producer name.
Purity: share of lines whose source key holds mostly their own vendor.
Fragments: how many source keys one vendor's lines are spread over.
"""
import collections
import json
import sqlite3
import sys

# sources of one vendor and one format, which should share a family
VENDOR = {"exchange": "microsoft365", "onedrive": "microsoft365", "sharepoint": "microsoft365", "office365": "microsoft365",
          "paloalto_traffic": "paloalto", "paloalto_threat": "paloalto", "paloalto_system": "paloalto",
          "sophos_firewall_idp": "sophos", "sophos_firewall_waf": "sophos", "sophos_firewall_xg": "sophos"}
db = sqlite3.connect(sys.argv[1])
origin = {json.loads(l)["offset"]: json.loads(l)["source"] for l in open(sys.argv[2])}
by_key = collections.defaultdict(collections.Counter)
by_vendor = collections.defaultdict(collections.Counter)
n = 0
for off, src in db.execute("select offset, source from raw"):
    v = VENDOR.get(origin.get(off, "?"), origin.get(off, "?"))
    key = src.split("|", 1)[1]
    by_key[key][v] += 1
    by_vendor[v][key] += 1
    n += 1
pure = sum(c.most_common(1)[0][1] for c in by_key.values())
print(f"lines {n}; source keys {len(by_key)}; vendors {len(by_vendor)}; purity {pure / n:.2%}")
print("source keys that mix vendors:")
for k, c in sorted(by_key.items(), key=lambda kv: -sum(kv[1].values())):
    if len(c) > 1:
        print(f"  {sum(c.values()):6d}  {k[:60]:60s} {dict(c.most_common(4))}")
print("vendors spread over more than one source key:",
      {v: len(c) for v, c in sorted(by_vendor.items(), key=lambda kv: -len(kv[1])) if len(c) > 1})
