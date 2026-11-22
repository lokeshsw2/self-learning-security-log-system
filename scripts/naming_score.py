"""Score source names assigned by agents against the true file of each line.

  python scripts/naming_score.py RUN.db data/owner_mixed/_origin.jsonl

A line counts as correctly named when its source key carries a vendor name that
contains one of the expected words for its true file (case-insensitive).
"""
import collections
import json
import sqlite3
import sys

EXPECT = {
    "aws_cloudtrail": ["aws", "amazon"], "vpcflow": ["aws", "amazon"],
    "azure_eventhub": ["microsoft"], "azuread": ["microsoft"], "dhcp": ["microsoft"], "dns": ["microsoft"],
    "exchange": ["microsoft"], "office365": ["microsoft"], "onedrive": ["microsoft"], "sharepoint": ["microsoft"],
    "sysmon": ["microsoft"], "microsoft_graph_security": ["microsoft"],
    "barracuda": ["barracuda"], "brivo": ["brivo"], "ciscoasa": ["cisco"], "ciscowsa": ["cisco"],
    "meraki": ["cisco", "meraki"], "duo": ["duo", "cisco"], "citrix": ["citrix", "netscaler"],
    "cloudflare_firewall": ["cloudflare"], "crowdstrike_fdr": ["crowdstrike"], "cyberark": ["cyberark", "cyber-ark"],
    "cyfox_edr": ["cybonet", "cyfox"], "cyntros": ["cyntros"], "fortigate": ["fortinet", "fortigate"],
    "github_audit": ["github"], "kaspersky_endpoint": ["kaspersky"], "mimecast": ["mimecast"],
    "netskope": ["netskope"], "okta": ["okta"], "paloalto_system": ["palo alto"], "paloalto_threat": ["palo alto"],
    "paloalto_traffic": ["palo alto"], "sophos_firewall_idp": ["sophos"], "sophos_firewall_waf": ["sophos"],
    "sophos_firewall_xg": ["sophos"], "trendmicro": ["trend micro"], "vmware_vcenter_eam_access": ["vmware"],
    "watchguard_proxy": ["watchguard"], "zscaler": ["zscaler"],
    "linux": ["linux", "openssh", "openbsd", "unix", "graylog", "nxlog"], "ssh": ["linux", "openssh", "openbsd", "unix", "graylog", "nxlog"],
}
db = sqlite3.connect(sys.argv[1])
origin = {json.loads(l)["offset"]: json.loads(l)["source"] for l in open(sys.argv[2])}
names = {r[0]: (r[1], r[2]) for r in db.execute("select source, vendor, product from sources")}
per = collections.defaultdict(collections.Counter)
ok = unnamed = wrong = 0
wrong_ex = collections.Counter()
for off, src in db.execute("select offset, source from raw"):
    f = origin.get(off, "?")
    v, p = names.get(src, (None, None))
    per[f][f"{v} / {p}" if v else "(unnamed)"] += 1
    if not v:
        unnamed += 1
    elif any(w in v.lower() for w in EXPECT.get(f, [f])):
        ok += 1
    else:
        wrong += 1
        wrong_ex[(f, v)] += 1
n = ok + unnamed + wrong
print(f"lines {n}: named correctly {ok / n:.1%}, named wrongly {wrong / n:.1%}, unnamed {unnamed / n:.1%}")
print("wrong names:", dict(wrong_ex.most_common(10)))
for f in sorted(per):
    print(f"  {f:26s} " + "; ".join(f"{k} ({c})" for k, c in per[f].most_common(3)))
