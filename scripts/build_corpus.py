"""Assemble the public datasets under data/raw into one corpus.

Output:
  data/corpus/<source>.log     raw lines, byte-for-byte from the origin files
  data/corpus/manifest.json    origin files, licence and attribution per source
  data/corpus/mixed.log        every text source interleaved (the "mixed stream")
  data/corpus/binary/*         binary samples the engine must route aside

Nothing here is used by the engine at run time. It only prepares test input.
"""
from __future__ import annotations

import glob
import hashlib
import json
import os
import shutil

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RAW = os.path.join(ROOT, "data", "raw")
OUT = os.path.join(ROOT, "data", "corpus")

LIC = {
    "loghub": ("Loghub licence (free for research/academic use, attribution required)",
               "https://github.com/logpai/loghub"),
    "beats-apache": ("Apache-2.0", "https://github.com/elastic/beats (filebeat/module)"),
    "beats-elastic": ("Elastic License 2.0 (not permissive; test input only, never seeded as rules)",
                      "https://github.com/elastic/beats (x-pack/filebeat/module)"),
    "sentinel": ("MIT", "https://github.com/Azure/Azure-Sentinel (Sample Data)"),
    "metron": ("Apache-2.0", "https://github.com/apache/metron (metron-integration-test sample data)"),
    "ocsf-examples": ("Apache-2.0", "https://github.com/ocsf/examples"),
}

FB = "beats/filebeat/module"
XP = "beats/x-pack/filebeat/module"
SD = "azure-sentinel/Sample Data/CEF"
MT = "metron/metron-platform/metron-integration-test/src/main/sample/data"

# name -> (licence key, vendor, product, [globs], max lines per origin file)
SOURCES = {
    # Loghub
    "loghub_openssh": ("loghub", "OpenBSD", "OpenSSH", ["loghub/OpenSSH/OpenSSH_2k.log"], None),
    "loghub_linux": ("loghub", "Linux", "syslog", ["loghub/Linux/Linux_2k.log"], None),
    "loghub_apache_error": ("loghub", "Apache", "HTTP Server error log", ["loghub/Apache/Apache_2k.log"], None),
    "loghub_mac": ("loghub", "Apple", "macOS system log", ["loghub/Mac/Mac_2k.log"], None),
    "loghub_windows_cbs": ("loghub", "Microsoft", "Windows CBS log", ["loghub/Windows/Windows_2k.log"], None),
    "loghub_hdfs": ("loghub", "Apache", "HDFS", ["loghub/HDFS/HDFS_2k.log"], None),
    "loghub_zookeeper": ("loghub", "Apache", "ZooKeeper", ["loghub/Zookeeper/Zookeeper_2k.log"], None),
    "loghub_bgl": ("loghub", "IBM", "Blue Gene/L RAS log", ["loghub/BGL/BGL_2k.log"], None),
    # Beats, Apache-2.0
    "apache_access": ("beats-apache", "Apache", "HTTP Server access log", [FB + "/apache/access/test/*.log"], None),
    "nginx_access": ("beats-apache", "F5", "nginx access log", [FB + "/nginx/access/test/*.log"], None),
    "auditd": ("beats-apache", "Linux", "auditd", [FB + "/auditd/log/test/*.log"], 400),
    "haproxy": ("beats-apache", "HAProxy", "HAProxy", [FB + "/haproxy/log/test/*.log"], None),
    "iis_access": ("beats-apache", "Microsoft", "IIS", [FB + "/iis/access/test/*.log"], None),
    "system_auth": ("beats-apache", "Linux", "auth log", [FB + "/system/auth/test/*.log"], None),
    "osquery": ("beats-apache", "osquery", "osquery", [FB + "/osquery/result/test/*.log"], None),
    "santa": ("beats-apache", "Google", "Santa", [FB + "/santa/log/test/*.log"], None),
    # Beats, Elastic licence (test input only)
    "cisco_asa": ("beats-elastic", "Cisco", "ASA", [XP + "/cisco/asa/test/*.log"], None),
    "cisco_ftd": ("beats-elastic", "Cisco", "Firepower Threat Defense", [XP + "/cisco/ftd/test/*.log"], None),
    "cisco_ios": ("beats-elastic", "Cisco", "IOS", [XP + "/cisco/ios/test/*.log"], None),
    "panw_panos": ("beats-elastic", "Palo Alto Networks", "PAN-OS", [XP + "/panw/panos/test/*.log"], None),
    "fortinet_fortigate": ("beats-elastic", "Fortinet", "FortiGate", [XP + "/fortinet/firewall/test/*.log"], None),
    "checkpoint_firewall": ("beats-elastic", "Check Point", "Firewall", [XP + "/checkpoint/firewall/test/*.log"], None),
    "juniper_srx": ("beats-elastic", "Juniper", "SRX", [XP + "/juniper/srx/test/*.log"], None),
    "sophos_xg": ("beats-elastic", "Sophos", "XG Firewall", [XP + "/sophos/xg/test/*.log"], None),
    "suricata_eve": ("beats-elastic", "OISF", "Suricata", [XP + "/suricata/eve/test/*.log"], None),
    "zeek_json": ("beats-elastic", "Zeek", "Zeek", [XP + "/zeek/*/test/*.log"], None),
    "cef_generic": ("beats-elastic", "various", "CEF samples", [XP + "/cef/log/test/*.log"], None),
    "aws_cloudtrail": ("beats-elastic", "AWS", "CloudTrail", [XP + "/aws/cloudtrail/test/*.log"], None),
    "aws_vpcflow": ("beats-elastic", "AWS", "VPC Flow Logs", [XP + "/aws/vpcflow/test/*.log"], None),
    "aws_elb": ("beats-elastic", "AWS", "Elastic Load Balancing", [XP + "/aws/elb/test/*.log"], None),
    "okta_system": ("beats-elastic", "Okta", "System Log", [XP + "/okta/system/test/*.log"], None),
    "o365_audit": ("beats-elastic", "Microsoft", "Office 365 audit", [XP + "/o365/audit/test/*.log"], None),
    "iptables": ("beats-elastic", "Linux", "iptables", [XP + "/iptables/log/test/*.log"], None),
    "crowdstrike_falcon": ("beats-elastic", "CrowdStrike", "Falcon", [XP + "/crowdstrike/falcon/test/*.log"], None),
    "cyberark_pas": ("beats-elastic", "CyberArk", "PAS", [XP + "/cyberarkpas/audit/test/*.log"], None),
    "azure_signin": ("beats-elastic", "Microsoft", "Entra ID sign-in logs", [XP + "/azure/signinlogs/test/*.log"], None),
    "gcp_audit": ("beats-elastic", "Google Cloud", "Audit Logs", [XP + "/gcp/audit/test/*.log"], None),
    # Azure Sentinel sample data, MIT (raw CEF over syslog)
    "barracuda_waf": ("sentinel", "Barracuda", "WAF", [SD + "/barracudaWAFCEF.txt"], None),
    "citrix_adc": ("sentinel", "Citrix", "NetScaler ADC", [SD + "/CitrixADC.txt"], None),
    "fortiweb": ("sentinel", "Fortinet", "FortiWeb Cloud", [SD + "/fortiwebwafsamplelog.txt"], None),
    "illumio_core": ("sentinel", "Illumio", "PCE", [SD + "/IllumioCore"], None),
    "radiflow_isid": ("sentinel", "Radiflow", "iSID", [SD + "/RadiflowIsid_RawLogs.txt"], None),
    "votiro": ("sentinel", "Votiro", "Votiro cloud", [SD + "/VotiroSampleData.txt"], None),
    "withsecure": ("sentinel", "WithSecure", "Elements", [SD + "/WithSecureViaConnectorSampleData.txt"], None),
    # Apache Metron samples, Apache-2.0
    "metron_asa": ("metron", "Cisco", "ASA", [MT + "/asa/raw/asa_raw"], None),
    "trendmicro_leef": ("metron", "Trend Micro", "Deep Security (LEEF)", [MT + "/leef/raw/leefOutput"], None),
    "snort": ("metron", "Cisco", "Snort", [MT + "/snort/raw/SnortOutput"], 300),
    "squid": ("metron", "Squid", "Squid proxy", [MT + "/squid/raw/SquidExampleOutput"], None),
    "yaf": ("metron", "CERT NetSA", "YAF", [MT + "/yaf/raw/YafExampleOutput"], 300),
    "syslog5424": ("metron", "various", "RFC 5424 syslog", [MT + "/syslog5424/raw/Syslog5424Output"], None),
    "websphere": ("metron", "IBM", "WebSphere", [MT + "/websphere/raw/WebsphereOutput.txt"], None),
    # OCSF examples, Apache-2.0
    "zeek_samples": ("ocsf-examples", "Zeek", "Zeek", ["ocsf-examples/raw_sample_log_dataset/Zeek/*.log"], 60),
}

BINARY = ["ocsf-examples/raw_sample_log_dataset/Microsoft/WinEventLog/Security/xml/security.evtx"]


def read_lines(path: str, cap):
    with open(path, "rb") as fh:
        data = fh.read()
    lines = data.split(b"\n")
    if lines and lines[-1] == b"":
        lines.pop()
    lines = [ln.rstrip(b"\r") for ln in lines]
    return lines[:cap] if cap else lines


def main() -> None:
    os.makedirs(OUT, exist_ok=True)
    os.makedirs(os.path.join(OUT, "binary"), exist_ok=True)
    manifest = {}
    per_source = {}
    for name, (lic, vendor, product, globs, cap) in SOURCES.items():
        files = []
        for g in globs:
            files += sorted(glob.glob(os.path.join(RAW, g)))
        lines, origins = [], []
        for f in files:
            got = read_lines(f, cap)
            origins.append({"file": os.path.relpath(f, RAW), "lines": len(got)})
            lines += got
        with open(os.path.join(OUT, name + ".log"), "wb") as fh:
            for ln in lines:
                fh.write(ln + b"\n")
        per_source[name] = lines
        manifest[name] = {
            "vendor": vendor, "product": product, "lines": len(lines),
            "license": LIC[lic][0], "attribution": LIC[lic][1], "origin": origins,
        }
        print(f"{name:24s} {len(lines):6d} lines from {len(files)} file(s)")

    # Mixed stream: deterministic interleave. Sources that carry file-level
    # header directives (#Fields, #fields) or multi-line records stay in blocks,
    # because a real collector would not shuffle lines inside one file either.
    block = {"iis_access", "websphere", "aws_cloudtrail", "osquery"}
    keyed = []
    for name, lines in per_source.items():
        for i, ln in enumerate(lines):
            if name in block:
                k = hashlib.md5(name.encode()).hexdigest()
                keyed.append((k, name, i, ln))
            else:
                k = hashlib.md5(b"%s:%d" % (name.encode(), i // 20)).hexdigest()
                keyed.append((k, name, i, ln))
    keyed.sort(key=lambda t: (t[0], t[1], t[2]))
    with open(os.path.join(OUT, "mixed.log"), "wb") as fh, \
            open(os.path.join(OUT, "mixed.origin.jsonl"), "w") as oh:
        for _, name, i, ln in keyed:
            fh.write(ln + b"\n")
            oh.write(json.dumps({"source": name, "line": i}) + "\n")
    for b in BINARY:
        shutil.copy(os.path.join(RAW, b), os.path.join(OUT, "binary", os.path.basename(b)))
    with open(os.path.join(OUT, "manifest.json"), "w") as fh:
        json.dump(manifest, fh, indent=1)
    print("total", sum(m["lines"] for m in manifest.values()), "lines,", len(manifest), "sources")


if __name__ == "__main__":
    main()
