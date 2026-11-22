"""Source families: the source of a line, worked out from its content.

A mixed Kafka topic carries no vendor name. For lines whose header already
names the producer (a syslog program name, a CEF vendor and product) the
detection bucket is enough. Structured records without such a name (JSON,
key=value, delimited, XML) are clustered by their schema instead: the set of
key paths for JSON and XML, the set of keys for key=value, the shape of the
leading columns for delimited data. Records of one vendor share most of their
keys and differ from other vendors', so a new key set joins the family of its
bucket whose core keys it overlaps most, or starts a new family.

The family takes the place of the missing source label: it scopes the
explosion guard, the repair questions and decisions, and sign or mask rules.
It never changes a signature, so learned parsers and mappings are unaffected.
Assignment runs once per new key set, not per event.
"""
from __future__ import annotations

import hashlib
import json
from collections import Counter

STRUCTURED = ("json", "kv", "delimited", "xml")


def _shape(v: str) -> str:
    v = str(v).strip()
    if not v:
        return "E"
    if v.isdigit():
        return "N"
    if len(v) >= 8 and all(c.isdigit() or c in "/:- .T" for c in v):
        return "D"
    return "W"


def keyset(fmt: str, flat: dict, delimiter: str | None = None) -> frozenset:
    """Schema fingerprint of one decoded record. Values are ignored except for
    the shape of the leading columns of delimited data."""
    if fmt == "delimited":
        vals = [flat.get(f"c{i}", "") for i in range(4)] if "c0" in flat else list(flat.values())[:4]
        return frozenset({"shape=" + "".join(_shape(v) for v in vals), f"delim={delimiter or ','}"})
    out = set()
    for k in flat:
        if k.startswith(("@", "_text")):
            continue
        k = k.split("#", 1)[0]
        parts = [p for p in k.split(".") if not p.isdigit()][:2]      # depth 2, array positions dropped
        if parts:
            out.add(".".join(parts))
    return frozenset(out)


def similarity(ks: frozenset, core: set) -> float:
    return len(ks & core) / len(ks | core) if ks or core else 0.0


class Families:
    def __init__(self, store, threshold: float = 0.4):
        self.store = store
        self.threshold = threshold
        self.fams: dict = {}            # id -> {"bucket", "keys": Counter, "n", "label"}
        self.by_bucket: dict = {}
        self.cache: dict = {}           # keyset hash -> family id
        self._dirty: set = set()
        self._new_keys: list = []
        for r in store.q("SELECT * FROM families"):
            f = {"bucket": r["bucket"], "keys": Counter(json.loads(r["keys"])), "n": r["n"], "label": r["label"]}
            self.fams[r["id"]] = f
            self.by_bucket.setdefault(r["bucket"], []).append(r["id"])
        for r in store.q("SELECT keyhash, family_id FROM family_keys"):
            self.cache[r["keyhash"]] = r["family_id"]

    @staticmethod
    def _h(*parts) -> str:
        return hashlib.blake2b("\x1f".join(parts).encode("utf-8", "replace"), digest_size=6).hexdigest()

    def core(self, fid: str) -> set:
        f = self.fams[fid]
        return {k for k, c in f["keys"].items() if c >= 0.5 * f["n"]}

    def assign(self, bucket: str, ks: frozenset) -> str:
        kh = self._h(bucket, *sorted(ks))
        fid = self.cache.get(kh)
        if fid is None:
            best, best_s = None, 0.0
            for cand in self.by_bucket.get(bucket, ()):
                s = similarity(ks, self.core(cand))
                if s > best_s:
                    best, best_s = cand, s
            if best is None or best_s < self.threshold:
                fid = "f" + self._h(bucket, *sorted(ks))
                self.fams[fid] = {"bucket": bucket, "keys": Counter(), "n": 0, "label": None}
                self.by_bucket.setdefault(bucket, []).append(fid)
            else:
                fid = best
            self.cache[kh] = fid
            self._new_keys.append((kh, fid))
            f = self.fams[fid]
            if f["n"] < 200:          # the core settles on the first key sets; later ones only join
                f["keys"].update(ks)
                f["n"] += 1
                self._dirty.add(fid)
        return fid

    def flush(self) -> None:
        for fid in self._dirty:
            f = self.fams[fid]
            self.store.x("INSERT INTO families(id,bucket,keys,n,label) VALUES(?,?,?,?,?) ON CONFLICT(id) DO UPDATE "
                         "SET keys=excluded.keys, n=excluded.n, label=excluded.label",
                         (fid, f["bucket"], json.dumps(dict(f["keys"])), f["n"], f["label"]))
        if self._new_keys:
            self.store.db.executemany("INSERT OR REPLACE INTO family_keys(keyhash, family_id) VALUES(?,?)", self._new_keys)
        self._dirty, self._new_keys = set(), []
