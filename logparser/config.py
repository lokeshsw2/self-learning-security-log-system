"""Engine settings. These are operating thresholds, not format knowledge.

Everything format-specific lives in the registry as data.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, fields


@dataclass
class Settings:
    # A new group is sent to the needs-parser / needs-mapping queue at this count.
    group_threshold: int = 50
    # Sample raw lines kept per group, chosen for diversity.
    samples_max: int = 20
    # Explosion guard: distinct signatures allowed per source.
    signature_cap: int = 500
    # Explosion guard: also trip when signatures/lines stays above this ratio
    # once the source has produced at least `explosion_min_lines` lines.
    explosion_ratio: float = 0.5
    explosion_min_lines: int = 400
    # Near-duplicate merge: a template position counts as an unmasked variable
    # when it shows at least this many distinct values.
    merge_min_distinct: int = 3
    merge_candidates: str = "exact"     # or "drain"
    drain_sim_th: float = 0.5
    drain_depth: int = 4
    # Format drift: key-set overlap (Jaccard) needed to attach a new structured
    # signature to an existing group as a new version of it.
    drift_overlap: float = 0.8
    # Parse failures on an existing group before it is queued for repair.
    drift_failures: int = 5
    # Idle batches before a below-threshold group goes to the long-tail queue,
    # and before an idle signature with no rule is dropped (TTL).
    longtail_idle_batches: int = 2
    ttl_idle_batches: int = 500
    # Save gates.
    parser_min_match: float = 1.0       # on the samples the agent saw
    parser_min_holdout: float = 0.98    # on stored lines the agent did not see
    # Shadow mode: lines a shadow rule must hold on before promotion.
    shadow_mode: bool = False           # new versions of live rules start in shadow
    shadow_min_lines: int = 2000
    shadow_min_ok: float = 0.995
    # Normalisation.
    default_tz: str = "UTC"
    max_line_len: int = 65536
    keep_raw_data: bool = False
    ocsf_version: str = "1.10.0"
    # Long-tail agent daily budget (calls).
    longtail_daily_budget: int = 200

    @classmethod
    def load(cls, path: str | None) -> "Settings":
        s = cls()
        if path:
            with open(path) as fh:
                data = json.load(fh)
            known = {f.name for f in fields(cls)}
            for k, v in data.items():
                if k not in known:
                    raise ValueError(f"unknown setting: {k}")
                setattr(s, k, v)
        return s

    def to_dict(self) -> dict:
        return asdict(self)
