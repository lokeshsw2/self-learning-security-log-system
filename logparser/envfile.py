"""Load KEY=VALUE lines from a .env file into os.environ (no extra dependency).

Shell variables win: a key already set in the environment is not overwritten.
Empty values are skipped, so a blank placeholder does not count as a key.
"""
from __future__ import annotations

import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load_env(path: str | None = None) -> list:
    path = path or os.path.join(ROOT, ".env")
    loaded = []
    if not os.path.isfile(path):
        return loaded
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            key = key.strip().removeprefix("export ").strip()
            val = val.strip().strip('"').strip("'")
            if key and val and not os.environ.get(key):
                os.environ[key] = val
                loaded.append(key)
    return loaded
