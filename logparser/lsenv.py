"""Where Logstash is on this host. macOS/Homebrew for local work, the Linux package layout in production:

  LP_LOGSTASH_BIN   the logstash executable          (else PATH, Homebrew, /usr/share/logstash/bin/logstash)
  LP_LOGSTASH_HOME  the install dir with config/      (else Homebrew's newest Cellar version, /usr/share/logstash)
"""
from __future__ import annotations

import os
import shutil

BREW_CELLAR = "/opt/homebrew/Cellar/logstash"


def logstash_bin() -> str:
    for p in (os.environ.get("LP_LOGSTASH_BIN"), shutil.which("logstash"), "/opt/homebrew/bin/logstash",
              "/usr/share/logstash/bin/logstash"):
        if p and os.path.exists(p):
            return p
    raise FileNotFoundError("Logstash not found: set LP_LOGSTASH_BIN")


def config_file(name: str) -> str | None:
    """A file from the install's config/ (jvm.options, log4j2.properties), to copy into a settings dir."""
    homes = [os.environ.get("LP_LOGSTASH_HOME")]
    if os.path.isdir(BREW_CELLAR):
        homes += [os.path.join(BREW_CELLAR, v, "libexec") for v in sorted(os.listdir(BREW_CELLAR), reverse=True)]
    homes += ["/usr/share/logstash", "/etc/logstash"]
    for h in homes:
        if not h:
            continue
        for p in (os.path.join(h, "config", name), os.path.join(h, name)):
            if os.path.exists(p):
                return p
    return None
