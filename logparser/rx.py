"""All rule patterns run on RE2, which matches in time linear in the input.

A pattern written by an AI agent (or copied from an attacker-controlled log
line) therefore cannot hang a worker. RE2 rejects backreferences and
lookarounds at compile time; that rejection is part of rule validation.
"""
from __future__ import annotations

import functools

import re2

MAX_PATTERN_LEN = 8000
error = re2.error


class PatternError(ValueError):
    pass


@functools.lru_cache(maxsize=8192)
def compile(pattern: str):
    if not isinstance(pattern, str) or not pattern:
        raise PatternError("pattern must be a non-empty string")
    if len(pattern) > MAX_PATTERN_LEN:
        raise PatternError(f"pattern longer than {MAX_PATTERN_LEN} characters")
    opts = re2.Options()
    opts.log_errors = False
    opts.max_mem = 64 << 20
    try:
        return re2.compile(pattern, opts)
    except Exception as exc:  # re2.error
        raise PatternError(f"not a valid RE2 pattern: {exc}") from None


@functools.lru_cache(maxsize=8192)
def compile_b(pattern: str):
    """The same pattern compiled for bytes. For ASCII text, byte offsets equal character offsets,
    and the RE2 wrapper skips its offset conversions, which roughly halves the cost of a match."""
    compile(pattern)                      # validates
    opts = re2.Options()
    opts.log_errors = False
    opts.max_mem = 64 << 20
    return re2.compile(pattern.encode("utf-8"), opts)


def search_dict(pattern: str, text: str):
    """Search and return the named groups as a dict of str, or None. Uses the bytes path for ASCII text."""
    if text.isascii():
        m = compile_b(pattern).search(text.encode("ascii"))
        if not m:
            return None
        return {(k.decode("ascii") if isinstance(k, bytes) else k): (v.decode("ascii") if v is not None else None)
                for k, v in m.groupdict().items()}
    m = compile(pattern).search(text)
    return m.groupdict() if m else None


def check(pattern: str) -> str | None:
    """Return an error string, or None when the pattern is usable."""
    try:
        compile(pattern)
        return None
    except PatternError as exc:
        return str(exc)
