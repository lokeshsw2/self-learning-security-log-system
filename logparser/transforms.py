"""The fixed transform library that mapping rules may call.

Adding a function here is a code change and should be rare. Rules can only
name these functions and pass plain arguments; they cannot supply code.
A transform returns the new value, or None to drop the field.
"""
from __future__ import annotations

import calendar
import datetime as dt
import math
from zoneinfo import ZoneInfo

from . import rx

MONTHS = {m.lower(): i for i, m in enumerate(calendar.month_abbr) if m}
_ISO = rx.compile(r"^(\d{4})-(\d\d)-(\d\d)[Tt ](\d\d):(\d\d):(\d\d)(?:[.,](\d+))?\s*(Z|z|UTC|GMT|[+-]\d\d:?\d\d)?$")
_SLASH = rx.compile(r"^(\d{4})/(\d\d?)/(\d\d?)[ T](\d\d):(\d\d):(\d\d)(?:[.,](\d+))?$")
_SYSLOG = rx.compile(r"^(?:[A-Z][a-z]{2},? )?([A-Z][a-z]{2})\s+(\d{1,2})(?:\s+(\d{4}))?\s+(\d\d):(\d\d):(\d\d)(?:[.,](\d+))?"
                     r"(?:\s+(\d{4}))?(?:\s+(Z|UTC|GMT|[+-]\d\d:?\d\d))?$")
_CLF = rx.compile(r"^(\d\d?)/([A-Za-z]{3})/(\d{4})[: ](\d\d):(\d\d):(\d\d)(?:[.,](\d+))?(?:\s+([+-]\d{4}))?$")
_OFFSET = rx.compile(r"^([+-])(\d\d):?(\d\d)$")
_NUM = rx.compile(r"^-?\d+(?:\.\d+)?$")
_INT = rx.compile(r"^\s*([+-]?\d+)\s*$")


class TransformError(ValueError):
    pass


def _tz(name: str | None, ctx: dict):
    name = name or ctx.get("default_tz") or "UTC"
    if name in ("Z", "z", "UTC", "GMT"):
        return dt.timezone.utc
    m = _OFFSET.match(name)
    if m:
        sign = -1 if m.group(1) == "-" else 1
        return dt.timezone(sign * dt.timedelta(hours=int(m.group(2)), minutes=int(m.group(3))))
    try:
        return ZoneInfo(name)
    except Exception:
        raise TransformError(f"unknown time zone: {name}") from None


def _frac_us(frac: str | None) -> int:
    return int((frac or "0")[:6].ljust(6, "0"))


def _ms(d: dt.datetime) -> int:
    return calendar.timegm(d.utctimetuple()) * 1000 + d.microsecond // 1000


def _flag(ctx: dict, name: str) -> None:
    ctx.setdefault("flags", set()).add(name)


def _year(month: int, day: int, ctx: dict) -> int:
    """Year for a timestamp that has none: the most recent one not in the future."""
    now = dt.datetime.fromtimestamp(ctx.get("now", 0) or dt.datetime.now().timestamp(), dt.timezone.utc)
    _flag(ctx, "year_assumed")
    for y in (now.year, now.year - 1):
        try:
            if dt.datetime(y, month, day, tzinfo=dt.timezone.utc) <= now + dt.timedelta(days=2):
                return y
        except ValueError:
            continue
    return now.year - 1


def parse_timestamp(value, args: dict, ctx: dict):
    """Any common textual or epoch timestamp -> epoch milliseconds (OCSF timestamp_t)."""
    s = str(value).strip().strip("[]")
    if not s:
        return None
    unit = args.get("unit")
    if _NUM.match(s) and not args.get("formats"):
        f = float(s)
        if unit is None:
            a = abs(f)
            unit = "s" if a < 1e11 else "ms" if a < 1e14 else "us" if a < 1e17 else "ns"
        scale = {"s": 1000.0, "ms": 1.0, "us": 1e-3, "ns": 1e-6}[unit]
        return int(f * scale)
    tzname = args.get("tz")
    for fmt in args.get("formats") or []:
        try:
            d = dt.datetime.strptime(s, fmt)
        except ValueError:
            continue
        if "%Y" not in fmt and "%y" not in fmt and "%G" not in fmt:
            d = d.replace(year=_year(d.month, d.day, ctx))
        if d.tzinfo is None:
            _flag(ctx, "tz_assumed")
            d = d.replace(tzinfo=_tz(tzname, ctx))
        return _ms(d)
    m = _ISO.match(s)
    if m:
        y, mo, da, h, mi, se, frac, off = m.groups()
        d = dt.datetime(int(y), int(mo), int(da), int(h), int(mi), int(se), _frac_us(frac))
    else:
        m = _SLASH.match(s)
        if m:
            y, mo, da, h, mi, se, frac = m.groups()
            off = None
            d = dt.datetime(int(y), int(mo), int(da), int(h), int(mi), int(se), _frac_us(frac))
        else:
            m = _SYSLOG.match(s)
            if m:
                mon, da, y1, h, mi, se, frac, y2, off = m.groups()
                if mon.lower() not in MONTHS:
                    raise TransformError(f"unparseable timestamp: {s[:60]}")
                mo = MONTHS[mon.lower()]
                y = y1 or y2 or args.get("year") or _year(mo, int(da), ctx)
                d = dt.datetime(int(y), mo, int(da), int(h), int(mi), int(se), _frac_us(frac))
            else:
                m = _CLF.match(s)
                if not m:
                    raise TransformError(f"unparseable timestamp: {s[:60]}")
                da, mon, y, h, mi, se, frac, off = m.groups()
                if mon.lower() not in MONTHS:
                    raise TransformError(f"unparseable timestamp: {s[:60]}")
                d = dt.datetime(int(y), MONTHS[mon.lower()], int(da), int(h), int(mi), int(se), _frac_us(frac))
    if off:
        d = d.replace(tzinfo=_tz(off, ctx))
    else:
        _flag(ctx, "tz_assumed")
        d = d.replace(tzinfo=_tz(tzname, ctx))
    return _ms(d)


def to_int(value, args, ctx):
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, (int, float)):
        return int(value)
    s = str(value).strip().replace(",", "") if args.get("allow_commas") else str(value).strip()
    base = args.get("base", 10)
    try:
        if base == 16:
            return int(s, 16)
        if base == "auto":
            return int(s, 0)
        return int(float(s)) if "." in s or "e" in s.lower() else int(s)
    except ValueError:
        raise TransformError(f"not an integer: {s[:40]}") from None


def to_float(value, args, ctx):
    try:
        f = float(str(value).strip())
    except ValueError:
        raise TransformError(f"not a number: {str(value)[:40]}") from None
    if math.isnan(f) or math.isinf(f):
        raise TransformError("not a finite number")
    return f


def to_bool(value, args, ctx):
    s = str(value).strip().lower()
    if s in ("true", "1", "yes", "y", "t", "on"):
        return True
    if s in ("false", "0", "no", "n", "f", "off"):
        return False
    raise TransformError(f"not a boolean: {s[:40]}")


def to_str(value, args, ctx):
    return str(value)


def enum_lookup(value, args, ctx):
    table = args.get("map") or {}
    s = str(value)
    if args.get("case_insensitive", True):
        s = s.lower().strip()
        table = {str(k).lower(): v for k, v in table.items()}
    if s in table:
        return table[s]
    for pat, v in (args.get("patterns") or {}).items():
        if rx.compile(pat).search(str(value)):
            return v
    return args.get("default")


def lower(value, args, ctx):
    return str(value).lower()


def upper(value, args, ctx):
    return str(value).upper()


def trim(value, args, ctx):
    return str(value).strip(args.get("chars")) or None


def regex_extract(value, args, ctx):
    pat = rx.compile(args["pattern"])
    m = pat.search(str(value))
    if not m:
        return None
    group = args.get("group", 1 if pat.groups else 0)
    try:
        return m.group(group)
    except (IndexError, TypeError):
        raise TransformError(f"regex_extract: the pattern has no group {group!r}") from None


def split_index(value, args, ctx):
    parts = str(value).split(args["sep"])
    i = args.get("index", 0)
    try:
        return parts[i].strip() or None
    except IndexError:
        return None


def split(value, args, ctx):
    parts = [p.strip() for p in str(value).split(args.get("sep", ","))]
    return [p for p in parts if p] or None


def null_if(value, args, ctx):
    return None if str(value).strip() in args["values"] else value


def scale(value, args, ctx):
    f = to_float(value, {}, ctx) * args["factor"]
    return int(f) if args.get("int", True) else f


def prefix(value, args, ctx):
    return f"{args.get('prefix', '')}{value}{args.get('suffix', '')}"


_WIRE = rx.compile(r"\((\d{1,2})\)")


def dns_name(value, args, ctx):
    """Windows DNS debug-log question name `(3)www(7)example(3)com(0)` -> `www.example.com`."""
    s = str(value).strip()
    if "(" not in s:
        return s.rstrip(".") or None
    labels = [p for p in _WIRE.split(s)[2::2] if p]
    return ".".join(labels) or None


def syslog_severity(value, args, ctx):
    """Syslog PRI or severity number (0-7) -> OCSF severity_id."""
    n = to_int(value, {}, ctx)
    sev = n % 8 if args.get("from_pri", n > 7) else n
    return {0: 6, 1: 5, 2: 5, 3: 4, 4: 3, 5: 2, 6: 1, 7: 1}.get(sev, 0)


FUNCS = {
    "parse_timestamp": (parse_timestamp, {"formats": list, "tz": str, "unit": str, "year": int}, []),
    "to_int": (to_int, {"base": (int, str), "allow_commas": bool}, []),
    "to_float": (to_float, {}, []),
    "to_bool": (to_bool, {}, []),
    "to_str": (to_str, {}, []),
    "enum_lookup": (enum_lookup, {"map": dict, "default": object, "case_insensitive": bool, "patterns": dict}, []),
    "lower": (lower, {}, []),
    "upper": (upper, {}, []),
    "trim": (trim, {"chars": str}, []),
    "regex_extract": (regex_extract, {"pattern": str, "group": (int, str)}, ["pattern"]),
    "split_index": (split_index, {"sep": str, "index": int}, ["sep"]),
    "split": (split, {"sep": str}, []),
    "null_if": (null_if, {"values": list}, ["values"]),
    "scale": (scale, {"factor": (int, float), "int": bool}, ["factor"]),
    "prefix": (prefix, {"prefix": str, "suffix": str}, []),
    "syslog_severity": (syslog_severity, {"from_pri": bool}, []),
    "dns_name": (dns_name, {}, []),
}


def check(fn: str, args: dict) -> str | None:
    if fn not in FUNCS:
        return f"unknown transform `{fn}`; the library is: {', '.join(sorted(FUNCS))}"
    _, allowed, required = FUNCS[fn]
    for k, v in args.items():
        if k not in allowed:
            return f"transform {fn}: unknown argument `{k}`"
        if allowed[k] is not object and not isinstance(v, allowed[k]):
            return f"transform {fn}: argument `{k}` has the wrong type"
    for k in required:
        if k not in args:
            return f"transform {fn}: missing argument `{k}`"
    for k in ("pattern",):
        if k in args and rx.check(args[k]):
            return f"transform {fn}: {rx.check(args[k])}"
    for pat in (args.get("patterns") or {}) if fn == "enum_lookup" else ():
        if rx.check(pat):
            return f"transform {fn}: {rx.check(pat)}"
    if fn == "parse_timestamp":
        if args.get("unit") not in (None, "s", "ms", "us", "ns"):
            return "parse_timestamp: unit must be s, ms, us or ns"
        if args.get("tz"):
            try:
                _tz(args["tz"], {})
            except TransformError as exc:
                return str(exc)
    return None


def apply(steps, value, ctx: dict):
    """Run one transform or a chain. Raises TransformError on bad input."""
    if isinstance(steps, dict):
        steps = [steps]
    for st in steps or []:
        if value is None:
            return None
        if isinstance(value, list) and st["fn"] not in ("split",):
            value = [FUNCS[st["fn"]][0](v, st.get("args") or {}, ctx) for v in value]
            value = [v for v in value if v is not None] or None
        else:
            value = FUNCS[st["fn"]][0](value, st.get("args") or {}, ctx)
    return value
