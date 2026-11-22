"""Batch reader (file and Kafka behind one interface) and record framing.

A source hands out raw byte lines with offsets. Framing joins them into
records (multiline events, octet-counted syslog) using the `framing` rule.
An unfinished record at the end of a batch is not consumed: the batch offset
stops before it, so the next batch starts with it again.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field

from . import rx


@dataclass
class Record:
    stream: str
    offset: int
    text: str = ""
    blob: bytes | None = None          # set for binary input, which is routed aside
    flags: list = field(default_factory=list)
    label: str | None = None           # source metadata (Kafka header, configured label)
    columns: dict | None = None        # replay only: the header that applied to this line


def looks_binary(data: bytes, max_nonprintable: float = 0.1) -> bool:
    if not data:
        return False
    sample = data[:4096]
    if sample[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return False  # UTF-16 text with a byte order mark
    bad = sum(1 for b in sample if b < 9 or (13 < b < 32 and b != 27) or b == 127)
    return bad / len(sample) > max_nonprintable


def decode(data: bytes) -> tuple[str, list]:
    flags = []
    if data[:3] == b"\xef\xbb\xbf":
        data = data[3:]
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        try:
            return data.decode("utf-16"), ["utf16"]
        except UnicodeDecodeError:
            pass
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        text = data.decode("latin-1")
        flags.append("latin1_fallback")
    if "\x00" in text:
        text = text.replace("\x00", "")
        flags.append("nul_stripped")
    return text, flags


class FileSource:
    """Reads a file in batches. The offset is a byte position kept in the store."""

    def __init__(self, path: str, stream: str | None = None, label: str | None = None):
        self.path = path
        self.stream = stream or os.path.basename(path)
        self.label = label

    def read(self, offset: int, max_lines: int) -> tuple[list[tuple[int, bytes]], bool]:
        """Return ([(offset, line bytes)], at_eof)."""
        out = []
        with open(self.path, "rb") as fh:
            if offset == 0:
                head = fh.read(4096)
                if looks_binary(head):
                    fh.seek(0)
                    return [(0, fh.read())], True
                fh.seek(0)
            else:
                fh.seek(offset)
            pos = offset
            while len(out) < max_lines:
                line = fh.readline()
                if not line:
                    return out, True
                if not line.endswith(b"\n"):       # last line without newline
                    out.append((pos, line))
                    return out, True
                out.append((pos, line[:-1].rstrip(b"\r")))
                pos += len(line)
            more = fh.read(1)
            return out, not more

    def end_offset(self, lines: list[tuple[int, bytes]], consumed: int, at_eof: bool) -> int:
        if consumed >= len(lines):
            return os.path.getsize(self.path) if at_eof else (lines[-1][0] + len(lines[-1][1]) + 1 if lines else 0)
        return lines[consumed][0]


class KafkaSource:
    """Kafka topic as a batch source. One message is one record candidate.

    Needs `confluent_kafka` and a broker; it is not exercised by the test suite.
    Offsets are committed by the engine only after the batch state is written.
    """

    def __init__(self, topic: str, config: dict, label_header: str = "source"):
        try:
            from confluent_kafka import Consumer  # type: ignore
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError("install confluent-kafka to read from Kafka") from exc
        cfg = dict(config)
        cfg["enable.auto.commit"] = False
        self.consumer = Consumer(cfg)
        self.consumer.subscribe([topic])
        self.stream = f"kafka:{topic}"
        self.label_header = label_header
        self.label = None
        self._last = []

    def read_messages(self, max_lines: int, timeout: float = 1.0):  # pragma: no cover
        msgs = self.consumer.consume(num_messages=max_lines, timeout=timeout)
        self._last = [m for m in msgs if m.error() is None]
        out = []
        for m in self._last:
            label = None
            for k, v in (m.headers() or []):
                if k == self.label_header and v:
                    label = v.decode("utf-8", "replace")
            out.append((m.offset(), m.value() or b"", label, f"{self.stream}:{m.partition()}"))
        return out

    def commit(self) -> None:  # pragma: no cover
        if self._last:
            self.consumer.commit(message=self._last[-1], asynchronous=False)


class Framer:
    def __init__(self, rule: dict, max_line_len: int = 65536):
        self.cont = [rx.compile(p) for p in rule.get("continuation", [])]
        self.ml_json = rule.get("multiline_json", True)
        self.ml_xml = rule.get("multiline_xml", True)
        self.octet = rule.get("octet_counting", True)
        self.max_lines = rule.get("max_record_lines", 500)
        self.max_len = max_line_len
        self._oct = rx.compile(r"^(\d{1,7}) (<\d{1,3}>.*)$")
        self._xml_open = rx.compile(r"^\s*<([A-Za-z_][\w:.\-]*)[\s>]")

    @staticmethod
    def _json_balance(text: str, depth: int, in_str: bool, esc: bool) -> tuple[int, bool, bool]:
        for ch in text:
            if in_str:
                if esc:
                    esc = False
                elif ch == "\\":
                    esc = True
                elif ch == '"':
                    in_str = False
            elif ch == '"':
                in_str = True
            elif ch in "{[":
                depth += 1
            elif ch in "}]":
                depth -= 1
        return depth, in_str, esc

    def frame(self, stream: str, lines: list[tuple[int, bytes]], at_eof: bool,
              label: str | None = None) -> tuple[list[Record], int]:
        """Return (records, number of input lines consumed)."""
        recs: list[Record] = []
        i, n = 0, len(lines)
        while i < n:
            off, data = lines[i]
            if looks_binary(data):
                recs.append(Record(stream, off, blob=data, label=label))
                i += 1
                continue
            text, flags = decode(data)
            if self.octet:
                m = self._oct.match(text)
                if m and abs(int(m.group(1)) - len(m.group(2).encode("utf-8"))) <= 2:
                    text = m.group(2)
                    flags.append("octet_counted")
            j = i + 1
            stripped = text.strip()
            if self.ml_json and stripped.startswith("{") and not stripped.endswith("}"):
                depth, in_str, esc = self._json_balance(text, 0, False, False)
                parts = [text]
                while depth > 0 and j < n and j - i < self.max_lines:
                    nxt, f2 = decode(lines[j][1])
                    depth, in_str, esc = self._json_balance(nxt, depth, in_str, esc)
                    parts.append(nxt)
                    j += 1
                if depth > 0 and j >= n and not at_eof:
                    return recs, i          # unfinished: leave for the next batch
                if depth <= 0:
                    text = "\n".join(parts)
                    if len(parts) > 1:
                        flags.append("multiline")
                else:
                    j = i + 1               # never closed: emit the first line alone
                    flags.append("truncated")
            elif self.ml_xml and stripped.startswith("<") and not stripped.startswith("<?"):
                m = self._xml_open.match(text)
                if m and f"</{m.group(1)}>" not in text and not stripped.endswith("/>") \
                        and not rx.compile(r"^<\d{1,3}>").match(stripped):
                    close = f"</{m.group(1)}>"
                    parts = [text]
                    found = False
                    while j < n and j - i < self.max_lines:
                        nxt, f2 = decode(lines[j][1])
                        parts.append(nxt)
                        j += 1
                        if close in nxt:
                            found = True
                            break
                    if not found and j >= n and not at_eof:
                        return recs, i
                    if found:
                        text = "\n".join(parts)
                        flags.append("multiline")
                    else:
                        j = i + 1
            if j == i + 1 and self.cont:
                parts = [text]
                while j < n and j - i < self.max_lines:
                    nxt, f2 = decode(lines[j][1])
                    if not any(c.search(nxt) for c in self.cont):
                        break
                    parts.append(nxt)
                    j += 1
                if j >= n and not at_eof and i > 0:
                    return recs, i          # the next batch may continue this record
                if len(parts) > 1:
                    text = "\n".join(parts)
                    flags.append("multiline")
            if len(text) > self.max_len:
                text = text[: self.max_len]
                flags.append("truncated")
            if text.strip():
                recs.append(Record(stream, off, text=text, flags=flags, label=label))
            i = j
        return recs, n
