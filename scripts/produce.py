"""Push log files into a Kafka topic as one mixed stream (no vendor label), for testing the service.

  python scripts/produce.py --topic logs.unparsed --every 50 "path/to/logs"/*.log
  --every N sends every Nth line of each file; --limit caps lines per file; lines are interleaved.
"""
import argparse
import itertools
import os
import sys

from confluent_kafka import Producer


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("files", nargs="+")
    ap.add_argument("--bootstrap", default="127.0.0.1:19092")
    ap.add_argument("--topic", default="logs.unparsed")
    ap.add_argument("--every", type=int, default=1)
    ap.add_argument("--limit", type=int, default=0)
    a = ap.parse_args()

    def lines(path):
        n = 0
        with open(path, "rb") as fh:
            for i, line in enumerate(fh):
                if i % a.every:
                    continue
                line = line.rstrip(b"\r\n")
                if line.strip():
                    yield line
                    n += 1
                    if a.limit and n >= a.limit:
                        return
    p = Producer({"bootstrap.servers": a.bootstrap, "linger.ms": 50, "compression.type": "lz4"})
    failed = []

    def report(err, msg):
        if err is not None:
            failed.append(str(err))
    gens = [lines(f) for f in a.files]
    sent = 0
    for batch in itertools.zip_longest(*gens):            # interleave: a mixed stream, like production
        for line in batch:
            if line is None:
                continue
            while True:
                try:
                    p.produce(a.topic, line, on_delivery=report)
                    break
                except BufferError:
                    p.poll(0.5)
            sent += 1
        p.poll(0)
    left = p.flush(60)
    print(f"sent {sent} lines from {len(a.files)} files to {a.topic}; undelivered {left + len(failed)}",
          file=sys.stderr)
    if left or failed:
        print("errors:", failed[:5], file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
