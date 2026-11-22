#!/bin/sh
# Local single-node Kafka for testing: ./scripts/kafka.sh start|stop|status
# Heap capped at 512 MB; not a background service, so it runs only while testing.
set -e
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CONF="$ROOT/deploy/kafka/server.properties"
DATA="$ROOT/work/kafka/data"
LOG="$ROOT/work/kafka/server.log"
PID="$ROOT/work/kafka/server.pid"
BIN=/opt/homebrew/opt/kafka/bin
export KAFKA_HEAP_OPTS="-Xms256m -Xmx512m"
case "$1" in
  start)
    mkdir -p "$DATA"
    if [ ! -f "$DATA/meta.properties" ]; then
      "$BIN/kafka-storage" format --standalone -t "$("$BIN/kafka-storage" random-uuid)" -c "$CONF" >/dev/null
    fi
    nohup "$BIN/kafka-server-start" "$CONF" > "$LOG" 2>&1 &
    echo $! > "$PID"
    echo "starting (log: $LOG)";;
  stop)  # only this project's broker: other Kafka on this machine (e.g. in Docker) is left alone
    if [ -f "$PID" ]; then
      for p in $(pgrep -f "kafka.Kafka $CONF") $(cat "$PID"); do kill "$p" 2>/dev/null || true; done
      rm -f "$PID"
    else
      pkill -f "kafka.Kafka $CONF" || true
    fi;;
  status) "$BIN/kafka-broker-api-versions" --bootstrap-server 127.0.0.1:19092 >/dev/null 2>&1 && echo up || echo down;;
  *) echo "usage: $0 start|stop|status"; exit 1;;
esac
