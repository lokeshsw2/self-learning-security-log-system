#!/bin/sh
# Local Logstash for the learning service: ./scripts/logstash.sh start|stop|status [settings dir]
# It runs the deployed pipelines (written by the service into the settings dir) and reloads them on change.
set -e
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIR="${2:-$ROOT/work/service/logstash}"
PID="$DIR/logstash.pid"
case "$1" in
  start)
    [ -f "$DIR/pipelines.yml" ] || { echo "no pipelines deployed in $DIR yet"; exit 1; }
    nohup /opt/homebrew/bin/logstash --path.settings "$DIR" > "$DIR/stdout.log" 2>&1 &
    echo $! > "$PID"; echo "starting (log: $DIR/stdout.log)";;
  stop)
    [ -f "$PID" ] && { kill "$(cat "$PID")" 2>/dev/null || true; rm -f "$PID"; }
    pkill -f "path.settings $DIR" 2>/dev/null || true;;
  status)
    if [ -f "$PID" ] && kill -0 "$(cat "$PID")" 2>/dev/null; then echo up; else echo down; fi;;
  *) echo "usage: $0 start|stop|status [settings dir]"; exit 1;;
esac
