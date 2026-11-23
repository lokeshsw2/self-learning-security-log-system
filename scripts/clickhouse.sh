#!/bin/sh
# Local ClickHouse for development: HTTP 127.0.0.1:8123, native 9000, data in work/clickhouse.
#   scripts/clickhouse.sh start | stop | status
set -e
ROOT=$(cd "$(dirname "$0")/.." && pwd)
DIR="$ROOT/work/clickhouse"
BIN="${LP_CLICKHOUSE_BIN:-clickhouse}"

up() { curl -s --max-time 2 "http://127.0.0.1:8123/ping" >/dev/null 2>&1; }

case "$1" in
  start)
    if up; then echo "up"; exit 0; fi
    mkdir -p "$DIR/data" "$DIR/tmp" "$DIR/user_files"
    cd "$DIR"
    nohup "$BIN" server -- --path="$DIR/data/" --tmp_path="$DIR/tmp/" --user_files_path="$DIR/user_files/" \
      --logger.log="$DIR/server.log" --logger.errorlog="$DIR/err.log" --http_port=8123 --tcp_port=9000 \
      --listen_host=127.0.0.1 --mysql_port=0 --postgresql_port=0 --interserver_http_port=0 >"$DIR/out.log" 2>&1 &
    echo $! > "$DIR/clickhouse.pid"
    for i in $(seq 1 60); do if up; then echo "up"; exit 0; fi; sleep 1; done
    echo "ClickHouse did not start; see $DIR/err.log"; exit 1 ;;
  stop)
    if [ -f "$DIR/clickhouse.pid" ] && kill -0 "$(cat "$DIR/clickhouse.pid")" 2>/dev/null; then
      kill "$(cat "$DIR/clickhouse.pid")"
      for i in $(seq 1 30); do up || break; sleep 1; done
    fi
    if up; then echo "still up (started outside this script?)"; else echo "down"; fi ;;
  status)
    if up; then echo "up"; else echo "down"; fi ;;
  *) echo "usage: $0 start|stop|status"; exit 2 ;;
esac
