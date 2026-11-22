#!/bin/sh
# Local MySQL 8.4 for tests: 127.0.0.1:13306, data in work/mysql, never a system service.
#   scripts/mysql.sh start | stop | status
# The root user has no password and listens on 127.0.0.1 only (test data, this machine).
set -e
ROOT=$(cd "$(dirname "$0")/.." && pwd)
BIN=/opt/homebrew/opt/mysql@8.4/bin
DIR="$ROOT/work/mysql"
PORT=13306
PID="$DIR/mysqld.pid"

running() { [ -f "$PID" ] && kill -0 "$(cat "$PID")" 2>/dev/null; }

case "$1" in
  start)
    if running; then echo "up"; exit 0; fi
    mkdir -p "$DIR"
    if [ ! -d "$DIR/data/mysql" ]; then
      "$BIN/mysqld" --no-defaults --initialize-insecure --datadir="$DIR/data" >"$DIR/init.log" 2>&1
    fi
    "$BIN/mysqld" --no-defaults --datadir="$DIR/data" --port=$PORT --bind-address=127.0.0.1 \
      --socket="$DIR/mysql.sock" --mysqlx=OFF --pid-file="$PID" --log-error="$DIR/error.log" \
      --innodb-buffer-pool-size=128M --performance-schema=OFF --max-connections=60 \
      --character-set-server=utf8mb4 --collation-server=utf8mb4_bin >/dev/null 2>&1 &
    for i in $(seq 1 60); do
      if "$BIN/mysqladmin" --no-defaults -h127.0.0.1 -P$PORT -uroot ping >/dev/null 2>&1; then echo "up"; exit 0; fi
      sleep 1
    done
    echo "mysqld did not start; see $DIR/error.log"; exit 1 ;;
  stop)
    if running; then kill "$(cat "$PID")"; for i in $(seq 1 30); do running || break; sleep 1; done; fi
    echo "down" ;;
  status)
    if running; then echo "up"; else echo "down"; fi ;;
  *) echo "usage: $0 start|stop|status"; exit 2 ;;
esac
