#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -lt 1 ] || [ "$#" -gt 3 ]; then
  echo "usage: $0 <release-binary> [duration-seconds] [max-rss-growth-kib]" >&2
  exit 64
fi

BINARY=$(realpath "$1")
DURATION=${2:-300}
MAX_RSS_GROWTH_KIB=${3:-65536}
case "$DURATION:$MAX_RSS_GROWTH_KIB" in
  *[!0-9:]*|:*|*:) echo "duration and RSS growth limit must be positive integers" >&2; exit 64 ;;
esac
if [ "$DURATION" -lt 30 ] || [ "$MAX_RSS_GROWTH_KIB" -lt 1024 ]; then
  echo "duration must be at least 30 seconds and RSS growth limit at least 1024 KiB" >&2
  exit 64
fi
test -x "$BINARY"

WORK=$(mktemp -d /tmp/vollcrypt-shield-soak.XXXXXX)
ROOT="$WORK/scope"
STATE="$WORK/state"
CONFIG="$WORK/agent.toml"
BREAK_GLASS="$WORK/break-glass.seed"
WATCH_LOG="$WORK/watch.log"
WATCH_PID=

cleanup() {
  if [ -n "$WATCH_PID" ]; then
    kill "$WATCH_PID" 2>/dev/null || true
    wait "$WATCH_PID" 2>/dev/null || true
  fi
  rm -rf -- "$WORK"
}
report_error() {
  status=$?
  echo "watcher soak failed at line $1 with status $status" >&2
  if [ -n "$WATCH_PID" ] && kill -0 "$WATCH_PID" 2>/dev/null; then
    echo "watcher process is still running" >&2
    awk '/^(VmRSS|VmPeak|Threads):/ { print }' "/proc/$WATCH_PID/status" >&2 || true
    echo "open file descriptors: $(find "/proc/$WATCH_PID/fd" -mindepth 1 -maxdepth 1 2>/dev/null | wc -l)" >&2
  else
    echo "watcher process is not running" >&2
  fi
  test -f "$WATCH_LOG" && tail -n 40 "$WATCH_LOG" >&2 || true
  test -f "$WORK/status.err" && cat "$WORK/status.err" >&2 || true
  exit "$status"
}
trap 'report_error $LINENO' ERR
trap cleanup EXIT INT TERM

mkdir -p "$ROOT"
printf 'approved-0\n' > "$ROOT/app.conf"
"$BINARY" monitor-folder --root "$ROOT" --state-dir "$STATE" --config "$CONFIG" --break-glass-key "$BREAK_GLASS" >/dev/null
"$BINARY" watch --config "$CONFIG" --scope default >"$WATCH_LOG" 2>&1 &
WATCH_PID=$!

for _ in $(seq 1 100); do
  test -S "$STATE/ipc/status.sock" && break
  kill -0 "$WATCH_PID"
  sleep 0.1
done
test -S "$STATE/ipc/status.sock"

read_rss() {
  awk '/^VmRSS:/ { print $2; found=1 } END { if (!found) print 0 }' "/proc/$WATCH_PID/status"
}

# Exclude one-time scanner and crypto allocations from leak measurements.
printf 'warmup\n' > "$ROOT/app.conf"
for _ in $(seq 1 100); do
  if test -f "$STATE/notifications.jsonl" && grep -q '"kind":"dry-run-response"' "$STATE/notifications.jsonl"; then
    break
  fi
  kill -0 "$WATCH_PID"
  sleep 0.1
done
grep -q '"kind":"dry-run-response"' "$STATE/notifications.jsonl"
"$BINARY" status --config "$CONFIG" --scope default >"$WORK/status.json" 2>"$WORK/status.err"
test ! -s "$WORK/status.err"
sleep 1

BASELINE_RSS=$(read_rss)
BASELINE_FDS=$(find "/proc/$WATCH_PID/fd" -mindepth 1 -maxdepth 1 | wc -l)
PEAK_RSS=$BASELINE_RSS
PEAK_FDS=$BASELINE_FDS
EVENTS=0
DEADLINE=$((SECONDS + DURATION))

while [ "$SECONDS" -lt "$DEADLINE" ]; do
  BEFORE=0
  if [ -f "$STATE/notifications.jsonl" ]; then
    BEFORE=$(wc -l < "$STATE/notifications.jsonl")
  fi
  EVENTS=$((EVENTS + 1))
  printf 'changed-%s\n' "$EVENTS" > "$ROOT/app.conf"
  for _ in $(seq 1 100); do
    CURRENT=0
    if [ -f "$STATE/notifications.jsonl" ]; then
      CURRENT=$(wc -l < "$STATE/notifications.jsonl")
    fi
    [ "$CURRENT" -gt "$BEFORE" ] && break
    kill -0 "$WATCH_PID"
    sleep 0.1
  done
  [ "$CURRENT" -gt "$BEFORE" ]
  "$BINARY" status --config "$CONFIG" --scope default >"$WORK/status.json" 2>"$WORK/status.err"
  test ! -s "$WORK/status.err"

  RSS=$(read_rss)
  FDS=$(find "/proc/$WATCH_PID/fd" -mindepth 1 -maxdepth 1 | wc -l)
  [ "$RSS" -gt "$PEAK_RSS" ] && PEAK_RSS=$RSS
  [ "$FDS" -gt "$PEAK_FDS" ] && PEAK_FDS=$FDS
  [ "$((PEAK_RSS - BASELINE_RSS))" -le "$MAX_RSS_GROWTH_KIB" ]
  [ "$((PEAK_FDS - BASELINE_FDS))" -le 8 ]
  sleep 0.2
done

[ "$EVENTS" -ge 10 ]
TOTAL=$(wc -l < "$STATE/notifications.jsonl")
[ "$TOTAL" -ge "$EVENTS" ]
[ "$(grep -c '"kind":"dry-run-response"' "$STATE/notifications.jsonl")" -eq "$TOTAL" ]
[ "$(grep -c '"scope_id":"default"' "$STATE/notifications.jsonl")" -eq "$TOTAL" ]
"$BINARY" audit-verify --config "$CONFIG" >/dev/null
kill "$WATCH_PID"
wait "$WATCH_PID" || true
WATCH_PID=

printf '{"status":"passed","durationSeconds":%s,"events":%s,"baselineRssKiB":%s,"peakRssKiB":%s,"baselineFds":%s,"peakFds":%s}\n' "$DURATION" "$EVENTS" "$BASELINE_RSS" "$PEAK_RSS" "$BASELINE_FDS" "$PEAK_FDS"
