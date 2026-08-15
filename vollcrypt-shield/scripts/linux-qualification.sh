#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -lt 2 ] || [ "$#" -gt 3 ]; then
  echo "usage: $0 <release-binary> <package-suffix> [deb|rpm]" >&2
  exit 64
fi

BINARY=$(realpath "$1")
PACKAGE_SUFFIX=$2
PACKAGE_FORMAT=deb
if [ "$#" -eq 3 ]; then
  PACKAGE_FORMAT=$3
fi
case "$PACKAGE_FORMAT" in
  deb|rpm) ;;
  *) echo "package format must be deb or rpm" >&2; exit 64 ;;
esac
test -x "$BINARY"

WORK=$(mktemp -d /tmp/vollcrypt-shield-qualification.XXXXXX)
ROOT="$WORK/scope"
STATE="$WORK/state"
CONFIG="$WORK/agent.toml"
BREAK_GLASS="$WORK/break-glass.seed"
WATCH_LOG="$WORK/watch.log"
WATCH_PID=
PACKAGE_NAME="vollcrypt-shield"
PACKAGE_INSTALLED=0

cleanup() {
  if [ -n "$WATCH_PID" ]; then
    kill "$WATCH_PID" 2>/dev/null || true
    wait "$WATCH_PID" 2>/dev/null || true
  fi
  if [ "$PACKAGE_INSTALLED" -eq 1 ]; then
    if [ "$PACKAGE_FORMAT" = deb ]; then
      dpkg --remove "$PACKAGE_NAME" >/dev/null 2>&1 || true
    else
      rpm --erase "$PACKAGE_NAME" >/dev/null 2>&1 || true
    fi
  fi
  rm -rf -- "$WORK"
}
trap cleanup EXIT INT TERM

mkdir -p "$ROOT"
printf 'approved\n' > "$ROOT/app.conf"
"$BINARY" monitor-folder \
  --root "$ROOT" \
  --state-dir "$STATE" \
  --config "$CONFIG" \
  --break-glass-key "$BREAK_GLASS"
"$BINARY" verify --config "$CONFIG" --scope default

"$BINARY" watch --config "$CONFIG" --scope default >"$WATCH_LOG" 2>&1 &
WATCH_PID=$!
for _ in $(seq 1 100); do
  test -S "$STATE/ipc/status.sock" && break
  kill -0 "$WATCH_PID"
  sleep 0.1
done
test -S "$STATE/ipc/status.sock"

"$BINARY" status --config "$CONFIG" --scope default \
  > "$WORK/status-before.json" 2> "$WORK/status-before.err"
test ! -s "$WORK/status-before.err"
grep -q '"scope": "default"' "$WORK/status-before.json"
grep -q '"contained": false' "$WORK/status-before.json"
printf 'changed\n' > "$ROOT/app.conf"
for _ in $(seq 1 100); do
  if test -f "$STATE/notifications.jsonl" \
    && grep -q '"kind":"dry-run-response"' "$STATE/notifications.jsonl"; then
    break
  fi
  kill -0 "$WATCH_PID"
  sleep 0.1
done
grep -q '"kind":"dry-run-response"' "$STATE/notifications.jsonl"
test "$(cat "$ROOT/app.conf")" = changed
"$BINARY" status --config "$CONFIG" --scope default \
  > "$WORK/status-after.json" 2> "$WORK/status-after.err"
test ! -s "$WORK/status-after.err"
grep -q '"scope": "default"' "$WORK/status-after.json"
grep -q '"contained": false' "$WORK/status-after.json"
"$BINARY" audit-verify --config "$CONFIG"

kill "$WATCH_PID"
wait "$WATCH_PID" || true
WATCH_PID=

if [ "$PACKAGE_FORMAT" = deb ]; then
  PACKAGE=$(bash "$(dirname "$0")/build-linux-package.sh" "$BINARY" "$WORK/packages" deb | tail -n 1)
  dpkg-deb --info "$PACKAGE"
  dpkg --install "$PACKAGE"
  PACKAGE_INSTALLED=1
  systemd-analyze verify /usr/lib/systemd/system/vollcrypt-shield@.service
  id vollcrypt-shield >/dev/null
  test "$(stat -c %a /var/lib/vollcrypt-shield)" = 700
  /usr/bin/vollcrypt-shield --version | grep -q '1.0.0'
  dpkg --remove "$PACKAGE_NAME"
  PACKAGE_INSTALLED=0
else
  PACKAGE=$(bash "$(dirname "$0")/build-linux-package.sh" "$BINARY" "$WORK/packages" rpm | tail -n 1)
  rpm --checksig "$PACKAGE"
  rpm --install "$PACKAGE"
  PACKAGE_INSTALLED=1
  systemd-analyze verify /usr/lib/systemd/system/vollcrypt-shield@.service
  id vollcrypt-shield >/dev/null
  test "$(stat -c %a /var/lib/vollcrypt-shield)" = 700
  /usr/bin/vollcrypt-shield --version | grep -q '1.0.0'
  rpm --erase "$PACKAGE_NAME"
  PACKAGE_INSTALLED=0
fi

echo "Shield Linux qualification passed: watcher, IPC, audit, and $PACKAGE_FORMAT package smoke"
