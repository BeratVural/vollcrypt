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
PACKAGE_NAME="vollcrypt-shield-cli-${PACKAGE_SUFFIX}"
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
  ARCH=$(dpkg --print-architecture)
  PACKAGE_ROOT="$WORK/package"
  mkdir -p "$PACKAGE_ROOT/DEBIAN" "$PACKAGE_ROOT/usr/bin"
  install -m 0755 "$BINARY" "$PACKAGE_ROOT/usr/bin/vollcrypt-shield"
  cat > "$PACKAGE_ROOT/DEBIAN/control" <<EOF
Package: $PACKAGE_NAME
Version: 1.0.0
Architecture: $ARCH
Maintainer: Vollcrypt <security@vollcrypt.dev>
Description: Vollcrypt Shield filesystem integrity agent and CLI qualification package
EOF
  dpkg-deb --root-owner-group --build "$PACKAGE_ROOT" "$WORK/$PACKAGE_NAME.deb"
  dpkg-deb --info "$WORK/$PACKAGE_NAME.deb"
  dpkg --install "$WORK/$PACKAGE_NAME.deb"
  PACKAGE_INSTALLED=1
  /usr/bin/vollcrypt-shield --help >/dev/null
  dpkg --remove "$PACKAGE_NAME"
  PACKAGE_INSTALLED=0
else
  RPM_ROOT="$WORK/rpmbuild"
  mkdir -p "$RPM_ROOT/BUILD" "$RPM_ROOT/BUILDROOT" "$RPM_ROOT/RPMS" "$RPM_ROOT/SOURCES" "$RPM_ROOT/SPECS" "$RPM_ROOT/SRPMS"
  install -m 0755 "$BINARY" "$RPM_ROOT/SOURCES/vollcrypt-shield"
  cat > "$RPM_ROOT/SPECS/vollcrypt-shield.spec" <<EOF
Name: $PACKAGE_NAME
Version: 1.0.0
Release: 1
Summary: Vollcrypt Shield filesystem integrity agent and CLI qualification package
License: GPL-3.0-only OR LicenseRef-Commercial
Source0: vollcrypt-shield

%description
Vollcrypt Shield filesystem integrity agent and CLI qualification package.

%install
mkdir -p %{buildroot}/usr/bin
install -m 0755 %{SOURCE0} %{buildroot}/usr/bin/vollcrypt-shield

%files
/usr/bin/vollcrypt-shield
EOF
  rpmbuild --define "_topdir $RPM_ROOT" -bb "$RPM_ROOT/SPECS/vollcrypt-shield.spec"
  RPM_PACKAGE=$(find "$RPM_ROOT/RPMS" -type f -name '*.rpm' -print -quit)
  test -n "$RPM_PACKAGE"
  rpm --checksig "$RPM_PACKAGE"
  rpm --install "$RPM_PACKAGE"
  PACKAGE_INSTALLED=1
  /usr/bin/vollcrypt-shield --help >/dev/null
  rpm --erase "$PACKAGE_NAME"
  PACKAGE_INSTALLED=0
fi

echo "Shield Linux qualification passed: watcher, IPC, audit, and $PACKAGE_FORMAT package smoke"
