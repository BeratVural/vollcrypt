#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 3 ]; then
  echo "usage: $0 <expected-os-id> <expected-version-prefix> <evidence-file>" >&2
  exit 64
fi

EXPECTED_ID=$1
EXPECTED_VERSION=$2
EVIDENCE=$3
source /etc/os-release
test "${ID:-}" = "$EXPECTED_ID"
case "${VERSION_ID:-}" in
  "$EXPECTED_VERSION"*) ;;
  *) echo "expected $EXPECTED_ID $EXPECTED_VERSION, found ${VERSION_ID:-unknown}" >&2; exit 65 ;;
esac
test "$(cat /proc/1/comm)" = systemd
systemctl is-system-running --wait >/dev/null || test "$(systemctl is-system-running)" = degraded

ROOT=/srv/vollcrypt-shield-qualification
STATE=/var/lib/vollcrypt-shield/default-state
STAGED_CONFIG=/var/lib/vollcrypt-shield/default.toml
CONFIG=/etc/vollcrypt-shield/default.toml
BREAK_GLASS=/var/lib/vollcrypt-shield/default-break-glass.seed
PACKAGE_DIR=/root/vollcrypt-shield-package
PACKAGE_INSTALLED=0
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd -- "$SCRIPT_DIR/../.." && pwd)

cleanup() {
  systemctl disable --now vollcrypt-shield@default.service >/dev/null 2>&1 || true
  if [ "$PACKAGE_INSTALLED" -eq 1 ]; then
    dnf remove -y vollcrypt-shield >/dev/null 2>&1 || true
  fi
  rm -rf -- "$ROOT" "$STATE" "$PACKAGE_DIR"
  rm -f -- "$STAGED_CONFIG" "$CONFIG" "$BREAK_GLASS" "$BREAK_GLASS.public"
}
trap cleanup EXIT INT TERM

cd "$REPO_ROOT"
cargo test --locked -p vollcrypt-shield-core -p vollcrypt-shield-protocol -p vollcrypt-shield-fs -p vollcrypt-shield-cli
cargo build --locked --release -p vollcrypt-shield-cli
bash vollcrypt-shield/scripts/linux-qualification.sh target/release/vollcrypt-shield vm rpm
bash vollcrypt-shield/scripts/build-linux-package.sh target/release/vollcrypt-shield "$PACKAGE_DIR" rpm
PACKAGE=$(find "$PACKAGE_DIR" -maxdepth 1 -type f -name '*.rpm' -print -quit)
test -n "$PACKAGE"
PACKAGE_SHA256=$(sha256sum "$PACKAGE" | awk '{print $1}')
dnf install -y "$PACKAGE"
PACKAGE_INSTALLED=1

install -d -o vollcrypt-shield -g vollcrypt-shield -m 0750 "$ROOT"
printf 'approved\n' > "$ROOT/app.conf"
chown vollcrypt-shield:vollcrypt-shield "$ROOT/app.conf"
runuser -u vollcrypt-shield -- vollcrypt-shield monitor-folder \
  --root "$ROOT" \
  --state-dir "$STATE" \
  --config "$STAGED_CONFIG" \
  --break-glass-key "$BREAK_GLASS"
install -o root -g vollcrypt-shield -m 0640 "$STAGED_CONFIG" "$CONFIG"
systemctl enable --now vollcrypt-shield@default.service

for _ in $(seq 1 100); do
  systemctl is-active --quiet vollcrypt-shield@default.service || {
    journalctl -u vollcrypt-shield@default.service --no-pager >&2
    exit 1
  }
  test -S "$STATE/ipc/status.sock" && break
  sleep 0.1
done
test -S "$STATE/ipc/status.sock"
printf 'changed\n' > "$ROOT/app.conf"
for _ in $(seq 1 100); do
  if test -f "$STATE/notifications.jsonl" && grep -q '"kind":"dry-run-response"' "$STATE/notifications.jsonl"; then
    break
  fi
  systemctl is-active --quiet vollcrypt-shield@default.service
  sleep 0.1
done
grep -q '"kind":"dry-run-response"' "$STATE/notifications.jsonl"
test "$(cat "$ROOT/app.conf")" = changed
runuser -u vollcrypt-shield -- vollcrypt-shield audit-verify --config "$CONFIG" >/dev/null
systemctl is-active --quiet vollcrypt-shield@default.service

mkdir -p "$(dirname "$EVIDENCE")"
EVIDENCE_DIR=$(dirname "$EVIDENCE")
systemd-analyze security vollcrypt-shield@default.service > "$EVIDENCE_DIR/systemd-security.txt" || true
journalctl -u vollcrypt-shield@default.service --no-pager > "$EVIDENCE_DIR/service-journal.txt"
cat > "$EVIDENCE" <<EOF
{
  "status": "passed",
  "osId": "$ID",
  "osVersion": "$VERSION_ID",
  "kernel": "$(uname -r)",
  "architecture": "$(uname -m)",
  "init": "$(cat /proc/1/comm)",
  "packageSha256": "$PACKAGE_SHA256",
  "service": "$(systemctl is-active vollcrypt-shield@default.service)",
  "policyMode": "dry-run"
}
EOF
