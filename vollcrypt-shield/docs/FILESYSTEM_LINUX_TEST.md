# Shield Filesystem Linux Validation

Run this validation on each release-gated Ubuntu version from the repository
root. Use a disposable non-system directory. Do not point active response at
`/etc`, `/usr`, `/var/lib`, or another protected system path.

## Build and tests

```console
cargo test --locked -p vollcrypt-shield-core -p vollcrypt-shield-protocol -p vollcrypt-shield-fs -p vollcrypt-shield-cli
cargo clippy --locked -p vollcrypt-shield-fs -p vollcrypt-shield-cli --all-targets -- -D warnings
cargo build --locked --release -p vollcrypt-shield-cli
```

## Local end-to-end smoke test

```console
set -eu
ROOT=$(mktemp -d /tmp/shield-root.XXXXXX)
STATE=$(mktemp -d /tmp/shield-state.XXXXXX)
rm -rf "$STATE"
CONFIG=$(mktemp /tmp/shield-config.XXXXXX.toml)
rm -f "$CONFIG"
BREAK_GLASS=$(mktemp /tmp/shield-break-glass.XXXXXX.seed)
rm -f "$BREAK_GLASS"

printf 'approved\n' > "$ROOT/app.conf"
target/release/vollcrypt-shield monitor-folder --root "$ROOT" --state-dir "$STATE" --config "$CONFIG" --break-glass-key "$BREAK_GLASS"
target/release/vollcrypt-shield verify --config "$CONFIG" --scope default
target/release/vollcrypt-shield dashboard --config "$CONFIG" --scope default --once --no-color

printf 'changed\n' > "$ROOT/app.conf"
if target/release/vollcrypt-shield verify --config "$CONFIG" --scope default; then
  echo 'ERROR: changed content was accepted' >&2
  exit 1
fi
test "$(cat "$ROOT/app.conf")" = changed
target/release/vollcrypt-shield status --config "$CONFIG" --scope default
target/release/vollcrypt-shield audit-verify --config "$CONFIG"
```

The failed verification must report `match: false` and must not alter the
changed file because generated policies begin in mandatory dry-run mode. The
dashboard must render once without terminal control sequences. Preserve the
command output with the release evidence, then remove the disposable paths and
move the break-glass seed to an offline location or destroy it securely.

Before cleanup, run the interactive interface:

```console
target/release/vollcrypt-shield tui --config "$CONFIG" --scope default --no-color
```

Confirm that all six views open, the terminal remains responsive while
`VERIFYING` is shown, and resize works down to 48 x 12. The Files view must
show the changed file's absolute path. Press Enter on the text difference and
confirm that the digest-verified unified comparison opens. Quit with `q`; the
interface must not modify the changed file or any policy state.

## Watcher check

Run `watch` in one terminal and modify a regular file in the disposable root
from another terminal. Confirm that `status`, `dashboard`, the signed audit
chain, and `notifications.jsonl` reflect the event. Stop the watcher normally.
Filesystem notifications are hints; the periodic full rescan remains required.

Run this check in an unrestricted user session. Some CI, container, and coding
agent sandboxes deny Unix-domain socket operations with `EPERM`. In that case,
record the watcher check as blocked by the environment and repeat it outside the
sandbox; do not classify it as a Shield product failure. `status` and
`dashboard` may use the signed persisted state when live IPC is unavailable and
print an explicit warning to standard error.

## Automated Debian qualification

The pinned Debian 13 CI image runs the same watcher over a real inotify/Unix
socket path and installs a disposable `.deb` built from the release CLI:

```console
bash vollcrypt-shield/scripts/linux-qualification.sh \
  target/release/vollcrypt-shield debian13
```

The command must observe a dry-run notification, verify the signed audit chain,
prove live local-status IPC without persisted-state fallback, install and
execute the package, and uninstall it cleanly. A container or runner that
blocks inotify, Unix sockets, or package installation is not promotion
evidence.
