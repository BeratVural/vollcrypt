# Windows Active-Response Recovery Qualification

This gate is mandatory before Windows active response is promoted from
qualification-only. Run it from an elevated Shield service account on each
claimed Windows release and architecture. The account must hold and enable
`SeBackupPrivilege`, `SeRestorePrivilege`, and `SeSecurityPrivilege`.

The host must provide two writable local volumes, Developer Mode or equivalent
symlink permission, and an NTFS test scope. Test data must be disposable.

```powershell
$env:VOLLCRYPT_SHIELD_WINDOWS_ACTIVE_QUALIFICATION = "1"
cargo test --locked -p vollcrypt-shield-windows -p vollcrypt-shield-fs
```

With the qualification variable set, missing privileges, unavailable reparse
point creation, a missing second writable volume, metadata loss, or a failed
capability round trip fails the test run instead of being reported as an
environment skip.

The suite covers:

- an abruptly terminated process after the durable source-to-staging move and
  signed-journal recovery on restart;
- pre-move and post-commit journal recovery;
- tampered journals, destination races, and digest mismatches;
- locked-file rejection without modifying the source;
- file and directory reparse-point rejection;
- no-clobber moves and cross-volume move rejection;
- default streams, alternate streams, owner, DACL, SACL, integrity label,
  extended attributes, timestamps, and file attributes through the existing
  active-response capability round trip.

Retain the complete test log, exact Git commit, operating-system build,
architecture, filesystem type, volume identifiers, and service-account
privilege output as release evidence. Compilation or a non-strict test run is
not qualification evidence.

The `Vollcrypt Shield Windows Recovery` workflow automates this gate weekly and
on demand for Windows Server 2022/2025 x86_64 and Windows 11 ARM64. It provisions
a disposable second NTFS volume, requires the three service-account privileges,
runs the strict suites serially, and retains the host manifest, privilege list,
test logs, and disk lifecycle logs as workflow artifacts. A failed or missing
artifact is not qualification evidence.

## Retained qualification

The current complete automated gate passed from public commit `183def5` in
workflow run `31874458044` on all three claimed targets. GitHub retains one
artifact per target containing `host.json`, `privileges.json`, strict test
logs, the transcript, and disposable-disk lifecycle logs. The run includes the
ARM64-safe NTFS timestamp handling that still rejects creation-time,
last-write-time, or attribute drift and restores all signed basic metadata
after `BackupRead`. A release must run the gate again for its own commit; this
historical result does not replace that gate.
