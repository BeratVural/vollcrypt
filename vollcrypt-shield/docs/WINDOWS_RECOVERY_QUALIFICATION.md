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
