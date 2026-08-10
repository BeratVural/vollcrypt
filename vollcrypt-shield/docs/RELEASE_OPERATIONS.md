# Release Operations Evidence

Shield release qualification includes named drills for persistent state and
emergency recovery. A release must not rely only on compilation or ordinary
unit-test totals.

## Required drills

- `release_upgrade_migration_downgrade_and_backup_restore_drill` starts from a
  valid ML-DSA-signed state schema v1, loads it with the current agent, retains
  the exact signed source as `state.v1.backup.cbor`, migrates atomically to v2,
  restores the backup, migrates it again, and rejects a signed future schema.
- `release_break_glass_recovery_drill` places one scope in containment,
  releases only that scope with a time-bounded signed command, persists the
  release, and rejects nonce replay.
- `release_backup_rollback_and_break_glass_recovery_drill` runs on Unix and
  additionally proves that a changed regular file can be quarantined and
  restored from the digest-verified baseline vault with its supported metadata.

The migration backup is not a general-purpose secret export. It contains the
previous signed state document, not agent or break-glass private keys. Operators
must still back up offline break-glass material independently.

## Downgrade rule

State schema v2 is intentionally rejected by a v1 reader. Downgrading a binary
in place is unsupported because accepting newer state with older validation
logic would weaken fail-close behavior. Restore the pre-upgrade signed backup
only as part of a documented rollback window and retain the audit trail.
