# Vollcrypt Shield Protocol v1

This directory defines the language-independent wire contract implemented by
`shield-core` and `vollcrypt-shield-protocol`. Protocol payloads use
deterministic CBOR arrays. Decoders must
reject trailing bytes, unknown format versions, unsupported algorithm IDs,
wrong fixed-length fields, unsorted snapshot entries, and duplicate paths.

## Identifiers

- format version: `1`
- hash algorithm `1`: SHA-256
- signature algorithm `1`: ML-DSA-65
- entry kind: file `1`, directory `2`, symlink `3`
- break-glass action: release scope containment `1`

ML-DSA-65 public keys are 1952 bytes, signatures are 3309 bytes, secret seeds
are 32 bytes, and all SHA-256 digests and key IDs are 32 bytes.

Protocol signatures use the ML-DSA context parameter. The v1 contexts are
`Vollcrypt Shield Snapshot v1`, `Vollcrypt Shield Audit v1`,
`Vollcrypt Shield Break Glass v1`, `Vollcrypt Shield Agent State v1`,
`Vollcrypt Shield Vault v1`, and `Vollcrypt Shield Quarantine v1`. A signature
verified under any other context must fail.

Witness statements use the additional context
`Vollcrypt Shield Witness v1`.

## Signed snapshot

`Snapshot` is the seven-element array:

```text
[version, hash_algorithm, signature_algorithm, scope_id,
 created_at_unix_ms, merkle_root, entries]
```

Each `IntegrityEntry` is:

```text
[[normalized_relative_path], entry_kind, content_digest, metadata_digest, size]
```

Entries are strictly sorted by normalized path before encoding. A
`SignedSnapshot` is `[snapshot_cbor, public_key, signature]`; the signature is
over the exact snapshot CBOR bytes.

## Audit chain

An `AuditEvent` is:

```text
[version, sequence, timestamp_unix_ms, scope_id, event_kind,
 optional_path, detail, previous_event_hash]
```

A signed record is `[event_cbor, event_hash, public_key, signature]`.
`event_hash` is SHA-256 over the domain string
`VOLLCRYPT-SHIELD-AUDIT-v1\0`, the eight-byte big-endian event length, and the
exact event CBOR. The ML-DSA-65 signature covers `event_hash`. Sequence starts
at zero; the first previous hash is all zeroes and every later record names the
preceding record's event hash.

## Break-glass

The command payload is:

```text
[version, scope_id, nonce, issued_at_unix_ms, expires_at_unix_ms, action]
```

The signed wrapper is `[command_cbor, signer_key_id, signature]`. A verifier
must require the configured offline public key, the exact contained scope, a
previously unused 32-byte nonce, and a current time within a validity window of
at most 24 hours.

## Path and Merkle rules

Protocol paths are non-empty UTF-8 relative paths separated by `/`. Absolute
paths, backslashes, drive prefixes, NUL, empty components, `.` and `..` are
invalid. Leaf keys and values use separate v1 domain separators. Sparse Merkle
internal nodes use `VOLLCRYPT-SHIELD-NODE-v1\0`; missing leaves use
`VOLLCRYPT-SHIELD-EMPTY-LEAF-v1\0`. Implementations must not substitute the
encrypted chunk Merkle format from `vollcrypt-files`.

## SPAKE2 pairing

Pairing uses the stable RustCrypto `spake2` implementation with Ed25519 group
parameters. The agent is role B and the Viewer is role A. A generated one-time
code contains 80 random bits and is displayed as five groups of four
hexadecimal characters. Sessions must expire between 30 and 600 seconds.

`PairingHello` is:

```text
[version, session_id, agent_key_id, role, issued_at_unix_ms,
 expires_at_unix_ms, spake2_message]
```

The SPAKE2 identities bind the role, 16-byte session ID, and paired agent key
ID. The raw shared value is passed through HKDF-SHA-256 with the session ID as
salt and `VOLLCRYPT-SHIELD-PAIRING-KEY-v1\0` plus the agent key ID as info.
Peers exchange HMAC-SHA-256 authenticators over their identity public keys
before persisting a pairing. SPAKE2 state and codes are single-use and are
zeroized when dropped. The chosen upstream implementation does not claim
timing-attack resistance, so pairing codes are random, one-time, short-lived,
and pairing endpoints must be rate-limited.

## Witness quorum

An `AttestationRequest` is:

```text
[version, monotonically_increasing_epoch, signed_snapshot_cbor]
```

Each witness independently verifies that the snapshot signer is its paired
agent before producing a claim:

```text
[version, witness_id, agent_key_id, scope_id, snapshot_root,
 snapshot_created_at_unix_ms, epoch, witnessed_at_unix_ms,
 previous_statement_hash]
```

The signed statement wrapper is
`[claim_cbor, statement_hash, witness_public_key, signature]`. The hash binds
the domain `VOLLCRYPT-SHIELD-WITNESS-HASH-v1\0`, claim length, and exact claim
CBOR. Quorum verification requires a configured threshold of at least two,
distinct registered witness IDs, distinct witness keys, an exact agent/scope/
root/epoch match, and valid ML-DSA-65 signatures. Repeating one witness
statement cannot increase the accepted count. Each witness rejects epochs that
do not increase for an agent and scope.
