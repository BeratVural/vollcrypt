# Shield Architecture

## Distribution boundary

`vollcrypt-shield-core` is an internal Rust build dependency shared by Shield
artifacts. Agent binaries and Node native modules statically include that code.
Consumers do not install another Vollcrypt package for an artifact to work.

Other Vollcrypt products are outside the trust boundary. Future integrations
with db-guard, Wave, or classification tooling use explicit, versioned adapters
and cannot be required for base Shield behavior.

## Active first-delivery components

| Path | Artifact | Purpose |
| --- | --- | --- |
| `core/` | `vollcrypt-shield-core` | Merkle, signatures, CBOR, policies, audit |
| `agents/fs/` | `vollcrypt-shield-fs` | Scan, vault, response, notifications |
| `agents/container/` | `vollcrypt-shield-container` | Reachable OCI graph verification and signed image baselines |
| `agents/db/` | `vollcrypt-shield-db` | Canonical database-record integrity; statically bundled SQLite adapter |
| `cli/` | `vollcrypt-shield` | Administration and local agent commands |
| `bindings/node/` | `@vollcrypt/shield-core-node` | Self-contained Node native SDK |
| `protocol/` | `vollcrypt-shield-protocol` | Pairing and M-of-N witness records |
| `witness/` | `vollcrypt-shield-witness` | Independent monotonic witness node |
| `desktop-app/` | Shield Viewer | Read-only local and quorum verification |
| `control-plane/` | Documentation only | Commercial fleet capability and public interoperability boundary |
| `../vollcrypt-scan/core/` | `vollcrypt-scan-core` | Product-neutral bounded scan engine |
| `../vollcrypt-scan/shield-classifier/` | `vollcrypt-shield-classifier` | Signed advisory criticality rules |

The embedded component will be added only when its roadmap phase begins. Empty
placeholder packages are intentionally not published.

The Node artifact has no production npm dependencies and loads only the native
binary included in its own package. The Rust path dependency on `core/` is a
build-time implementation boundary; release binaries statically contain it.

## Monitoring loop

The filesystem watcher maintains an observed sparse Merkle tree and updates
only event paths and descendants. Incremental expansion is bounded by the
configured path ceiling and is transactional: a failed partial scan does not
replace the last complete observed tree. A separately governed full scan runs
periodically because filesystem notifications are treated as hints. Monitoring
failures are signed into the audit chain, sent through the durable notification
channel, and contain only the affected scope when its active policy permits it.

## Versioned protocol

Signed payloads use deterministic CBOR arrays with fixed field positions. Each
payload includes a format version and algorithm identifiers. Unknown versions
or algorithms fail closed. Human-facing JSON is diagnostic output and is never
the signed representation.

## Classification boundary

`vollcrypt-scan-core` has no Shield or crypto-agility rules. The independent
Shield classifier uses it through a generic rule-set trait and verifies its
canonical default rule JSON with an embedded ML-DSA-65 public key before any
scan begins. Classifier output is a versioned advisory document; it does not
mutate an agent configuration or bypass mandatory dry-run promotion.

## Container boundary

The container agent parses OCI and Docker v2 index/manifest JSON with bounded
structured decoding. It streams and verifies every reachable SHA-256 blob,
then builds a Shield Merkle snapshot over the control files and verified graph.
The local ML-DSA identity is pinned in a private state directory and every
baseline is signer-checked before use or explicit replacement. The state and
layout trees must be disjoint so agent writes cannot invalidate their own
baseline.

Unreferenced blobs are outside the semantic image graph and are not included in
the root. Live containerd/Docker event watching, sidecar enforcement, and
admission decisions remain later Phase 6 work.

## Database boundary

The database agent is independent of db-guard. Its first built-in adapter opens
SQLite read-only using a statically bundled SQLite library and scans inside one
consistent transaction. It accepts a validated table identifier, never raw SQL.
The table schema and typed column values are canonicalized into the snapshot.
Stable key values are domain-separated and hashed before becoming row paths, so
baseline and diagnostic output do not expose primary-key values or row content.

Tables without a primary key require explicit key columns. Null or duplicate
keys, non-finite REAL values, hidden key columns, schema ambiguity, symlinked
database files, and configured byte/row limits fail closed. PostgreSQL/MySQL and
optional db-guard context adapters are not implemented in this slice.

## Fleet boundary

Open, dual-licensed protocol records let an agent prove key possession and emit
ML-DSA-signed summaries without importing commercial code. The commercial
fleet platform provides centralized enrollment, identity pinning, strict
per-agent/per-scope epoch continuity, mTLS transport, RBAC/SSO, reporting, and
retention controls. Its implementation is maintained in a separate private
repository and is not a workspace member of this public monorepo.

## Offline transfer boundary

The dual-licensed protocol defines typed, expiring ML-DSA offline envelopes.
The envelope hash covers its canonical manifest and exact payload; the manifest
binds sender, channel, sequence, previous package hash, payload hash, and size.
Receivers still verify the inner signed record for its declared type.

The CLI requires an expected key and chain position before extracting a
payload. Licensed fleet deployments persist per-sender/per-channel cursors with
the inner summary cursor. Viewer is deliberately read-only: it verifies a
selected package and trusted key but does not claim replay protection without a
persistent external cursor.
