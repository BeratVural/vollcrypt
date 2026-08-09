# Vollcrypt Shield

Vollcrypt Shield is a tamper-evident integrity verification and scoped response
system. The current public delivery includes:

- a Shield-specific sparse Merkle tree and signed baseline format;
- ML-DSA-65 signatures and deterministic CBOR protocol records;
- a tamper-evident, signed audit chain;
- a Linux-first filesystem agent with full and incremental scans;
- mandatory dry-run before response policy activation;
- reversible quarantine, atomic rollback, and scope-only containment;
- recurring containment notifications and signed break-glass release commands;
- a self-contained CLI and Node.js native binding;
- an independent, read-only Tauri Viewer for scope status, verified events,
  file-level Merkle inspection, and external M-of-N witness quorum proofs;
- short-lived SPAKE2 agent-witness pairing over a one-shot TCP listener, with
  a versioned QR URI and mutually authenticated ML-DSA public identities.
- an independent bounded scan core and Shield classifier that emits reviewed,
  non-activating criticality suggestions from ML-DSA-signed default rules.
- an independent OCI image-layout agent that verifies every reachable index,
  manifest, config, and layer descriptor before comparing an ML-DSA-signed
  Shield baseline.
- an independent, zero-allocation `no_std` embedded integrity state for
  Cortex-M33, Cortex-M4, and RV32 targets, with monotonic audit checkpoints and
  a hardware-backed ML-DSA-65 signing boundary.

Linux/Unix is the active-response target for this delivery. On Windows the
agent scans, verifies, logs, and reports in enforced dry-run mode; it does not
quarantine or roll back until equivalent ACL/ownership restoration guarantees
are implemented. Active quarantine and rollback currently accept regular files
only. Directories, symlinks, operating-system shutdown, network isolation, and
permission-destructive responses are rejected.

Shield does not depend on any other Vollcrypt product. Published agents and
bindings include the Shield core they need and do not require another
`@vollcrypt/*` package at runtime.

Shield is not an antivirus, EDR, vulnerability scanner, or memory-monitoring
system. Its evidence provides cryptographic assurance that a monitored state
matches an approved baseline. A software trust root stored on the monitored
host is classified as weak until an external witness policy is pinned outside
the monitored state and a valid quorum anchors every baseline.

## CLI workflow

```console
vollcrypt-shield config-example --root /srv/app --state-dir /var/lib/vollcrypt-shield --output shield.toml
vollcrypt-shield init --config shield.toml --break-glass-key /offline/shield-break-glass.seed
vollcrypt-shield baseline --config shield.toml --scope default
vollcrypt-shield verify --config shield.toml --scope default
vollcrypt-shield watch --config shield.toml --scope default
```

Every generated response policy is dry-run. Shield requires signed verification
evidence for the exact current scope and policy fingerprint before
`policy-activate` succeeds. Changing a rule invalidates prior evidence. A
successful activation is itself appended to the signed audit chain.
The Linux watcher exposes only the watched scope's status through a user-only
Unix socket; baseline, policy, and break-glass controls are not available over
that socket.

## Shield Viewer

The Viewer verifies the configured agent public key, signed state, signed
baseline, tamper-evident audit chain, and current Merkle root itself. It does
not expose policy activation, deployment approval, or break-glass commands.
Local deployments are labelled `local-unanchored` because a key stored on the
monitored host is not an independent trust anchor. The Viewer labels a scope
`witness-quorum` only after independently verifying the selected external
policy and enough ML-DSA statements for the exact agent, scope, root, baseline
timestamp, and epoch. The Viewer rejects policy files inside the agent state
directory or a monitored scope.

## Witness protocol foundation

`vollcrypt-shield-protocol` implements short-lived, one-time SPAKE2 pairing
with HKDF-SHA-256 key derivation and mutual HMAC confirmation. The independent
`vollcrypt-shield-witness` node pins agent identities, verifies signed
snapshots, produces ML-DSA-65 witness statements, and persists signed monotonic
epoch state. The agent stores paired witness identities in its own signed
registry. Quorum verification requires at least two distinct registered
witnesses and rejects duplicate statements, wrong roots, unpaired agents, and
epoch rollback.

Connected pairing prints a short code and the same data as a versioned
`vollcrypt-shield://pair/v1/...` QR payload. `pair-witness` accepts one
connection and expires after five minutes by default. For LAN listening, bind
to a wildcard address but advertise the reachable agent address explicitly.

```console
vollcrypt-shield pair-witness --config shield.toml --listen 0.0.0.0:49372 --advertise 192.0.2.10:49372
vollcrypt-shield-witness pair-agent --state-dir /var/lib/shield-witness-a --invitation "vollcrypt-shield://pair/v1/..."
vollcrypt-shield witness-policy-export --config shield.toml --threshold 2 --output /offline/shield-witness-policy.json
vollcrypt-shield witness-request --config shield.toml --scope default --epoch 1 --output request.cbor
vollcrypt-shield-witness attest --state-dir /var/lib/shield-witness-a --request request.cbor --output statements/witness-a.cbor
```

Repeat pairing and attestation for enough distinct witnesses to meet the
policy threshold, then select the external policy and statements directory in
Shield Viewer. Air-gapped transfer uses the same request and statement files.

## Classification suggestions

The classifier is outside the Shield agent dependency tree. It combines
bounded deterministic traversal, path heuristics, exact content markers, and
entropy analysis. Every path receives a `Critical`, `Important`, or `Standard`
suggestion, confidence score, and reasons. The signed, versioned default rule
document is compiled into the binary and verified before scanning; rules are
never downloaded or silently learned at runtime.

```console
vollcrypt-shield-classify --root /srv/project --output shield-suggestions.json
```

The output is advisory and cannot activate a response policy. Administrators
must review suggestions; normal Shield mandatory dry-run and explicit policy
promotion remain unchanged.

## Container image workflow

The Phase 6 host-agent slice operates on OCI image-layout directories. It
rejects symlinked control/blob files, non-canonical SHA-256 descriptors,
descriptor size or digest mismatches, oversized graphs, and state directories
nested in the monitored layout. Baseline replacement requires explicit
`--replace` approval and first verifies the existing signed baseline.

```console
vollcrypt-shield-container init --state-dir /var/lib/vollcrypt-shield/container/my-image --scope my-image
vollcrypt-shield-container scan --layout /srv/oci/my-image
vollcrypt-shield-container baseline --state-dir /var/lib/vollcrypt-shield/container/my-image --layout /srv/oci/my-image
vollcrypt-shield-container verify --state-dir /var/lib/vollcrypt-shield/container/my-image --layout /srv/oci/my-image
```

The current guarantee is `strong` only for this host-level OCI verification
path. Sidecar and admission-controller integrations are not implemented yet and
must not be treated as equivalent runtime guarantees. Follow
[`docs/CONTAINER_LINUX_TEST.md`](docs/CONTAINER_LINUX_TEST.md) for the Linux
runtime validation matrix.

## Database record integrity

`vollcrypt-shield-db` is a standalone Phase 9 agent with a statically bundled
SQLite adapter. It needs neither db-guard nor a system SQLite installation. A
read-only transaction produces an ML-DSA-signed Merkle baseline over the table
schema and canonical typed rows, while hashed row paths avoid disclosing key
values.

```console
vollcrypt-shield-db init --state-dir /var/lib/vollcrypt-shield/db/accounts --scope accounts
vollcrypt-shield-db baseline --state-dir /var/lib/vollcrypt-shield/db/accounts --database app.sqlite --table accounts
vollcrypt-shield-db verify --state-dir /var/lib/vollcrypt-shield/db/accounts --database app.sqlite --table accounts
```

PostgreSQL/MySQL and optional db-guard enhanced context remain later adapters;
they are not required for the current SQLite mode.

## Embedded integrity foundation

`vollcrypt-shield-embedded` is independent of Wave and every other Vollcrypt
package. It maintains a fixed-capacity Merkle measurement set, monotonic audit
chain, scope-only containment gate, and fixed checkpoint bytes without an
allocator or operating system. Applications provide persistence, a hardware
monotonic counter, notifications, and ML-DSA-65 signing or verification through
traits.

This is an integrity-state foundation, not a bootloader or board support
package. A deployment reaches a hardware-backed trust level only when the
application places counters and keys in TrustZone-M or a secure element and
persists audit records outside attacker-writable firmware state. See
[`agents/embedded/README.md`](agents/embedded/README.md).

## Commercial fleet platform

Centralized fleet management is a commercially licensed product. Its server,
storage, administration, and dashboard implementation is maintained privately
and is not published from this monorepo. Commercial capabilities include
bootstrap provisioning, mTLS fleet transport, centralized inventory and
dashboard views, replay-protected summary retention, SSO/RBAC, enterprise
reporting, compliance exports, high-availability storage, and policy-controlled
raw or signed-summary retention.

The filesystem agent exports protocol files without exposing its secret key:

```console
vollcrypt-shield fleet-enrollment-request --config shield.toml --label node-a --output enrollment.cbor
vollcrypt-shield fleet-summary --config shield.toml --scope default --epoch 1 --output summary-1.cbor
```

The public protocol remains independently auditable: agents can generate
ML-DSA-signed enrollment and summary records, and clients can verify signed
commercial-service responses without importing private server code. See
[`control-plane/README.md`](control-plane/README.md) and
[`docs/COMMERCIAL_FEATURES.md`](docs/COMMERCIAL_FEATURES.md).

## Air-gapped packages

Shield offline packages bind a typed inner payload to an ML-DSA sender,
channel, expiry, sequence, previous package hash, and random package ID. The
inner enrollment, summary, snapshot, or witness record is independently
verified before use.

```console
vollcrypt-shield offline-pack --config shield.toml --kind fleet-summary --channel production-summaries --input summary-1.cbor --sequence 1 --output summary-1.vcsp
vollcrypt-shield offline-unpack --package summary-1.vcsp --expected-public-key /trusted/node-a.public --expected-sequence 1 --output verified-summary-1.cbor
```

For sequence 2 and later, pass the preceding `packageHash` as
`--previous-hash`. Licensed fleet deployments persist this cursor and reject
replay automatically. Shield Viewer can select a package and
trusted public key to verify outer and inner signatures without extracting the
payload. Viewer reports later sequence continuity as unanchored because its
read-only inspection does not persist a cursor. See
[`docs/OFFLINE_PACKAGES.md`](docs/OFFLINE_PACKAGES.md).

## Licensing

The public Shield core, agents, witness components, protocol, and SDK bindings
are dual-licensed under `GPL-3.0-only OR LicenseRef-Commercial`. The fleet
fleet platform, SSO/RBAC, enterprise reporting, and centralized operations are
commercial only. Their implementation is not included in this public repo.
