# Shield Security Model

## Phase 0-2 guarantees

Shield detects state differences using a versioned sparse Merkle tree whose
leaves bind normalized paths, entry types, content digests, and configured
metadata. Approved roots and audit records are signed with ML-DSA-65.

The Phase 2 response engine is deliberately bounded:

- containment applies only to the scope that triggered the policy;
- containment blocks new baselines and approvals for that scope;
- it never shuts down the operating system, disables networking, applies
  `chmod 000`, or performs a global agent lock;
- quarantine records the original path, permissions, ownership, timestamps,
  extended attributes, and content digest before moving an entry;
- rollback verifies backup content and metadata in a random, create-new
  same-directory file, then atomically creates the destination with a
  no-clobber hard link;
- every response policy starts in dry-run and requires explicit promotion;
- a contained scope emits persistent audit records and recurring log/webhook
  reminders until a valid break-glass command releases it.

The metadata guarantee above applies to the Linux/Unix active-response target.
Windows remains enforced dry-run in this delivery because preserving and
restoring Windows ACLs and ownership losslessly is not implemented. Active
quarantine and rollback reject non-regular files instead of applying an unsafe
partial restore.

## Trust boundary

An administrator or kernel-level attacker can stop the Phase 1 agent or replace
a software-only local trust root. Shield reports this mode as
`local-unanchored`. Phase 4 can raise the evidence level with an external M-of-N
witness policy, but only when the Viewer pins that policy outside agent state
and monitored scopes and independently verifies quorum statements for every
baseline. Hardware-backed roots remain future work.

Connected pairing uses a random 80-bit one-time code, SPAKE2, HKDF-SHA-256, and
mutual HMAC confirmation that binds each peer's ML-DSA public identity. The
listener consumes one connection attempt and has a 30-600 second validity
window. Pairing does not make public keys confidential. Witness epochs are
monotonic per agent and scope; replay or rollback is rejected by signed witness
state.

Filesystem notifications are hints, not proof. The agent combines notifications
with periodic scans and performs descriptor-based metadata checks to reduce
time-of-check/time-of-use risk. No claim is made that every modification can be
prevented before execution.

Linux local status IPC is read-only, bounded to 4096-byte messages, placed in a
mode `0700` directory, and exposed through a mode `0600` Unix socket. It does
not expose response-policy, baseline, or break-glass mutation commands.

Classification suggestions are untrusted advisory input, not policy. The
classifier verifies its compiled canonical default rule document with
ML-DSA-65, applies deterministic file/byte ceilings, and does not follow
symlinks. Its output cannot activate responses; an administrator must review
it and Shield's mandatory dry-run/promotion controls still apply.

## Terminology

Use "cryptographic assurance", not "mathematical certainty". Audit logs are
"tamper-evident", not immutable. State security is described by algorithm and
security level rather than a fixed-year guarantee.
