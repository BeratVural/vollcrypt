# Vollcrypt Shield Witness

`vollcrypt-shield-witness` is an independent witness node for Shield's M-of-N
remote trust model. It pins agent identities, independently verifies signed
snapshots, signs witness statements with ML-DSA-65, and persists monotonic
per-agent/per-scope epochs to reject rollback attempts.

For a connected workflow, use the one-time invitation printed by the agent.
The witness writes the agent key to signed state only after SPAKE2, mutual HMAC
identity confirmation, and the agent's final receipt all succeed.

```console
vollcrypt-shield-witness init --state-dir /var/lib/shield-witness --id witness-a
vollcrypt-shield-witness pair-agent --state-dir /var/lib/shield-witness --invitation "vollcrypt-shield://pair/v1/..."
```

For an air-gapped workflow, move the signed attestation request and resulting
statement as files. `trust-agent` remains an explicit manual pinning operation.

```console
vollcrypt-shield-witness trust-agent --state-dir /var/lib/shield-witness --agent-public-key agent.public
vollcrypt-shield-witness attest --state-dir /var/lib/shield-witness --request request.cbor --output statement.cbor
```

The witness is dual-licensed under
`GPL-3.0-only OR LicenseRef-Commercial`.
