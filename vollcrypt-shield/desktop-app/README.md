# Vollcrypt Shield Viewer

Shield Viewer is the independent, read-only Tauri interface for a local
Vollcrypt Shield filesystem agent. It verifies the configured agent public
key, signed state, signed baseline, tamper-evident audit chain, and current
Merkle root itself. It does not accept policy changes, deployment approvals,
or break-glass commands.

The local trust root is labelled `local-unanchored` because the public key is
stored on the monitored machine. Select an externally pinned witness policy
JSON file and a directory of signed witness statement CBOR files to enable
independent M-of-N verification. A complete proof must match the exact agent,
scope, baseline root, baseline timestamp, and epoch. Policies inside the agent
state directory or a monitored scope are rejected.

```powershell
npm ci
npm run build
npm run tauri dev
```

Shield Viewer is dual-licensed under
`GPL-3.0-only OR LicenseRef-Commercial`.
