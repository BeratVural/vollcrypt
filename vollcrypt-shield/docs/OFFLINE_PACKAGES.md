# Shield Offline Packages

Shield offline packages are deterministic-CBOR transfer envelopes for physical
or otherwise disconnected movement of signed evidence. They do not encrypt the
payload. Use encrypted removable media when confidentiality is required.

## Signed fields

Each ML-DSA-65 signature covers the exact payload and canonical manifest. The
manifest includes:

- protocol version, random package ID, and payload type;
- sender key ID and channel ID;
- creation and expiry times, with a maximum 30-day lifetime;
- sequence and previous package hash;
- SHA-256 payload hash and payload length.

Payloads are limited to 16 MiB. Package readers reject symlinks, oversized
files, trailing CBOR data, expired packages, wrong trusted keys, and inner
records whose signer does not match the outer sender.

## First package

```console
vollcrypt-shield fleet-summary --config shield.toml --scope default --epoch 1 --output summary-1.cbor
vollcrypt-shield offline-pack --config shield.toml --kind fleet-summary --channel production-summaries --input summary-1.cbor --sequence 1 --output summary-1.vcsp
```

Sequence 1 requires an all-zero previous hash, which the CLI supplies when
`--previous-hash` is absent.

## Continued chain

Use the first command's `summaryHash` as the next fleet summary's
`--previous-hash`. Use the first offline-pack command's `packageHash` as the
next package's `--previous-hash`:

```console
vollcrypt-shield fleet-summary --config shield.toml --scope default --epoch 2 --previous-hash <SUMMARY_HASH_1> --output summary-2.cbor
vollcrypt-shield offline-pack --config shield.toml --kind fleet-summary --channel production-summaries --input summary-2.cbor --sequence 2 --previous-hash <PACKAGE_HASH_1> --output summary-2.vcsp
```

## Receiving

For a one-off extraction, the receiver supplies the expected sender key and
chain position:

```console
vollcrypt-shield offline-unpack --package summary-2.vcsp --expected-public-key node-a.public --expected-sequence 2 --previous-hash <PACKAGE_HASH_1> --output summary-2.cbor
```

For durable fleet ingestion, the control plane stores the channel cursor in its
signed state:

```console
# Licensed fleet deployments import the package through their private service interface.
```

Viewer verifies a selected package and trusted public key without writing the
inner payload. It verifies package authenticity, expiry, payload digest, and
the type-specific inner signature. Viewer does not persist a replay ledger, so
sequence continuity after package 1 must be checked through the CLI, control
plane, or another externally pinned cursor.
