# Shield Container Linux Validation

This procedure validates the Phase 6 host-agent slice against a real OCI image
layout. Run it from the Vollcrypt repository root on Linux. The example uses
Podman and Skopeo; Docker can supply the source image, but Skopeo is used to
produce the standard OCI directory layout.

## Prerequisites

```console
rustup toolchain install stable
sudo apt-get install -y podman skopeo
cargo build --locked -p vollcrypt-shield-container
```

## Valid image

```console
rm -rf /tmp/shield-oci /tmp/shield-container-state
skopeo copy docker://docker.io/library/alpine:3.20 oci:/tmp/shield-oci:alpine
target/debug/vollcrypt-shield-container init \
  --state-dir /tmp/shield-container-state --scope alpine-3.20
target/debug/vollcrypt-shield-container scan --layout /tmp/shield-oci
target/debug/vollcrypt-shield-container baseline \
  --state-dir /tmp/shield-container-state --layout /tmp/shield-oci
target/debug/vollcrypt-shield-container verify \
  --state-dir /tmp/shield-container-state --layout /tmp/shield-oci
```

Expected: `scan` reports `valid`, `verify` reports `match`, and both report a
`strong` guarantee. The secret key and both state directories must be private:

```console
stat -c '%a %n' /tmp/shield-container-state \
  /tmp/shield-container-state/keys \
  /tmp/shield-container-state/keys/agent.seed
```

Expected modes: `700`, `700`, and `600` respectively.

## Tampering

Select a reachable blob from `index.json` and alter one byte without changing
the descriptor. This command deliberately corrupts the first referenced blob
in the disposable test layout:

```console
blob=$(find /tmp/shield-oci/blobs/sha256 -type f | head -n 1)
printf X | dd of="$blob" bs=1 seek=0 conv=notrunc status=none
target/debug/vollcrypt-shield-container verify \
  --state-dir /tmp/shield-container-state --layout /tmp/shield-oci
```

Expected: a non-zero exit and a descriptor digest mismatch. Restore the layout
with Skopeo before further tests.

## Symlink rejection

```console
mv /tmp/shield-oci/index.json /tmp/index.real.json
ln -s /tmp/index.real.json /tmp/shield-oci/index.json
target/debug/vollcrypt-shield-container scan --layout /tmp/shield-oci
```

Expected: a non-zero exit stating that `index.json` is not a regular
non-symlink file. These commands only target disposable `/tmp` paths created by
this procedure.
