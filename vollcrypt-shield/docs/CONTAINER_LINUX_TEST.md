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

## Live Docker host monitor

The policy pins Docker's immutable local image ID. Do not substitute a mutable
tag such as `latest`.

```console
docker pull alpine:3.20
digest=$(docker image inspect alpine:3.20 --format '{{.Id}}')
target/debug/vollcrypt-shield-container approve-docker \
  --state-dir /tmp/shield-container-state --image-digest "$digest"
docker run -d --name shield-approved alpine:3.20 sleep 120
target/debug/vollcrypt-shield-container watch-docker \
  --state-dir /tmp/shield-container-state --max-observations 1
target/debug/vollcrypt-shield-container runtime-audit-verify \
  --state-dir /tmp/shield-container-state
docker rm -f shield-approved
```

Expected: the observation reports `host-agent`, `strong`, and
`"approved":true`; audit verification reports `valid`. Repeat with an image
whose immutable ID is absent from the policy. A bounded monitor run must report
`"approved":false`, persist the violation, and exit with status 2. A daemon
disconnect or malformed event fails the monitor closed and appends a
`MonitoringFailed` audit event when the journal remains writable.

## Live containerd host monitor

Use a disposable namespace and approve the target descriptor digest reported
by containerd's Images service:

```console
sudo ctr namespaces create shield-test
sudo ctr --namespace shield-test images pull docker.io/library/alpine:3.20
digest=$(sudo ctr --namespace shield-test images ls \
  | awk '$1 == "docker.io/library/alpine:3.20" { print $3 }')
sudo target/debug/vollcrypt-shield-container approve-containerd \
  --state-dir /tmp/shield-container-state --namespace shield-test \
  --image-digest "$digest"
sudo ctr --namespace shield-test run -d \
  docker.io/library/alpine:3.20 shield-approved sleep 120
sudo target/debug/vollcrypt-shield-container watch-containerd \
  --state-dir /tmp/shield-container-state --max-observations 1
sudo target/debug/vollcrypt-shield-container runtime-audit-verify \
  --state-dir /tmp/shield-container-state --runtime containerd
```

Expected: the inventory observation is approved and the containerd audit chain
is valid. The monitor subscribes before inventory so events occurring during
the inventory window remain queued on the established gRPC stream. It rejects
namespace mismatch, unexpected topics, protobuf type confusion, oversized
payloads, invalid timestamps, and untrusted socket ownership before reporting a
`strong` guarantee.

## Constrained sidecar

Follow [CONTAINER_SIDECAR.md](CONTAINER_SIDECAR.md) to generate the signed
policy outside the pod. Run the one-shot check before deploying:

```console
target/debug/vollcrypt-shield-container sidecar-check \
  --state-dir /tmp/shield-sidecar-state \
  --evidence-file /tmp/shield-sidecar-evidence.json
target/debug/vollcrypt-shield-container runtime-audit-verify \
  --state-dir /tmp/shield-sidecar-state --runtime sidecar
```

Expected: the decision reports `sidecar`, `constrained`, and
`"approved":true`. A binding mismatch, mutable tag, malformed evidence, or
unapproved digest reports `"approved":false` and exits with status 2.
