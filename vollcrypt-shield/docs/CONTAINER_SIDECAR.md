# Shield Container Sidecar

The Shield sidecar compares pod evidence with an ML-DSA-signed policy and
contributes a readiness condition to the pod. It is a constrained integration,
not a host monitor. It cannot independently query the container runtime's
actual image ID, inspect host namespaces, or prevent an already running process
from executing. Use the Docker or containerd host monitor when a strong runtime
guarantee is required.

## Approval boundary

Create and approve state outside the pod in a trusted deploy step. Never derive
the approved digest from evidence supplied by the pod being checked.

```console
vollcrypt-shield-container init \
  --state-dir ./shield-sidecar-state --scope payments-api
vollcrypt-shield-container approve-sidecar \
  --state-dir ./shield-sidecar-state \
  --binding production/payments-api \
  --image-digest sha256:<64-lowercase-hex>
```

The state contains an audit signing seed. Store it in a Kubernetes Secret
protected by narrow RBAC and encryption at rest, or in a CSI-backed secret
store. Mount or copy it only into the Shield container. The workload container
must not receive the state volume.

## Evidence

The sidecar accepts a bounded JSON file or four fixed environment variables.
Unknown JSON fields, mutable tags, non-canonical digests, invalid identifiers,
and files reached through symlinks fail closed.

```json
{
  "version": 1,
  "podUid": "4c27d923-5401-4d04-b523-037fe71b77b0",
  "namespace": "production",
  "containerName": "payments-api",
  "imageDigest": "sha256:<64-lowercase-hex>"
}
```

The environment form uses `SHIELD_POD_UID`, `SHIELD_NAMESPACE`,
`SHIELD_CONTAINER_NAME`, and `SHIELD_IMAGE_DIGEST`. The signed policy binds
the exact `namespace/containerName` pair.

## Readiness service

```console
vollcrypt-shield-container serve-sidecar \
  --state-dir /var/lib/vollcrypt-shield/container/sidecar \
  --listen 0.0.0.0:9464 --poll-seconds 5
```

`GET /readyz` returns 200 only while the evidence matches the signed policy;
all failures return 503. Kubernetes considers a pod ready only when every
container with a readiness probe is ready, so the sidecar probe removes the pod
from Service endpoints on a mismatch. This does not terminate the workload and
does not replace admission control.

Every outcome transition is written to
`runtime.sidecar.audit.cborseq` as a framed, ML-DSA-signed, hash-chained
record. Repeated identical polls do not grow the journal.

```console
vollcrypt-shield-container runtime-audit-verify \
  --state-dir /var/lib/vollcrypt-shield/container/sidecar --runtime sidecar
```

The deployment skeleton in
[`examples/kubernetes-sidecar.yaml`](../examples/kubernetes-sidecar.yaml)
keeps approved state out of the application container. Replace every
`REPLACE_...` value with a digest-pinned image or pre-created Secret before
applying it.
