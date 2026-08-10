# Shield Kubernetes Admission Controller

The Shield admission controller rejects Pods whose container images are not
digest pinned and approved by an ML-DSA-signed namespace policy. It validates
regular, init, and ephemeral containers on Pod CREATE and UPDATE requests.

Its guarantee is labeled `build-time-only`. Admission proves what the API
server accepted; it does not prove that the node later ran the same image.
Combine it with the strong containerd or Docker host monitor for runtime
evidence.

## Prepare policy

Generate state outside the cluster or in a trusted deployment pipeline:

```console
vollcrypt-shield-container init \
  --state-dir ./admission-state --scope production-admission
vollcrypt-shield-container approve-admission \
  --state-dir ./admission-state --namespace production \
  --image-digest sha256:<64-lowercase-hex>
```

Store the state in a narrowly scoped Secret or CSI secret store. It contains an
audit signing seed and must never be mounted into admitted workloads.

Test a captured AdmissionReview before deployment:

```console
vollcrypt-shield-container admission-check \
  --state-dir ./admission-state --review review.json
vollcrypt-shield-container runtime-audit-verify \
  --state-dir ./admission-state --runtime admission
```

## TLS and webhook

Kubernetes requires HTTPS. Issue a certificate whose SAN covers
`vollcrypt-shield-admission.vollcrypt-shield-system.svc`, mount the certificate
and private key as individual `subPath` bind mounts so they appear as regular
non-symlink files, and put the issuing CA in the webhook `caBundle`. Because
`subPath` mounts do not receive Secret updates, rotate TLS with a controlled
Deployment rollout.

```console
vollcrypt-shield-container serve-admission \
  --state-dir /state --listen 0.0.0.0:8443 \
  --tls-cert /tls/tls.crt --tls-key /tls/tls.key
```

The example
[`kubernetes-admission.yaml`](../examples/kubernetes-admission.yaml) uses
`failurePolicy: Fail`, a three-second timeout, no side effects, and Pod-only
CREATE/UPDATE rules. Label only the namespace bound by the signed policy with
`vollcrypt.io/shield-admission=enabled`.

The request body is capped at 1 MiB, each Pod is capped at 256 container
entries, image references are capped at 1024 bytes, and concurrent requests are
capped at 64. Capacity exhaustion, malformed JSON, unsupported operations, TLS
failure, policy failure, and audit write failure all fail closed. The webhook
does not contact a registry and rejects mutable tags.
