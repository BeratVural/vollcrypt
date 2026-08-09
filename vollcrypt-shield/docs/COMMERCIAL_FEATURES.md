# Shield Commercial Features

Shield uses an open-core distribution boundary. Trust-critical formats and
standalone agents remain auditable in the public repository; centralized
enterprise operations are supplied under a commercial license from a private
implementation repository.

The product name remains **Vollcrypt Shield**. After a commercial agreement,
customers receive a private, prebuilt `shield-commercial` deployment bundle.
That distribution name distinguishes licensed fleet operations from the
standalone public Shield packages; it does not rename the product.

## Public and dual-licensed

- Shield core Merkle, ML-DSA, policy, audit, and snapshot primitives;
- standalone filesystem, OCI container, SQLite database, and `no_std` embedded
  agents;
- witness node and M-of-N witness protocol;
- pairing, enrollment, signed-summary, offline-package, and signed-response
  protocol formats;
- local CLI, Node binding, classifier, and read-only Viewer verification;
- single-node local monitoring and direct evidence verification.

These components use `GPL-3.0-only OR LicenseRef-Commercial`. A commercial
license permits proprietary integration without applying GPL obligations to the
licensee's own application, subject to the applicable agreement.

## Available in the current licensed distribution

- centralized fleet registration, inventory, and provisioning;
- time- and use-limited bootstrap workflows;
- TLS 1.3 mTLS fleet service using customer-supplied certificates;
- pinned agent identities and replay-protected signed-summary retention;
- air-gapped signed-package ingestion;
- ML-DSA-signed service responses; and
- prebuilt `shield-commercial` Windows/Linux deployment bundles.

## Contract-specific roadmap

- centralized dashboard and cross-agent comparison;
- managed certificate lifecycle;
- SSO, RBAC, viewer/control role separation, and enterprise audit roles;
- compliance reports, evidence exports, and retention workflows;
- database-backed high availability and horizontal scaling;
- `raw` data retention; and
- enterprise notification, incident-routing, and support integrations.

Roadmap items are not part of the current deliverable unless a signed agreement
explicitly includes and schedules them. This public repository intentionally
contains no commercial server, storage, administration, or fleet-dashboard
source code.

## Interoperability

Public agents can produce signed enrollment, summary, witness, and offline
records for a licensed fleet deployment. Public clients can verify ML-DSA-signed
responses and evidence independently. Publishing these formats does not publish
the private service implementation and avoids making the commercial platform a
blind trust root.
