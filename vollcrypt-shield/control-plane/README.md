# Vollcrypt Shield Commercial Fleet Platform

The Shield fleet platform is offered under a commercial license. Its server,
storage, administration, and dashboard implementation is maintained in a
private repository and is not distributed from this public monorepo.

The customer-facing product remains **Vollcrypt Shield**. Licensed customers
receive the private control-plane distribution as a prebuilt
`shield-commercial` package after the applicable agreement. No installer,
binary, private source, or customer credential is published here.

## Available in the current licensed distribution

- centralized agent enrollment and inventory;
- time- and use-limited bootstrap provisioning;
- TLS 1.3 mutual-authentication fleet transport;
- pinned agent identities and signed-summary replay protection;
- air-gapped signed-package ingestion;
- ML-DSA-signed service responses; and
- prebuilt `shield-commercial` Windows/Linux deployment bundles.

## Contract-specific roadmap

- centralized fleet dashboard and comparative integrity reporting;
- SSO, RBAC, separate viewer/control authorization, and audit roles;
- compliance reports and export workflows;
- database-backed high availability and horizontal scaling;
- per-agent `raw` or `signed-summary` retention policy;
- enterprise notification and incident-routing integrations.

Roadmap items are not included in the current licensed binary unless a signed
agreement explicitly schedules their delivery. No commercial capability is
included in the open-source packages.

## Public interoperability boundary

The public `vollcrypt-shield-protocol` crate contains versioned enrollment,
summary, offline-package, and signed-response formats. Public agents can create
signed evidence and public Viewer components can independently verify it. This
keeps the trust format auditable without publishing the commercial service
implementation.

The public filesystem, container, and database agents do not require the fleet
platform. They continue to work in standalone single-node mode.

For commercial licensing and deployment terms, use the project's published
commercial contact channel. No commercial server binary or source package is
published from this directory.
