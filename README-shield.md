---
layout: default
title: Vollcrypt Shield
---

<div class="product-intro">
  <img class="product-mark" src="vollcrypt-shield/desktop-app/src-tauri/icons/128x128.png" alt="Vollcrypt Shield application icon" width="96" height="96">
  <p class="product-kicker">RUNTIME INTEGRITY</p>
  <h1>Vollcrypt Shield</h1>
  <p><strong>Prove approved state, detect drift, and contain the affected scope without disabling the machine.</strong></p>
  <p>
    <a href="https://github.com/BeratVural/vollcrypt/actions/workflows/ci-shield.yml"><img src="https://github.com/BeratVural/vollcrypt/actions/workflows/ci-shield.yml/badge.svg" alt="Shield CI"></a>
    <a href="LICENSE-GPL"><img src="https://img.shields.io/badge/License-GPLv3-blue.svg" alt="GPLv3 license"></a>
    <a href="LICENSE-COMMERCIAL.md"><img src="https://img.shields.io/badge/License-Commercial-goldenrod.svg" alt="Commercial license"></a>
  </p>
</div>

Shield continuously compares monitored state with an approved ML-DSA-65-signed Merkle baseline. It records signed, tamper-evident evidence and can move only the affected policy scope into containment when verification fails.

## Public Shield 1.0

| Surface | Included capability |
| :--- | :--- |
| Filesystem agent | Full and incremental scans, reversible quarantine, atomic rollback, scoped containment, and recurring notifications |
| Shield Viewer | Guarded folder onboarding, independent verification, absolute change paths, signed-baseline text comparison, and persistent settings |
| Headless CLI | Stable JSON status plus a live read-only terminal dashboard for Linux servers |
| OCI agent | Verifies reachable image indexes, manifests, configs, and layers before baseline comparison |
| Database agent | Standalone SQLite record integrity with canonical typed rows and hashed row paths |
| Embedded core | Zero-allocation `no_std` integrity state for Cortex-M33, Cortex-M4, and RV32 targets |
| Witness protocol | M-of-N external witnesses, SPAKE2 pairing, signed statements, and air-gapped evidence transfer |

## Safe Response Boundary

Every generated response policy begins in mandatory dry-run. Linux active response is restricted to regular files in non-system monitoring roots. Shield does not shut down the operating system, cut networking, apply destructive permissions, or globally lock unrelated scopes. Windows detection, evidence, notification, and Viewer workflows remain enforced dry-run.

## Desktop and Headless Operation

Use **Vollcrypt Shield Viewer** on supported desktop Linux and Windows systems. Select a folder, save the emergency recovery seed outside that folder, and let Viewer create the first signed baseline. Verification runs on background workers so navigation and settings remain responsive during long scans.

On headless Ubuntu systems, use the terminal dashboard:

```bash
vollcrypt-shield monitor-folder \
  --root /srv/app \
  --state-dir /var/lib/vollcrypt-shield \
  --config shield.toml \
  --break-glass-key /offline/shield-break-glass.seed

vollcrypt-shield dashboard --config shield.toml --scope default
```

## Supported Platforms

| Platform | Agent and CLI | Active response | Viewer |
| :--- | :--- | :--- | :--- |
| Ubuntu 22.04 LTS x86_64 | Supported | Non-system regular-file scopes | Supported on desktop installs |
| Ubuntu 24.04 LTS x86_64 | Supported | Non-system regular-file scopes | Supported on desktop installs |
| Windows Server 2022/2025 x86_64 | Supported | Enforced dry-run | Supported |
| Windows 11 x86_64 | Supported after release smoke test | Enforced dry-run | Supported |

<div class="commercial-band">
  <h2>Shield Commercial</h2>
  <p>Move from one independently verified node to centralized fleet operations. Licensed <code>shield-commercial</code> bundles add fleet enrollment and inventory, managed mTLS identities and revocation, pinned-JWKS OIDC roles, replay-protected signed-summary or raw retention, SQLite WAL or TLS 1.3 PostgreSQL storage, air-gapped ingestion, a centralized terminal dashboard, and ML-DSA-signed JSON/CSV compliance reports.</p>
  <p>Commercial server, storage, administration, and fleet-dashboard source remains in a separate private repository. Customers receive prebuilt Linux and Windows deployment bundles; public agents and clients can still verify signed evidence independently.</p>
  <a class="action-link action-link-primary" href="mailto:berat.vural.tr@gmail.com?subject=Vollcrypt%20Shield%20Commercial">Discuss a commercial deployment</a>
  <a class="action-link" href="vollcrypt-shield/docs/COMMERCIAL_FEATURES.md">Review the feature boundary</a>
</div>

## Documentation

- [Complete Shield technical documentation](vollcrypt-shield/README.md)
- [Security model](vollcrypt-shield/docs/SECURITY_MODEL.md)
- [Platform support](vollcrypt-shield/docs/PLATFORM_SUPPORT.md)
- [Linux filesystem validation](vollcrypt-shield/docs/FILESYSTEM_LINUX_TEST.md)
- [Offline signed packages](vollcrypt-shield/docs/OFFLINE_PACKAGES.md)

## Licensing

Public Shield trust-critical components are dual-licensed under `GPL-3.0-only OR LicenseRef-Commercial`. Centralized fleet operations are commercially licensed and delivered privately.
