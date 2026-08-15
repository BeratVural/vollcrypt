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
| Headless CLI | Stable JSON status, script-safe snapshots, and a full-screen read-only TUI with independently verified evidence and bounded text diffs |
| OCI agent | Signed OCI baselines, live Docker/containerd monitoring, constrained sidecar, and fail-closed admission verification |
| Database agent | Standalone SQLite plus TLS-required PostgreSQL/MySQL integrity with canonical typed rows and hashed row paths |
| Embedded core | Zero-allocation `no_std` integrity state for Cortex-M33, Cortex-M4, and RV32 targets |
| Witness protocol | M-of-N external witnesses, SPAKE2 pairing, signed statements, and air-gapped evidence transfer |

## Safe Response Boundary

Every generated response policy begins in mandatory dry-run. Linux active response is restricted to regular files in non-system monitoring roots. Windows Server active response is available only when the privileged baseline and recovery probe prove that owner, DACL, SACL, integrity label, alternate streams, timestamps, and attributes can be restored. Ordinary Windows accounts remain in dry-run. Shield does not shut down the operating system, cut networking, apply destructive permissions, or globally lock unrelated scopes.

## Desktop and Headless Operation

Use **Vollcrypt Shield Viewer** on supported desktop Linux and Windows systems. Select a folder, save the emergency recovery seed outside that folder, and let Viewer create the first signed baseline. Verification runs on background workers so navigation and settings remain responsive during long scans.

The Windows Store channel packages Viewer as one x64/ARM64 MSIX bundle.
Microsoft signs the package after certification; users never install a
Vollcrypt root certificate. Store signing covers Viewer only. Shield libraries
and the CLI remain independently installable through their native package
channels.

On headless Linux systems, use the full-screen TUI or script-safe dashboard:

```bash
vollcrypt-shield monitor-folder \
  --root /srv/app \
  --state-dir /var/lib/vollcrypt-shield \
  --config shield.toml \
  --break-glass-key /offline/shield-break-glass.seed

vollcrypt-shield tui --config shield.toml --scope default
vollcrypt-shield dashboard --config shield.toml --scope default --once --no-color
```

## Supported Platforms

| Platform | Agent and CLI | Active response | Viewer |
| :--- | :--- | :--- | :--- |
| Ubuntu 22.04 LTS x86_64 | Supported | Non-system regular-file scopes | Supported on desktop installs |
| Ubuntu 24.04 LTS x86_64 | Supported | Non-system regular-file scopes | Supported on desktop installs |
| Ubuntu 26.04 LTS x86_64 | Supported | Non-system regular-file scopes | Supported on desktop installs |
| Debian 13 x86_64 | Supported | Non-system regular-file scopes | Supported on desktop installs |
| Fedora 44 / Rocky 9.8 / AlmaLinux 9.8 x86_64 | Supported | Non-system regular-file scopes | Not packaged |
| RHEL 9.8 x86_64 | Supported | Non-system regular-file scopes | Not packaged |
| Windows Server 2022/2025 x86_64 | Supported | Privilege/capability gated | Supported |
| Windows 11 x86_64 | Supported after trusted-signed release smoke | Privilege/capability gated | Supported |

Windows 11 ARM64 has passed Rust, Node, Viewer, installer, and strict recovery qualification. It remains a qualification target until an exact-commit installer carries a trusted Authenticode signature.

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
- [Package and signature verification](vollcrypt-shield/docs/PACKAGE_VERIFICATION.md)
- [Microsoft Store distribution](vollcrypt-shield/docs/STORE_DISTRIBUTION.md)
- [Shield Viewer privacy policy](PRIVACY-SHIELD.md)
- [Linux filesystem validation](vollcrypt-shield/docs/FILESYSTEM_LINUX_TEST.md)
- [Offline signed packages](vollcrypt-shield/docs/OFFLINE_PACKAGES.md)

## Licensing

Public Shield trust-critical components are dual-licensed under `GPL-3.0-only OR LicenseRef-Commercial`. Centralized fleet operations are commercially licensed and delivered privately.
