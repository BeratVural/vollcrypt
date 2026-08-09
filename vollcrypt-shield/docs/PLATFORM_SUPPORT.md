# Shield Platform Support

This document defines the public Shield support boundary. A platform is only
listed as verified after its required CI job and release smoke test pass for
the exact Shield release. Support removal follows
[`DEPRECATION_POLICY.md`](DEPRECATION_POLICY.md).

## Release-gated platforms

| Platform | Architecture | Agent and CLI | Active response | Viewer | Validation |
| --- | --- | --- | --- | --- | --- |
| Ubuntu 22.04 LTS | x86_64 | Supported | Supported for non-system regular-file scopes | Supported on desktop installs | Dedicated CI and release smoke test |
| Ubuntu 24.04 LTS | x86_64 | Supported | Supported for non-system regular-file scopes | Supported on desktop installs | Dedicated CI and release smoke test |
| Ubuntu 26.04 LTS | x86_64 | Supported | Supported for non-system regular-file scopes | Supported on desktop installs | Dedicated CI and real-host smoke test |
| Windows Server 2022 | x86_64 | Supported | Not supported; enforced dry-run | Supported | Dedicated CI and release smoke test |
| Windows Server 2025 | x86_64 | Supported | Not supported; enforced dry-run | Supported | Dedicated CI and release smoke test |

Windows 11 x86_64 is a supported desktop target for the CLI, detection,
reporting, notifications, and Viewer. It requires a signed release smoke test
on a real Windows 11 host because GitHub-hosted CI uses Windows Server images.
It has the same enforced dry-run response boundary as Windows Server.

## Qualification targets

The following platforms are being qualified but are not release-supported
until every listed gate passes for a Shield release:

| Platform | Architecture | Current gate |
| --- | --- | --- |
| Debian 13 | x86_64 | Dedicated agent/CLI, Node binding, and Viewer CI plus unrestricted watcher and package smoke tests |
| Windows 11 | ARM64 | Dedicated Rust/CLI, Node binding, and Viewer CI plus signed real-device installer smoke test |

Qualification results must be recorded as `blocked`, rather than product
failures, when a test environment denies required Unix-domain sockets, network
access, package installation, or a graphical session. A blocked result never
promotes a platform to release-supported.

Other Linux distributions, Windows architectures outside the listed targets,
and 32-bit systems are not release supported until they have dedicated build
and runtime coverage. The Rust libraries may compile elsewhere, but successful
compilation is not a support commitment.

## Capability boundary

Linux active response is deliberately limited. Quarantine and rollback accept
regular files in non-system monitoring roots. Directories, symlinks, shutdown,
network isolation, and permission-destructive actions are rejected. Protected
system roots remain passive even when a policy says `active`.

Windows scans, verifies, signs evidence, records the audit chain, emits
notifications, serves status, and runs the read-only Viewer. Quarantine and
rollback stay disabled until Shield can preserve and atomically restore Windows
owners, DACLs, SACLs, integrity labels, alternate data streams, and relevant
extended attributes without weakening access control.

## User interfaces

- `vollcrypt-shield tui` is the full-screen interface for headless Linux and
  Windows terminals. Its read-only views independently verify signed local
  evidence and run filesystem verification off the render thread.
- `vollcrypt-shield dashboard --once` is stable non-interactive text output
  for scripts, service diagnostics, and support captures.
- Vollcrypt Shield Viewer is the graphical interface for desktop Linux and
  Windows. Its guarded `Monitor folder` flow can initialize a local dry-run
  scope and first signed baseline; operational views remain read-only and
  independently verify signed evidence rather than trusting an agent status
  claim.
- `vollcrypt-shield status` remains stable JSON output for automation.

## Release evidence

Every release must retain the following evidence before artifacts are
published:

1. Locked Rust tests and Clippy on each release-gated operating system.
2. Node binding build and tests on each release-gated operating system.
3. Viewer frontend build and independent verifier tests on each release-gated
   operating system.
4. Installer/package smoke tests on Ubuntu 22.04, Ubuntu 24.04, Ubuntu 26.04,
   Windows Server 2022, and Windows Server 2025.
5. A real-host Windows 11 smoke test before marking Windows 11 as verified in
   release notes.

CI success on a floating `*-latest` image is not accepted as platform evidence.
