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
| Debian 13 | x86_64 | Supported | Supported for non-system regular-file scopes | Supported on desktop installs | Pinned CI, unrestricted watcher, and package smoke test |
| Fedora 44 | x86_64 | Supported | Supported for non-system regular-file scopes | Not packaged | Full-VM systemd, watcher, audit, and RPM smoke |
| Rocky Linux 9.8 | x86_64 | Supported | Supported for non-system regular-file scopes | Not packaged | Full-VM systemd, watcher, audit, and RPM smoke |
| AlmaLinux 9.8 | x86_64 | Supported | Supported for non-system regular-file scopes | Not packaged | Full-VM systemd, watcher, audit, and RPM smoke |
| Windows Server 2022 | x86_64 | Supported | Supported behind a privilege/capability gate | Supported | Strict real-host recovery and release smoke |
| Windows Server 2025 | x86_64 | Supported | Supported behind a privilege/capability gate | Supported | Strict real-host recovery and release smoke |

Windows 11 x86_64 is a supported desktop target for the CLI, detection,
reporting, notifications, and Viewer. It requires a signed release smoke test
on a real Windows 11 host because GitHub-hosted CI uses Windows Server images.
Its active-response implementation has the same fail-closed qualification
boundary as Windows Server.

## Qualification targets

The following platforms are being qualified but are not release-supported
until every listed gate passes for a Shield release:

| Platform | Architecture | Current gate |
| --- | --- | --- |
| Windows 11 | ARM64 | Dedicated Rust/CLI, Node binding, and Viewer CI plus signed real-device installer smoke test |
| RHEL 9 / UBI 9.8 | x86_64 | Digest-pinned ABI-compatible CI and RPM smoke; licensed RHEL real-host evidence pending |

The weekly `Vollcrypt Shield RPM VM Qualification` gate boots Fedora, Rocky
Linux, and AlmaLinux as full virtual machines with systemd as PID 1. It builds
and installs the native RPM, runs the agent as the packaged service identity,
exercises watcher/IPC/audit delivery, and retains kernel, package digest,
service journal, and systemd hardening evidence. RHEL promotion still requires
licensed real-host evidence; UBI is not treated as a RHEL host.

Run `31873772624` passed this gate for Fedora 44, Rocky Linux 9.8, and
AlmaLinux 9.8 from public commit `7dae462`. Its per-platform artifacts retain
the exact OS release, kernel, architecture, package SHA-256, systemd hardening
report, service journal, active service state, and dry-run policy result.

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
notifications, serves status, and runs the read-only Viewer without elevated
backup privileges. Active quarantine and rollback require a new baseline from
the same privileged Shield service account that will run the agent. Shield uses
the Windows backup stream to preserve default data, alternate data streams,
extended attributes, owner, DACL, SACL, and integrity label. It stores creation,
access, write, and change times plus file attributes separately in the signed
sidecar. Activation performs a create-new backup/restore probe and fails closed
unless `SeBackupPrivilege`, `SeRestorePrivilege`, and `SeSecurityPrivilege` are
all assigned and can be enabled. Regular non-reparse, non-EFS files are the only
accepted targets. Strict real-host recovery qualification runs weekly and on
demand across Windows Server 2022/2025 x86_64 and Windows 11 ARM64; each release
must retain a passing artifact for its exact commit.

The dedicated Windows 11 ARM64 runner also builds the native NSIS installer,
installs it silently, validates the installed PE machine type, and uninstalls
it. This is package smoke evidence, but Windows 11 ARM64 remains a qualification
target until the same installer has a valid trusted Authenticode signature.

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
   Debian 13, Windows Server 2022, and Windows Server 2025.
5. A real-host Windows 11 smoke test before marking Windows 11 as verified in
   release notes.

CI success on a floating `*-latest` image is not accepted as platform evidence.
