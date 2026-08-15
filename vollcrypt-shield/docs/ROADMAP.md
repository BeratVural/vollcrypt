# Shield Development Roadmap

This document is the ordered engineering backlog for Shield. A checked item
means that its implementation and required validation gate are complete. A
platform or capability is never promoted based on compilation alone.

## Platform qualification

- [x] Ubuntu 26.04 LTS x86_64: Rust, Node binding, Viewer CI, and unrestricted
  real-host filesystem validation.
- [x] Debian 13 x86_64: agent/CLI, Node binding, and Viewer CI; then unrestricted
  watcher and package smoke tests.
- [x] Windows 11 ARM64: Rust/CLI, Node binding, Viewer, strict recovery, and
  unsigned real-device installer qualification.
- [ ] Promote Windows 11 ARM64 only after retaining an exact-commit installer
  smoke with a trusted Authenticode signature.
- [x] Fedora 44, Rocky Linux 9.8, and AlmaLinux 9.8: pinned CI images, native
  RPM builds, and retained full-VM systemd/watcher/package smoke evidence.
- [ ] RHEL 9: native RPM build plus retained smoke evidence from a licensed
  real host before support promotion. UBI evidence is not accepted as RHEL.
  The fail-closed self-hosted qualification workflow is ready; promotion awaits
  a licensed runner carrying the `rhel-9` and `shield-qualification` labels.

## Interactive terminal interface

- [x] Build a full-screen, read-only TUI for headless Linux using `ratatui` and
  `crossterm` while retaining the current non-interactive `dashboard --once`
  output for scripts and support captures.
- [x] Provide stable Overview, Scopes, Events, Files, Witnesses, and
  Notifications views with keyboard navigation and accessible no-color mode.
- [x] Show absolute changed paths and bounded, digest-verified text diffs without
  reading unverified or oversized content into the terminal.
- [x] Keep policy activation, break-glass, baseline replacement, and destructive
  operations outside the first TUI delivery. Control actions require a separate
  threat model, confirmation design, and authorization boundary.
- [x] Add terminal-size, resize, malformed-event, high-volume-event, and
  non-interactive regression tests.

## Active response

- [x] Implement Windows quarantine and rollback only after owners, DACLs, SACLs,
  integrity labels, alternate data streams, timestamps, and relevant attributes
  can be captured and restored atomically without weakening access control.
- [x] Add crash recovery, power-loss, locked-file, junction/reparse-point, and
  cross-volume rollback tests on real Windows hosts.
  The strict gate in `WINDOWS_RECOVERY_QUALIFICATION.md` passes on Windows
  Server 2022/2025 x86_64 and Windows 11 ARM64 with retained host, privilege,
  volume, and test-log evidence.

## Container integrity

- [x] Add live containerd and Docker event monitoring to the host agent.
- [x] Add a sidecar integration with an explicitly lower assurance label than
  host-level monitoring.
- [x] Add a Kubernetes admission controller that verifies signed image evidence
  before admission and fails closed under a bounded, documented policy.

## Database integrity

- [x] Implement PostgreSQL and MySQL adapters using consistent read-only
  snapshots and the existing canonical record-source contract. Disposable
  TLS baseline/match/drift evidence is recorded in
  `DATABASE_QUALIFICATION.md`.
- [x] Add optional db-guard enhanced context through an explicit versioned
  adapter; standalone Shield DB behavior must remain independent.
- [x] Qualify the commercial PostgreSQL backend against a disposable,
  TLS 1.3 staging database without publishing private implementation code.
  The private commit and job evidence are recorded in
  `DATABASE_QUALIFICATION.md`.

## Release and operations

- [x] Build, attest, install, verify, and remove native packages for every
  promoted Linux distribution and Windows architecture in the release gate.
- [x] Fail release publication closed on missing trusted Authenticode or pinned
  detached-GPG signing credentials, and smoke-test detached signing with an
  ephemeral CI key.
- [ ] Configure the maintainer-controlled production GPG identity and trusted
  Authenticode certificate, then retain the first exact-commit signed release
  evidence. Signing secrets must never be generated in or committed to CI.
- [x] Add upgrade, downgrade-rejection, state migration, backup restoration, and
  break-glass recovery drills to release evidence. The named cross-platform and
  Unix vault drills are required by both CI and the release workflow; see
  `RELEASE_OPERATIONS.md`.
- [x] Add long-running watcher resource and notification-delivery soak tests.
  Every change runs a bounded smoke; releases require five minutes, and the
  scheduled/manual workflow runs fifteen minutes while bounding RSS and file
  descriptor growth and verifying log, webhook, IPC, and signed audit delivery.
- [x] Define deprecation windows for operating systems, protocol versions, and
  package formats before removing support.
