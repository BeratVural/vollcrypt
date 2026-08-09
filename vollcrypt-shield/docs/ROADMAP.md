# Shield Development Roadmap

This document is the ordered engineering backlog for Shield. A checked item
means that its implementation and required validation gate are complete. A
platform or capability is never promoted based on compilation alone.

## Platform qualification

- [x] Ubuntu 26.04 LTS x86_64: Rust, Node binding, Viewer CI, and unrestricted
  real-host filesystem validation.
- [ ] Debian 13 x86_64: agent/CLI, Node binding, and Viewer CI; then unrestricted
  watcher and package smoke tests.
- [ ] Windows 11 ARM64: Rust/CLI, Node binding, and Viewer qualification; then a
  signed real-device installer smoke test.
- [ ] Fedora, RHEL, Rocky Linux, and AlmaLinux: pinned CI images, native package
  builds, and real-host smoke evidence before support promotion.

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
- [ ] Add crash recovery, power-loss, locked-file, junction/reparse-point, and
  cross-volume rollback tests on real Windows hosts.

## Container integrity

- [ ] Add live containerd and Docker event monitoring to the host agent.
- [ ] Add a sidecar integration with an explicitly lower assurance label than
  host-level monitoring.
- [ ] Add a Kubernetes admission controller that verifies signed image evidence
  before admission and fails closed under a bounded, documented policy.

## Database integrity

- [ ] Implement PostgreSQL and MySQL adapters using consistent read-only
  snapshots and the existing canonical record-source contract.
- [ ] Add optional db-guard enhanced context through an explicit versioned
  adapter; standalone Shield DB behavior must remain independent.
- [ ] Qualify the commercial PostgreSQL backend against a disposable,
  TLS-enabled staging database without publishing private implementation code.

## Release and operations

- [ ] Add signed native packages and installation smoke tests for every promoted
  Linux distribution and Windows architecture.
- [ ] Add upgrade, downgrade-rejection, state migration, backup restoration, and
  break-glass recovery drills to release evidence.
- [ ] Add long-running watcher resource and notification-delivery soak tests.
- [x] Define deprecation windows for operating systems, protocol versions, and
  package formats before removing support.
