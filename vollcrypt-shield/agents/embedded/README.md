# Vollcrypt Shield Embedded

`vollcrypt-shield-embedded` is an independent, zero-allocation `#![no_std]`
integrity-state library for long-lived embedded devices. It does not depend on
Wave, an operating system, a network stack, or another Vollcrypt package.

The current foundation provides:

- fixed-capacity, deterministic SHA-256 Merkle measurements;
- a monotonic, tamper-evident audit-chain head;
- signed-checkpoint bytes with versioned SHA-256 and ML-DSA-65 identifiers;
- a hardware/secure-element signer trait that keeps private keys outside the
  library;
- scope-local containment that blocks baseline replacement until a signed,
  bounded break-glass command is verified; and
- compile checks for Cortex-M33, Cortex-M4, and RV32 targets.

The application supplies component identifiers, digests, monotonic counters,
persistent storage, notifications, and an ML-DSA-65 implementation through the
documented traits. A software counter or key stored in the same writable trust
domain as monitored firmware is a weak trust root. Cortex-M33 deployments
should place counters and signing behind TrustZone-M or a secure element.

This crate does not implement a bootloader, flash driver, network isolation,
device shutdown, or remote fleet control. Commercial centralized fleet
management is described publicly but implemented in a separate private
repository.

Licensed under `GPL-3.0-only OR LicenseRef-Commercial`.
