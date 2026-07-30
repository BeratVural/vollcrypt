# FIPS / PQC Validation Status

This document is a status note, not a CMVP Security Policy and not evidence of FIPS 140-3 validation.

## Current Status

`@vollcrypt/db-guard` is not a FIPS 140-3 validated cryptographic module. The repository does not currently contain a CMVP certificate, validated module boundary, power-up Known Answer Test implementation, or automated FIPS error-state enforcement for this package.

The package uses standard cryptographic primitives such as AES-GCM, AES key wrap, HKDF-SHA256, and signature verification through its Node/Rust dependencies. That implementation detail must not be represented as FIPS validation or certification.

## Post-Quantum Status

This package does not currently implement a validated post-quantum KEM/signature boundary. Any ML-KEM, ML-DSA, or hybrid post-quantum support elsewhere in the repository must be documented and validated in that component's own security boundary before it is claimed here.

## Allowed Wording

Use these statements until validation evidence exists:

- "Uses standard cryptographic primitives through Node/Rust cryptographic providers."
- "Not FIPS 140-3 validated."
- "FIPS validation and PQC validation are roadmap items, not current certifications."

## Requirements Before Any Future FIPS Claim

Before this package can claim FIPS 140-3 validation, the project must provide:

- A defined cryptographic module boundary.
- A referenced CMVP certificate or validated provider configuration.
- Power-up and conditional self-tests wired into runtime initialization.
- Fail-closed error-state behavior covered by tests.
- CI checks that exercise the validated mode on a supported platform.

Until those items are complete, product, README, package, and sales material must avoid "FIPS-compliant", "FIPS-certified", "FIPS-validated", and equivalent claims for `@vollcrypt/db-guard`.
