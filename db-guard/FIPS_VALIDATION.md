# FIPS 140-3 Cryptographic Module Validation Program (CMVP) Security Policy

This document defines the FIPS 140-3 Security Policy and Post-Quantum Transition documentation for the standalone `@vollcrypt/db-guard` package.

---

## 1. Cryptographic Module Specification

The Cryptographic Module (hereafter referred to as the "Module") is a software-only cryptographic module. 

### 1.1 Logical Boundary
The logical boundary of the module contains:
- **Node.js Wrapper**: Configured in [src/security.ts](file:///c:/Users/iTopya/Desktop/Project/vollcrypt/db-guard/node/src/security.ts) utilizing the Node.js built-in FIPS-compliant OpenSSL cryptographic engine.
- **Rust Core Wrapper**: Configured in [src/lib.rs](file:///c:/Users/iTopya/Desktop/Project/vollcrypt/db-guard/rust/src/lib.rs) utilizing FIPS-approved underlying primitives or CMVP-validated cryptographic hardware providers.

### 1.2 Physical Boundary
The physical boundary of the module is the physical container of the host computer system running the software wrapper (CPU, memory, storage, and motherboard).

---

## 2. Approved Modes of Operation

The module supports a FIPS-approved mode of operation. In this mode, only FIPS-approved algorithms may be utilized for data encryption, decryption, key derivation, and signature verification.

| Algorithm | Standard | Usage | Key Sizes / Strengths |
| :--- | :--- | :--- | :--- |
| **AES-GCM** | FIPS 197, SP 800-38D | Database Field Encryption and Decryption | 256-bit keys |
| **AES-KW** | RFC 3394, SP 800-38F | Local Key Envelope Wrapping (DEK wrap via KEK) | 256-bit keys |
| **HKDF-SHA256** | SP 800-56C | Blind Index Generation & Key Derivation | 256-bit strength |
| **Ed25519** | FIPS 186-5 | Threshold Break-Glass Signature Verification | 256-bit public keys |

---

## 3. Allowed Non-Approved Modes (Post-Quantum Transition)

For transitional security against future quantum attacks (Harvest Now, Decrypt Later threats), the module implements hybrid post-quantum key encapsulation mechanism schemas.

- **ML-KEM (FIPS 203)**: Formerly known as Kyber. Registered under NIST post-quantum standard FIPS 203.
- **Hybrid Negotiation**: ML-KEM is paired alongside classical FIPS-approved key agreement algorithms (X25519 / SP 800-56A) to maintain FIPS 140-3 conformance while acquiring post-quantum protection.

---

## 4. Cryptographic Self-Tests

The module executes power-up self-tests automatically upon initialization of the cryptographic services to verify the integrity and correct operation of all algorithmic engines.

### 4.1 Cryptographic Algorithm Known Answer Tests (KATs)
- **AES-GCM KAT**: Encrypts and decrypts a known test block. Verification checks that output matches pre-calculated ciphertext and tag.
- **AES-KW KAT**: Wraps and unwraps a known test key block. Verification checks that unwrapped output matches input.
- **HKDF KAT**: Derives a known output key material using a fixed entropy vector.
- **Ed25519 KAT**: Verifies a pre-computed message signature against a known public key.

If any self-test fails, the module enters an error state (`FAIL_CLOSED`), zeroizes all active keys in RAM, and blocks all cryptographic calls.

---

## 5. Key Zeroization (RAM Protection)

To prevent memory-leak attacks (such as Cold Boot attacks or memory core dumps), the module actively zeroizes all key material in RAM immediately after use.

- **Memory Erasure**: Key buffers (represented as Node `Buffer` or Rust `Vec<u8>`) are zeroized by writing null bytes (`0x00`) over the allocated memory block using `Buffer.fill(0)` in Node.js and the `Zeroize` trait in Rust.
- **Fail-Closed Erase**: Upon trigger of a rate limit violation or self-test failure, the `triggerFailClosed` routine immediately zeroizes the `ephemeralMasterKey`, the `SecureKeyCache` entries, and all registered active database keys.
