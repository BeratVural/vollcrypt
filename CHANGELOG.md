# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-04-28

### Added

- **Core cryptographic primitives**
  - Ed25519 keypair generation, signing, and verification
  - X25519 keypair generation and ECDH key exchange
  - AES-256-GCM encryption/decryption with optional AAD
  - AES-256-GCM padded and chunked variants
  - File-based chunked encryption/decryption (Node.js)
  - HKDF-SHA256 and PBKDF2-SHA256 key derivation
  - AES-256-KW key wrapping/unwrapping
  - BIP-39 mnemonic generation and seed derivation

- **Post-quantum cryptography**
  - ML-KEM-768 (NIST FIPS 203) keypair generation, encapsulation, decapsulation
  - Hybrid KEM (X25519 + ML-KEM-768)
  - Authenticated KEM (hybrid KEM + Ed25519 signature)

- **Session security**
  - Session Root Key (SRK) and WindowKey derivation chain
  - Binary envelope packing/unpacking
  - PCS ratchet (post-compromise security via ephemeral X25519)
  - Transcript hashing (SHA-256 chain for message ordering integrity)

- **Privacy and verification**
  - Sealed sender (sender identity encrypted inside message)
  - Key verification codes (numeric and emoji)
  - Fingerprint computation and comparison

- **Key management**
  - Key Transparency log (append-only, Ed25519-signed, hash-linked)
  - Device registry with revocation support

- **Platform targets**
  - `@vollcrypt/node` — Node.js native binding via NAPI-RS
  - `@vollcrypt/wasm` — WebAssembly binding via wasm-bindgen
  - `vollcrypt-core` — Pure Rust crate

- **License tracking**
  - MAU-based license validation and usage reporting
  - Offline fallback mode
