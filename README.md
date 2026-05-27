<div align="center">

# Vollcrypt

**Cross-platform, quantum-resistant cryptography workspace for Node.js, WebAssembly, and Rust**

[![CI](https://github.com/BeratVural/vollcrypt/actions/workflows/ci.yml/badge.svg)](https://github.com/BeratVural/vollcrypt/actions/workflows/ci.yml)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)
[![FIPS 203](https://img.shields.io/badge/PQC-FIPS%20203%20ML--KEM--768-8A2BE2)](https://csrc.nist.gov/pubs/fips/203/final)

</div>

---

Vollcrypt is a cryptographic library providing secure building blocks for end-to-end encrypted (E2EE) messaging systems and file transfer tools. The core library is written in Rust and compiled to Node.js native bindings, WebAssembly, and native Rust.

## Repository structure

This repository is organized as a monorepo containing multiple modules:

*   **`vollcrypt-messages/` (Stable)**: Cryptographic primitives and session management for secure messaging. Includes hybrid PQC KEM handshakes, PCS ratcheting, sealed sender, transcript verification, and key transparency logs.
    *   *Documentation:* [vollcrypt-messages/README.md](file:///c:/Users/iTopya/Desktop/Project/vollcrypt/vollcrypt-messages/README.md)
    *   *NPM Scopes:* `@vollcrypt/messages-node` and `@vollcrypt/messages-wasm`
*   **`vollcrypt-file/` (Under Active Development)**: Encrypted file transmission, stream encryption/decryption, chunk-based encryption, and Merkle tree verification core.

---

## Security Properties

| Property                 | Mechanism                                         | Guarantee                                                        |
| ------------------------ | ------------------------------------------------- | ---------------------------------------------------------------- |
| Confidentiality          | AES-256-GCM                                       | Messages/files cannot be read without the session key            |
| Integrity                | AES-256-GCM auth tag + Transcript hash            | Data cannot be modified or reordered without detection           |
| Forward Secrecy          | Time-windowed WindowKey (HKDF-derived per window) | Compromising a current key does not expose past data             |
| Post-Compromise Security | Ephemeral X25519 PCS ratchet                      | System recovers from key compromise within N messages            |
| Quantum Resistance       | X25519 + ML-KEM-768 hybrid KEM                    | Session establishment resists both classical and quantum attacks |
| Sender Authenticity      | Ed25519 signature on KEM ciphertext               | The server cannot substitute a different sender's key            |
| Sender Privacy           | Sealed Sender (ephemeral ECDH + AES-GCM)          | The server routes messages without knowing the sender's identity |
| Key Authenticity         | Key Transparency log (Ed25519-signed hash chain)  | Key changes are auditable and cannot be silently backdated       |
| MITM Detection           | Verification codes (SHA-256 of public key pair)   | Users can confirm keys out of band                               |

---

## Algorithms Used

| Purpose                | Algorithm                          | Standard        |
| ---------------------- | ---------------------------------- | --------------- |
| Symmetric encryption   | AES-256-GCM                        | NIST SP 800-38D |
| Classical key exchange | X25519 ECDH                        | RFC 7748        |
| Post-quantum KEM       | ML-KEM-768                         | NIST FIPS 203   |
| Digital signatures     | Ed25519                            | RFC 8032        |
| Key derivation         | HKDF-SHA256                        | RFC 5869        |
| Password derivation    | PBKDF2-SHA256 (100 000 iterations) | RFC 8018        |
| Key wrapping           | AES-256-KW                         | RFC 3394        |
| Recovery phrase        | BIP-39 (24 words, 256-bit entropy) | BIP-39          |

---

## License Configuration

Create a `.env` file in your application root using the template below:

```env
VOLLCRYPT_LICENSE_KEY=your_license_key
VOLLCRYPT_LICENSE_SERVER=https://api.vollcrypt.com
VOLLCRYPT_LICENSE_REPORT_INTERVAL_MS=3600000
VOLLCRYPT_LICENSE_OFFLINE_FALLBACK=true
```

---

## Building From Source

### Prerequisites

| Tool      | Version          | Purpose                      |
| --------- | ---------------- | ---------------------------- |
| Rust      | stable (≥ 1.76) | Core and bindings            |
| wasm-pack | latest           | WASM build                   |
| Node.js   | ≥ 18            | Node.js binding and examples |
| npm       | ≥ 9             | Package management           |

### Steps

```bash
# Clone the repository
git clone https://github.com/BeratVural/vollcrypt.git
cd vollcrypt

# Run all workspace cargo tests (core and file modules)
cargo test --workspace

# Check formatting and lints
cargo fmt --all -- --check
cargo clippy --workspace -- -D warnings

# Build Node.js native addon for messages
cd vollcrypt-messages/node && npm install && npm run build && cd ../..

# Build WebAssembly package for messages
cd vollcrypt-messages/wasm && wasm-pack build --target web --out-dir pkg && cd ../..
```

---

## Licensing

Vollcrypt is licensed under the GPL-3.0 License.
