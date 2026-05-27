<div align="center">

# Vollcrypt

**Cross-platform, quantum-resistant cryptography workspace for Node.js, WebAssembly, and Rust**

[![CI](https://github.com/BeratVural/vollcrypt/actions/workflows/ci.yml/badge.svg)](https://github.com/BeratVural/vollcrypt/actions/workflows/ci.yml)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)
[![FIPS 203](https://img.shields.io/badge/PQC-FIPS%20203%20ML--KEM--768-8A2BE2)](https://csrc.nist.gov/pubs/fips/203/final)

</div>

---

Vollcrypt is a cryptographic library providing secure building blocks for end-to-end encrypted (E2EE) messaging systems and file transfer/storage tools. The core library is written in Rust and compiled to Node.js native bindings, WebAssembly, and native Rust.

## Documentation Modules

Explore the specific modules of Vollcrypt:

*   📩 **[Vollcrypt Messages Module Documentation (README-messages.md)](README-messages.md)** - Stable, E2EE messaging session managers, PCS ratchets, sealed sender, and transparency logs.
*   📁 **[Vollcrypt Files Module Documentation (README-files.md)](README-files.md)** - Active Development, streaming chunk-based encryption, and Merkle tree verification.

---

## Repository Structure

This repository is organized as a monorepo containing the following modules:

*   `vollcrypt-messages/`: The Rust implementation and bindings for E2EE messaging (Node.js and WebAssembly).
*   `vollcrypt-file/`: The Rust implementation and core logic for E2EE file/stream chunking and verification.

---

## Security Properties

| Property | Applied To | Mechanism | Guarantee / Protection |
| :--- | :--- | :--- | :--- |
| **Confidentiality** | Messages & Files | AES-256-GCM | Encrypted content cannot be read without the session/file key. Files are encrypted in chunk streams. |
| **Integrity** | Messages | AES-256-GCM tag + Transcript Hash Chain | Messages cannot be modified, reordered, replayed, or deleted without detection. |
| **Integrity** | Files | Merkle Tree over chunk authentication tags | Individual chunks cannot be swapped, reordered, or deleted. Allows verification of individual chunks without full download. |
| **Forward Secrecy** | Messages | Time-windowed WindowKey (HKDF) | Compromising a current key does not expose past session messages. |
| **Post-Compromise Security** | Messages | Ephemeral X25519 PCS ratchet | Session recovers automatically from key compromise within a few messages. |
| **Quantum Resistance** | Messages & Files | X25519 + ML-KEM-768 Hybrid KEM | Session/file key exchange resists both classical and quantum attacks. |
| **Sender Authenticity** | Messages & Files | Ed25519 signature on KEM ciphertext/metadata | Recipients can verify the authenticity of the sender and prevent MITM key substitution by the server. |
| **Sender Privacy** | Messages | Sealed Sender (ECDH + AES-GCM) | The server routes messages without knowing the sender's identity. |
| **Key Auditability** | Messages | Key Transparency log (signed hash chain) | Key modifications are append-only and public, preventing silent backdating of keys. |
| **MITM Detection** | Messages | Out-of-band Verification Codes (Numeric/Emoji) | Humans can easily verify the fingerprint of their keys to ensure no MITM is present. |
| **Password Derivation** | Messages & Files | Argon2id & PBKDF2 (100k iterations) | Derives high-entropy wrapping keys from user passwords to secure recovery seeds and keys. |
| **Key Wrapping** | Messages & Files | AES-256-KW (RFC 3394) | Protects sensitive keys (DEK, SRK, Mnemonics) when stored in insecure local storage. |

---

## Algorithms Used

| Purpose | Algorithm | Standard / Specification |
| :--- | :--- | :--- |
| **Symmetric Encryption** | AES-256-GCM | NIST SP 800-38D |
| **Classical Key Exchange** | X25519 ECDH | RFC 7748 |
| **Post-Quantum KEM** | ML-KEM-768 | NIST FIPS 203 |
| **Digital Signatures** | Ed25519 | RFC 8032 |
| **Key Derivation (KDF)** | HKDF-SHA256 | RFC 5869 |
| **Password Hashing / KDF** | Argon2id & PBKDF2-SHA256 | OWASP Recommendation / RFC 8018 |
| **Key Wrapping** | AES-256-KW | RFC 3394 |
| **Recovery Phrase** | BIP-39 (24 words, 256-bit entropy) | BIP-39 |

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

| Tool | Version | Purpose |
| :--- | :--- | :--- |
| Rust | stable (≥ 1.76) | Core and bindings |
| wasm-pack | latest | WASM build |
| Node.js | ≥ 18 | Node.js binding and examples |
| npm | ≥ 9 | Package management |

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
