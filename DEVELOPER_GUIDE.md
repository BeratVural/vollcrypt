# Vollcrypt Developer Documentation & Architecture Guide

Welcome to the **Vollcrypt** developer documentation. Vollcrypt is a high-performance, memory-safe, and quantum-resistant cryptographic engine built in Rust, specifically designed for the VollChat end-to-end encrypted (E2EE) messaging platform.

This comprehensive guide is intended for security engineers, backend developers, and frontend developers who need to integrate, maintain, or extend the Vollcrypt cryptographic library.

---

## 🏗️ 1. Architecture and Monorepo Structure

Vollcrypt is designed to be platform-agnostic, running identical cryptographic primitives across backend servers, web browsers, and mobile environments. To achieve this, the project is structured as a Cargo workspace (Monorepo) comprising three core spaces:

1. **`core` (`vollcrypt-core`)**: The pure Rust cryptographic heart of the application. It contains all mathematical operations, cryptographic algorithms, packet formatting, and key derivation logic. It operates in a completely isolated environment with `no_std` compatibility where possible, meaning it has zero dependencies on network or file I/O operations.
2. **`wasm` (WebAssembly Binding)**: Acts as the bridge for web browsers (React, Next.js, Service Workers) and React Native environments. It compiles the `core` module into WebAssembly using `wasm-bindgen`, exposing asynchronous and synchronous JavaScript functions for client-side encryption.
3. **`node` (Node.js Native Binding)**: Designed for backend servers (such as NestJS). It compiles the `core` into a native C++ N-API binary module (`.node`). This allows the backend to perform extremely fast server-side cryptographic checks (like Ed25519 signature validations) directly within the V8 Engine without the overhead of WASM instantiation.

---

## 🛡️ 2. Cryptographic Standards & Primitives

Vollcrypt strictly adheres to modern, "Best-Practice" cryptographic suites. Legacy or compromised algorithms (like RSA, AES-CBC, MD5, SHA-1) are strictly omitted.

| Purpose                           | Algorithm Used           | Technical Details                                                                                                                                                                                 |
| :-------------------------------- | :----------------------- | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Symmetric Encryption**          | **AES-256-GCM**          | Used for bulk data and message encryption. Provides Authenticated Encryption with Associated Data (AEAD). It utilizes a 12-byte random IV (Nonce) and a 16-byte Authentication Tag (MAC).         |
| **Asymmetric / Key Exchange**     | **X25519 + ML-KEM-768**  | Hybrid Key Encapsulation Mechanism. Combines classical Elliptic Curve Diffie-Hellman (X25519) with NIST's FIPS 203 standardized Post-Quantum KEM (Module-Lattice KEM).                            |
| **Digital Signatures & Identity** | **Ed25519**              | Used for user/device identity verification and guaranteeing message origin authenticity. Ed25519 was chosen over ECDSA to prevent random number generator vulnerabilities.                        |
| **Key Derivation (KDF)**          | **HKDF-SHA256 & PBKDF2** | HKDF is used to derive sub-keys from shared secrets. PBKDF2 (with 100,000 iterations) is used exclusively for deriving operational keys from user passwords.                                      |
| **Entropy & Recovery**            | **BIP39**                | Standardized 24-word (256-bit entropy) English mnemonic phrases used for paper keys and disaster recovery of the master identity.                                                                 |
| **Key Wrapping**                  | **AES-256-KW**           | Compliant with RFC 3394. Used to safely encrypt and wrap highly sensitive keys (like the DEK or SRK) before they are stored on disk (IndexedDB or LocalStorage) using the user's Master Password. |

---

## 🔄 3. Key Management Lifecycle & Data Flow

Vollcrypt does not use a single, static key for conversations. Instead, it implements a highly dynamic, time-rotating key architecture to ensure **Forward Secrecy (FS)** and **Post-Compromise Security (PCS)**.

### 3.1. The User Key Hierarchy

Every user relies on the following key hierarchy during a session:

1. **Paper Key (BIP39 - 24 Words)**: The root of trust. Generated once during onboarding and physically stored by the user. If a user loses all devices, this key can restore their Identity Keys and DEK.
2. **Master Password**: A daily unlock password used to decrypt the DEK.
3. **DEK (Data Encryption Key)**: A symmetrical AES-256 key kept purely in volatile memory (RAM) during an active session. It is the core operational key used to decrypt conversation keys.
4. **Identity Key (IK)**: An Ed25519 keypair identifying the specific device or user.

### 3.2. Initiating a Conversation (The Hybrid KEM Handshake)

When Alice wants to start a secure E2EE chat with Bob, they establish a shared secret resilient to both classical and quantum attacks (`core/src/pqc.rs`):

1. **Fetch Public Keys**: Alice retrieves Bob's classical `X25519 Public Key` and quantum `ML-KEM Encapsulation Key` from the server.
2. **Encapsulate**: Alice runs `hybrid_kem_encapsulate(&bob_x25519_pub, &bob_mlkem_pub)`.
3. **Output**: The function outputs an Encapsulated Ciphertext (to be sent to Bob) and a locally computed 32-byte **Hybrid Shared Secret**.
4. **Decapsulate**: Bob receives the ciphertext, runs `hybrid_kem_decapsulate()`, and generates the exact same 32-byte Hybrid Shared Secret on his device.

### 3.3. Time-Windowed Encryption (WindowKey Concept)

To isolate blast radius if a key is compromised, VollChat rotates keys based on time windows:

1. **SRK (Session Root Key)**: Derived via HKDF-SHA256 from the Hybrid Shared Secret combined with the unique `chat_id` and the context string `vollchat-srk-v1`.
2. **Window Key**: Instead of using the SRK directly to encrypt messages, the client calculates the current `Window Index` (e.g., current UNIX time divided by a 1-hour window size). It then derives a temporary `Window Key` from the SRK specifically for that time window.
3. **Key Ratcheting / Revocation**: When the clock pushes into a new time window, a new Window Key is computed, and the old Window Key is proactively and permanently deleted from RAM (`revokeWindow`).

### 3.4. The Binary Message Envelope

When a payload is encrypted via AES-256-GCM, Vollcrypt formats it into a strict binary envelope (`core/src/envelope.rs`). Before transmission, the byte array looks exactly like this:

1. `[4 Bytes]`: **Window Index** (Big-Endian format). Tells the receiving client which Window Key to derive for decryption.
2. `[12 Bytes]`: **AES IV / Nonce**. Cryptographically secure random bytes generated per message.
3. `[32 Bytes]`: **AAD Hash**. A SHA-256 hash of the metadata (Message ID, Sender ID, timestamp). Ensures the message hasn't been moved or attributed to another sender.
4. `[X Bytes]`: **Ciphertext**. The actual encrypted message data.
5. `[16 Bytes]`: **Authentication Tag**. The GCM MAC ensuring the ciphertext and AAD have not been tampered with.

---

## 🚨 4. Critical Security Mandates for Developers

When integrating the `wasm` or `node` bindings into a JavaScript/TypeScript environment, you **MUST** adhere to the following rules to prevent catastrophic security vulnerabilities.

### Rule 1: Memory Isolation via `zeroize()`

In the Rust core, sensitive data (like unencrypted seeds, private keys, or raw passwords) are actively overwritten with zeroes in memory immediately after their use. This is done via the `zeroize` crate to defend against RAM scraping and memory dumps.

- **Contributor Note**: If you add new cryptographic functions in Rust that utilize intermediate arrays (`Vec<u8>` or `[u8; N]`) for secrets, you must implement the `ZeroizeOnDrop` trait or manually call `.zeroize()` before the variable goes out of scope.

### Rule 2: Non-Extractable CryptoKeys (Web Crypto API)

When the WASM layer returns raw bytes for the DEK or SRK to the Javascript thread, you must immediately import these keys into the browser's native `SubtleCrypto` API with `extractable: false`.

```typescript
// ✅ CORRECT: Key cannot be stolen via XSS once imported
const dekAes = await crypto.subtle.importKey(
  "raw",
  rawDekArrayBuffer,
  { name: "AES-GCM" },
  false, // MUST BE FALSE
  ["encrypt", "decrypt"],
);
// Overwrite the raw array buffer immediately
rawDekArrayBuffer.fill(0);
```

Never save raw `Uint8Array` keys to IndexedDB, LocalStorage, or Redux/React State.

### Rule 3: Never Hardcode or Reuse IVs (Nonces)

The `encrypt_aes256gcm` function in Rust internally handles IV generation using `OsRng.fill_bytes(&mut nonce)`. You should never attempt to pass an IV manually into the encryption function from JavaScript. AES-GCM fails catastrophically (leaking the authentication key) if an IV is reused for identical keys.

---

## 💻 5. Core Module Directory Structure (`core/src/`)

For those contributing to the internal cryptography:

- `pqc.rs`: Contains the ML-KEM-768 logic and the `hybrid_kem_encapsulate()` / `hybrid_kem_decapsulate()` functions combining ECDH and KEM.
- `symmetric.rs`: AES-256-GCM functions for payload encryption (`encrypt_aes256gcm`, `decrypt_aes256gcm`).
- `kdf.rs`: Key Derivation Functions including `derive_hkdf`, `derive_pbkdf2` (fixed to 100k iterations), and `derive_window_key`.
- `keys.rs`: Operations for Ed25519 signing, verification, and classical X25519 ECDH keypair generation.
- `envelope.rs`: Logic for packing and unpacking the binary envelope (`[WindowIndex][IV][AAD][Ciphertext][Tag]`).
- `bip39.rs`: Mnemonic phrase generation and dictionary validation.
- `wrap.rs`: Secure implementations of AES-256-KW (Key Wrapping) mapped to RFC 3394.
- `device.rs`: Device registry systems for managing authorized device public keys and revocation logic.

---

## 🛠 6. Build Instructions

As a Cargo Workspace, compilation is segmented based on the target execution environment.

**Running the Test Suite**
To verify all cryptographic proofs, hashing predictability, and memory safety:

```bash
# Run tests for all packages in the workspace
cargo test --workspace
```

**Building for Frontend (WebAssembly)**
Compiles the `wasm` package for use in React, Next.js, or Vite environments:

```bash
cd wasm
wasm-pack build --target web --out-dir pkg
```

**Building for Backend (Node.js)**
Compiles the native N-API module for high-speed backend verification:

```bash
cd node
npm install
npm run build
```

---

_Vollcrypt is built with security first. Do not downgrade standards or bypass cryptographic validation steps for the sake of speed or convenience._
