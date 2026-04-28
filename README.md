<div align="center">

# Vollcrypt

**Cross-platform, quantum-resistant cryptography engine for Node.js, WebAssembly, and Rust**

[![CI](https://github.com/BeratVural/vollcrypt/actions/workflows/ci.yml/badge.svg)](https://github.com/BeratVural/vollcrypt/actions/workflows/ci.yml)
[![npm (node)](https://img.shields.io/npm/v/@vollcrypt/node?label=%40vollcrypt%2Fnode&color=cb3837)](https://www.npmjs.com/package/@vollcrypt/node)
[![npm (wasm)](https://img.shields.io/npm/v/@vollcrypt/wasm?label=%40vollcrypt%2Fwasm&color=cb3837)](https://www.npmjs.com/package/@vollcrypt/wasm)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)
[![FIPS 203](https://img.shields.io/badge/PQC-FIPS%20203%20ML--KEM--768-8A2BE2)](https://csrc.nist.gov/pubs/fips/203/final)

</div>

---

Vollcrypt is a cryptography library — not a product. It provides the cryptographic primitives needed to build secure end-to-end encrypted (E2EE) messaging systems, file transfer tools, or any application that needs modern, post-quantum-ready cryptography.

The same Rust core is compiled to three targets:

| Target           | Package             | Use Case                     |
| ---------------- | ------------------- | ---------------------------- |
| Node.js (native) | `@vollcrypt/node` | NestJS, Express, server-side |
| WebAssembly      | `@vollcrypt/wasm` | React, Next.js, browser      |
| Rust             | `vollcrypt-core`  | Direct Rust integration      |

---

## Table of Contents

- [Why Vollcrypt](#why-vollcrypt)
- [Security Properties](#security-properties)
- [What It Provides](#what-it-provides)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [API Reference](#api-reference)
  - [Identity and Key Exchange](#identity-and-key-exchange)
  - [Post-Quantum Cryptography](#post-quantum-cryptography)
  - [Symmetric Encryption](#symmetric-encryption)
  - [Key Derivation](#key-derivation)
  - [Key Management](#key-management)
  - [Session Security](#session-security)
  - [Sealed Sender](#sealed-sender)
  - [Key Verification Codes](#key-verification-codes)
  - [Key Transparency Log](#key-transparency-log)
  - [Device Registry](#device-registry)
- [License Configuration](#license-configuration)
- [Full E2EE Flow Example](#full-e2ee-flow-example)
- [Building From Source](#building-from-source)
- [Architecture](#architecture)
- [Security Considerations](#security-considerations)
- [Licensing](#licensing)
- [Contributing](#contributing)

---

## Why Vollcrypt

Most cryptography libraries give you low-level primitives and leave you to wire them together correctly. Vollcrypt goes one step further: it provides the higher-level building blocks — hybrid KEM handshakes, time-windowed forward secrecy, post-compromise security ratchets, sealed sender flows, key verification codes — while keeping each primitive independently accessible and testable.

**What makes it different:**

- **Hybrid post-quantum KEM** — X25519 combined with ML-KEM-768 (NIST FIPS 203). Breaking one does not break the session.
- **Post-Compromise Security** — Unlike systems that only offer forward secrecy, Vollcrypt implements a ratchet mechanism. If a session key is compromised, the system heals itself within a configurable number of messages.
- **Sealed Sender** — Sender identity is encrypted inside the message. The server routes messages without knowing who sent them.
- **Key Transparency** — Every public key publication is recorded in an append-only, hash-linked, Ed25519-signed log. Key changes cannot be silently backdated.
- **Verification Codes** — Users can confirm each other's keys out of band using short numeric or emoji codes, defeating MITM attacks at the human layer.
- **Single core, three targets** — The same Rust logic runs in Node.js, WebAssembly, and native Rust. No divergence between environments.

---

## Security Properties

| Property                 | Mechanism                                         | Guarantee                                                        |
| ------------------------ | ------------------------------------------------- | ---------------------------------------------------------------- |
| Confidentiality          | AES-256-GCM                                       | Messages cannot be read without the session key                  |
| Integrity                | AES-256-GCM auth tag + Transcript hash            | Messages cannot be modified or reordered without detection       |
| Forward Secrecy          | Time-windowed WindowKey (HKDF-derived per window) | Compromising a current key does not expose past messages         |
| Post-Compromise Security | Ephemeral X25519 PCS ratchet                      | System recovers from key compromise within N messages            |
| Quantum Resistance       | X25519 + ML-KEM-768 hybrid KEM                    | Session establishment resists both classical and quantum attacks |
| Sender Authenticity      | Ed25519 signature on KEM ciphertext               | The server cannot substitute a different sender's key            |
| Sender Privacy           | Sealed Sender (ephemeral ECDH + AES-GCM)          | The server routes messages without knowing the sender's identity |
| Key Authenticity         | Key Transparency log (Ed25519-signed hash chain)  | Key changes are auditable and cannot be silently backdated       |
| MITM Detection           | Verification codes (SHA-256 of public key pair)   | Users can confirm keys out of band                               |

**Algorithms used:**

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

**Algorithms explicitly excluded:** RSA, ECDSA, AES-CBC, AES-ECB, MD5, SHA-1, DH under 2048 bits.

---

## What It Provides

### Core Primitives

- Ed25519 keypair generation, signing, and verification
- X25519 keypair generation and ECDH
- ML-KEM-768 keypair generation, encapsulation, and decapsulation
- AES-256-GCM encryption and decryption with optional AAD
- HKDF-SHA256 and PBKDF2-SHA256 key derivation
- AES-256-KW key wrapping and unwrapping
- BIP-39 mnemonic generation and seed derivation

### Session Building Blocks

- Hybrid KEM handshake (X25519 + ML-KEM-768)
- Authenticated KEM (hybrid KEM + Ed25519 signature — closes MITM on key exchange)
- Time-windowed Session Root Key → WindowKey derivation chain
- Binary envelope packing: `[4B window_index][12B IV][32B AAD hash][ciphertext][16B auth tag]`
- PCS ratchet (ephemeral X25519 ratchet for post-compromise recovery)

---

## License Configuration

Create a `.env` file using the template below:

```
VOLLCRYPT_LICENSE_KEY=
VOLLCRYPT_LICENSE_SERVER=https://api.vollsign.io
VOLLCRYPT_LICENSE_REPORT_INTERVAL_MS=3600000
VOLLCRYPT_LICENSE_OFFLINE_FALLBACK=true
```

The Node.js package reads these values on startup and will validate the license automatically.
- Transcript hashing (SHA-256 chain over message sequence — detects reordering and deletion)
- Sealed sender (sender identity hidden from server)

### Key Management

- Key Transparency log (append-only, Ed25519-signed, hash-linked)
- Verification codes (numeric and emoji, derived from public key pair + conversation ID)
- Device registry with revocation

---

## Installation

### Node.js

```bash
npm install @vollcrypt/node
```

Prebuilt native binaries are provided for:

- Linux x64 (`linux-x64-gnu`)
- macOS x64 (`darwin-x64`)
- Windows x64 (`win32-x64-msvc`)

### WebAssembly (Browser / React Native)

```bash
npm install @vollcrypt/wasm
```

### Rust

```toml
# Cargo.toml
[dependencies]
vollcrypt-core = { git = "https://github.com/BeratVural/vollcrypt.git" }
```

Or in a workspace:

```toml
vollcrypt-core = { path = "../vollcrypt/core" }
```

---

## Quick Start

### Node.js — Generate Keys and Encrypt a Message

```ts
import {
  generateEd25519Keypair,
  generateX25519Keypair,
  encryptAesGcm,
  decryptAesGcm,
} from '@vollcrypt/node';
import crypto from 'crypto';

// Identity keypair
const [identitySecret, identityPublic] = generateEd25519Keypair();

// Session key (in practice, derived via KEM handshake)
const sessionKey = crypto.randomBytes(32);
const plaintext  = Buffer.from('Hello, Vollcrypt');

// Encrypt
const ciphertext = encryptAesGcm(sessionKey, plaintext, null);

// Decrypt
const decrypted = decryptAesGcm(sessionKey, ciphertext, null);
console.log(decrypted.toString()); // Hello, Vollcrypt
```

### WebAssembly — Browser

```ts
import init, {
  generateEd25519Keypair,
  encryptAesGcm,
  decryptAesGcm,
} from '@vollcrypt/wasm';

await init();

const [identitySecret, identityPublic] = generateEd25519Keypair();
const sessionKey = crypto.getRandomValues(new Uint8Array(32));
const plaintext  = new TextEncoder().encode('Hello, Vollcrypt');

const ciphertext = encryptAesGcm(sessionKey, plaintext, null);
const decrypted  = decryptAesGcm(sessionKey, ciphertext, null);
console.log(new TextDecoder().decode(decrypted));
```

### Rust

```rust
use vollcrypt_core::{
    generate_ed25519_keypair,
    encrypt_aes256gcm,
    decrypt_aes256gcm,
};

let (_secret, _public) = generate_ed25519_keypair().unwrap();
let key       = [0u8; 32]; // use OsRng in production
let plaintext = b"Hello, Vollcrypt";

let ciphertext = encrypt_aes256gcm(&key, plaintext, None).unwrap();
let decrypted  = decrypt_aes256gcm(&key, &ciphertext, None).unwrap();
assert_eq!(plaintext, decrypted.as_slice());
```

---

## API Reference

All examples below use the Node.js binding. The WASM binding exposes identical function names with `snake_case` convention. The Rust API mirrors the same logic in the `vollcrypt_core` crate.

---

### Identity and Key Exchange

#### `generateEd25519Keypair() → [secretKey, publicKey]`

Generates a new Ed25519 keypair. Use for user and device identity, message signing, and Key Transparency log entries.

```ts
const [secretKey, publicKey] = generateEd25519Keypair();
// secretKey: Buffer (32 bytes) — keep private, never transmit
// publicKey: Buffer (32 bytes) — safe to publish
```

#### `signMessage(secretKey, message) → signature`

Signs a message with an Ed25519 private key.

```ts
const message   = Buffer.from('data to sign');
const signature = signMessage(secretKey, message);
// signature: Buffer (64 bytes)
```

#### `verifySignature(publicKey, message, signature) → boolean`

Verifies an Ed25519 signature. Returns `true` only if the signature is valid for the given key and message.

```ts
const valid = verifySignature(publicKey, message, signature);
```

#### `generateX25519Keypair() → [secretKey, publicKey]`

Generates a new X25519 keypair. Use for ECDH key exchange and session establishment.

```ts
const [x25519Secret, x25519Public] = generateX25519Keypair();
```

---

### Post-Quantum Cryptography

#### `generateMlKem768Keypair() → [encapsKey, decapsKey]`

Generates a new ML-KEM-768 keypair (NIST FIPS 203).

```ts
const [encapsKey, decapsKey] = generateMlKem768Keypair();
// encapsKey: Buffer — share with peers for encapsulation
// decapsKey: Buffer — keep private
```

#### `hybridKemEncapsulate(recipientX25519Pub, recipientMlkemPub) → [ciphertext, sharedSecret]`

Performs a hybrid KEM encapsulation combining X25519 ECDH and ML-KEM-768. Produces a shared secret that is secure as long as either the classical or the post-quantum component is unbroken.

```ts
const [ciphertext, sharedSecret] = hybridKemEncapsulate(
  bobX25519Public,
  bobMlkemEncapsKey,
);
// ciphertext: Buffer — send to recipient
// sharedSecret: Buffer (32 bytes) — use to derive session keys
```

#### `hybridKemDecapsulate(ourX25519Secret, ciphertext, ourMlkemDecapsKey) → sharedSecret`

Decapsulates a hybrid KEM ciphertext. Produces the same shared secret as the sender.

```ts
const sharedSecret = hybridKemDecapsulate(
  myX25519Secret,
  receivedCiphertext,
  myMlkemDecapsKey,
);
```

#### `authenticatedKemEncapsulate(recipientX25519Pub, recipientMlkemPub, senderIdentitySk) → [ciphertext, sharedSecret]`

Performs a hybrid KEM encapsulation and signs the ciphertext with the sender's Ed25519 identity key. The recipient can verify that the ciphertext was produced by the claimed sender and was not substituted by the server.

```ts
const [authCiphertext, sharedSecret] = authenticatedKemEncapsulate(
  bobX25519Public,
  bobMlkemEncapsKey,
  aliceIdentitySecret,
);
```

#### `authenticatedKemDecapsulate(ciphertext, ourX25519Secret, ourMlkemDecapsKey, senderIdentityPk) → sharedSecret`

Verifies the sender's signature before decapsulating. Throws if the signature is invalid.

```ts
const sharedSecret = authenticatedKemDecapsulate(
  receivedAuthCiphertext,
  myX25519Secret,
  myMlkemDecapsKey,
  aliceIdentityPublic,   // obtained from Key Transparency log or server
);
```

> **Why authenticated KEM matters:** Without it, the server can replace Bob's public key with its own, read the message, and re-encrypt it for Bob. The sender's signature over the KEM ciphertext closes this attack.

---

### Symmetric Encryption

#### `encryptAesGcm(key, plaintext, aad?) → ciphertext`

Encrypts using AES-256-GCM. The IV is generated internally using the OS CSPRNG and prepended to the output. The optional `aad` (additional authenticated data) is authenticated but not encrypted — any modification is detected at decryption.

```ts
const aad        = Buffer.from(`${messageId}:${senderId}`);
const ciphertext = encryptAesGcm(sessionKey, plaintext, aad);
```

#### `decryptAesGcm(key, ciphertext, aad?) → plaintext`

Decrypts and verifies an AES-256-GCM ciphertext. Throws if the authentication tag or AAD does not match.

```ts
const plaintext = decryptAesGcm(sessionKey, ciphertext, aad);
```

> **Never reuse IVs.** The library generates a fresh random IV for every `encryptAesGcm` call. Do not attempt to pass IVs manually — there is no API for it.

---

### Key Derivation

#### `deriveHkdf(ikm, salt?, info?, length) → key`

Derives a key using HKDF-SHA256. Use distinct `info` strings for each purpose to ensure cryptographic domain separation.

```ts
const sessionRootKey = deriveHkdf(
  sharedSecret,
  chatId,
  Buffer.from('vollchat-srk-v1'),
  32,
);

const windowKey = deriveHkdf(
  sessionRootKey,
  Buffer.from(windowIndex.toString()),
  Buffer.from('vollchat-window-key-v1'),
  32,
);
```

#### `derivePbkdf2(password, salt, iterations?, length?) → key`

Derives a key from a password using PBKDF2-SHA256. Default: 100 000 iterations. Use for password-protected key storage.

```ts
const wrappingKey = derivePbkdf2(
  Buffer.from(userPassword),
  salt,           // random 16-byte salt, stored alongside wrapped key
  100_000,
  32,
);
```

#### `deriveSrk(sharedSecret, chatId) → sessionRootKey`

Convenience function. Derives a Session Root Key from a hybrid KEM shared secret and a conversation identifier. Equivalent to calling `deriveHkdf` with the context string `vollchat-srk-v1`.

#### `deriveWindowKey(sessionRootKey, windowIndex) → windowKey`

Derives a time-window-specific encryption key from the Session Root Key. Window index is typically `Math.floor(Date.now() / 1000 / WINDOW_SIZE_SECONDS)`.

```ts
const WINDOW_SIZE_SECONDS = 3600; // 1 hour
const windowIndex = Math.floor(Date.now() / 1000 / WINDOW_SIZE_SECONDS);
const windowKey   = deriveWindowKey(sessionRootKey, windowIndex);
```

---

### Key Management

#### `wrapKey(keyToWrap, wrappingKey) → wrappedKey`

Wraps a key using AES-256-KW (RFC 3394). Use to store sensitive keys (DEK, SRK) encrypted under a password-derived wrapping key.

```ts
const wrappedDek = wrapKey(dataEncryptionKey, wrappingKey);
// Store wrappedDek in IndexedDB or server — safe to store, cannot be used without wrappingKey
```

#### `unwrapKey(wrappedKey, wrappingKey) → key`

Unwraps a key wrapped with `wrapKey`. Throws if the wrapping key is incorrect.

```ts
const dataEncryptionKey = unwrapKey(wrappedDek, wrappingKey);
```

#### `generateBip39Mnemonic() → mnemonic`

Generates a 24-word BIP-39 mnemonic phrase (256-bit entropy). Use as a paper key for disaster recovery.

```ts
const mnemonic = generateBip39Mnemonic();
// "abandon ability able about above ..."
// Store physically — never digitally in plaintext
```

#### `bip39MnemonicToSeed(mnemonic, passphrase?) → seed`

Derives a 64-byte seed from a BIP-39 mnemonic. Use to reconstruct the master key hierarchy during account recovery.

```ts
const seed = bip39MnemonicToSeed(mnemonic, '');
```

---

### Session Security

#### `generateRatchetKeypair() → RatchetKeyPairObj`

Generates an ephemeral X25519 keypair for a PCS ratchet step. The private key never leaves the WASM boundary or the Rust core — only the public key is exposed.

```ts
const ratchetKp = generateRatchetKeypair();
// ratchetKp.public_key — send to peer
// Private key is used internally via compute_ratchet()
```

#### `ratchetKp.computeRatchet(currentSrk, theirRatchetPub, chatId, ratchetStep) → newSrk`

Performs one PCS ratchet step. Derives a new Session Root Key that neither party can compute from the old SRK alone. The old SRK should be zeroized after this call.

```ts
const MESSAGE_RATCHET_INTERVAL = 50;

if (messageCount % MESSAGE_RATCHET_INTERVAL === 0) {
  const newSrk = ratchetKp.computeRatchet(
    currentSrk,
    theirLatestRatchetPublic,
    chatId,
    ratchetStep,
  );
  currentSrk.fill(0);   // zeroize old SRK
  currentSrk = newSrk;
  ratchetStep += 1;
}
```

#### `shouldRatchet(messageCount, windowChanged, messagesPerRatchet, ratchetOnNewWindow) → boolean`

Returns `true` if a ratchet step should be performed given the current state.

```ts
const needsRatchet = shouldRatchet(messageCount, windowChanged, 50, true);
```

#### Transcript Hashing

Transcript hashing maintains a running SHA-256 hash chain over the message sequence. Reordering, deleting, or replaying any message breaks the chain and causes decryption or verification to fail.

```ts
// Initialize at session start
let chainState = transcriptNew(Buffer.from(conversationId));

// After encrypting each message
const msgHash  = transcriptComputeMessageHash(messageId, senderId, timestamp, ciphertext);
chainState     = transcriptUpdate(chainState, msgHash);

// To verify both parties are in sync (e.g., during key verification)
const inSync = transcriptVerifySync(myChainState, theirChainState);
```

---

### Sealed Sender

Sealed sender hides the sender's identity from the server. The server sees only the recipient — the sender identity is encrypted inside the message payload using an ephemeral ECDH key.

#### `sealMessage(recipientX25519Pub, senderId, content) → sealedPacket`

Encrypts `senderId` together with `content`. The ephemeral key changes for every call so sealed packets cannot be correlated by the server.

```ts
const sealed = sealMessage(
  bobX25519Public,
  Buffer.from('alice@example.com'),
  encryptedMessagePayload,
);
// sealed: Buffer — send to server with only { to: bobId, payload: sealed }
```

#### `unsealMessage(sealedPacket, ourX25519Secret) → [senderId, content]`

Decrypts the sealed packet. Throws if the packet was tampered with or decrypted with the wrong key.

```ts
const [senderId, content] = unsealMessage(sealed, myX25519Secret);
console.log(senderId.toString()); // alice@example.com
```

---

### Key Verification Codes

Verification codes let users confirm each other's public keys through a separate channel (in person, phone call, another app). If the codes match, no MITM substitution occurred.

The code is derived from both users' Ed25519 public keys and the conversation identifier. It is symmetric — Alice and Bob arrive at the same code regardless of which order they pass the keys.

#### `generateVerificationCode(keyA, keyB, conversationId) → VerificationCodeResult`

```ts
const result = JSON.parse(generateVerificationCode(
  alicePublicKey,
  bobPublicKey,
  Buffer.from('conv-alice-bob-001'),
));

console.log(result.numeric.formatted);
// "25437 81920 34521 09876 54321 12345 67890 24680 13579 86420 11223 34455"

console.log(result.emoji.formatted);
// "🔥💧🌊⚡🎯 🦋🌸🍀🌙☀️ 🎵🎸🎹🎺🎻 🦁🐯🐻🦊🐺"
```

**MITM detection:**

```ts
// Alice computes
const aliceCode = generateVerificationCode(alicePublic, bobPublic, convId);

// Bob computes (order does not matter — result is the same)
const bobCode = generateVerificationCode(bobPublic, alicePublic, convId);

// Compare out of band (phone, in person)
const safe = verifyFingerprintsMatch(
  Buffer.from(JSON.parse(aliceCode).fingerprint),
  Buffer.from(JSON.parse(bobCode).fingerprint),
);
// true  → keys match, no MITM
// false → keys differ, do not trust this session
```

---

### Key Transparency Log

The Key Transparency log is an append-only, Ed25519-signed, hash-linked record of every public key publication. No entry can be silently modified or deleted — any change breaks the hash chain and is detected during `verifyChain`.

#### Creating and Appending Entries

```ts
import { keyLogCreateEntry, keyLogVerifyChain } from '@vollcrypt/node';

const GENESIS_HASH = Buffer.alloc(32, 0);

// First entry — Alice publishes her key
const entry0 = JSON.parse(keyLogCreateEntry(
  Buffer.from('alice@example.com'),
  alicePublicKey,
  Math.floor(Date.now() / 1000),
  GENESIS_HASH,
  1,                    // action: 1=Add, 2=Update, 3=Revoke
  aliceIdentitySecret,
));

// Key rotation — Alice updates her key
const entry1 = JSON.parse(keyLogCreateEntry(
  Buffer.from('alice@example.com'),
  newAlicePublicKey,
  Math.floor(Date.now() / 1000),
  Buffer.from(entry0.hash),   // prev_entry_hash
  2,                          // action: Update
  aliceIdentitySecret,
));

const log = [entry0, entry1];
```

#### Verifying the Chain

```ts
const valid = keyLogVerifyChain(JSON.stringify(log));
// Throws with { atIndex, reason } if any entry has a broken chain or invalid signature
```

#### Querying the Log

```ts
// Get Alice's current active key
const currentKey = keyLogCurrentKey(
  JSON.stringify(log),
  Buffer.from('alice@example.com'),
);

// Get the key that was valid at a specific point in time
// (for verifying historical messages)
const historicalKey = keyLogKeyAtTimestamp(
  JSON.stringify(log),
  Buffer.from('alice@example.com'),
  messageTimestamp,
);
```

---

### Device Registry

```ts
import { addDevice, revokeDevice, isDeviceRevoked } from '@vollcrypt/node';

// Register a new device
addDevice(registry, {
  deviceId:  'device-uuid-001',
  publicKey: deviceEd25519Public,
  addedAt:   Math.floor(Date.now() / 1000),
});

// Revoke a lost or compromised device
revokeDevice(registry, 'device-uuid-001');

// Check before accepting a signed message
if (isDeviceRevoked(registry, signingDeviceId)) {
  throw new Error('Message signed by revoked device');
}
```

---

## Full E2EE Flow Example

The following shows a complete session between Alice and Bob using the authenticated KEM handshake, time-windowed encryption, sealed sender, and transcript hashing. See [`vollcrypt-example/src/09_full_flow.ts`](vollcrypt-example/src/09_full_flow.ts) for the runnable version.

```ts
// ─── 1. Key Generation ────────────────────────────────────────────────────
const [aliceIdSk, aliceIdPk] = generateEd25519Keypair();
const [aliceX25519Sk, aliceX25519Pk] = generateX25519Keypair();
const [aliceMlkemEncaps, aliceMlkemDecaps] = generateMlKem768Keypair();

const [bobIdSk, bobIdPk] = generateEd25519Keypair();
const [bobX25519Sk, bobX25519Pk] = generateX25519Keypair();
const [bobMlkemEncaps, bobMlkemDecaps] = generateMlKem768Keypair();

// ─── 2. Authenticated KEM Handshake ──────────────────────────────────────
const conversationId = Buffer.from('conv-alice-bob-001');

// Alice encapsulates and signs
const [authCiphertext, aliceSharedSecret] = authenticatedKemEncapsulate(
  bobX25519Pk, bobMlkemEncaps, aliceIdSk,
);

// Bob verifies Alice's signature and decapsulates
const bobSharedSecret = authenticatedKemDecapsulate(
  authCiphertext, bobX25519Sk, bobMlkemDecaps, aliceIdPk,
);
// aliceSharedSecret === bobSharedSecret

// ─── 3. Session Root Key and WindowKey Derivation ────────────────────────
const srk = deriveSrk(aliceSharedSecret, conversationId);
const WINDOW = 3600;
const windowIndex = Math.floor(Date.now() / 1000 / WINDOW);
const windowKey = deriveWindowKey(srk, windowIndex);

// ─── 4. Transcript Initialization ────────────────────────────────────────
let aliceChain = transcriptNew(conversationId);
let bobChain   = transcriptNew(conversationId);

// ─── 5. Alice Sends a Message (Sealed Sender) ────────────────────────────
const messageId  = Buffer.from('msg-001');
const senderId   = Buffer.from('alice@example.com');
const timestamp  = Math.floor(Date.now() / 1000);
const aad        = Buffer.concat([messageId, senderId, Buffer.from(timestamp.toString())]);
const plaintext  = Buffer.from('Hello Bob');

const ciphertext = encryptAesGcm(windowKey, plaintext, aad);
const sealed     = sealMessage(bobX25519Pk, senderId, ciphertext);

// Alice updates her transcript
const msgHash  = transcriptComputeMessageHash(messageId, senderId, timestamp, ciphertext);
aliceChain     = transcriptUpdate(aliceChain, msgHash);

// ─── 6. Bob Receives and Decrypts ────────────────────────────────────────
const [revealedSender, revealedCiphertext] = unsealMessage(sealed, bobX25519Sk);
const bobWindowKey = deriveWindowKey(
  deriveSrk(bobSharedSecret, conversationId),
  windowIndex,
);
const decrypted = decryptAesGcm(bobWindowKey, revealedCiphertext, aad);
bobChain = transcriptUpdate(bobChain, msgHash);

console.log(decrypted.toString());                       // Hello Bob
console.log(revealedSender.toString());                  // alice@example.com
console.log(transcriptVerifySync(aliceChain, bobChain)); // true

// ─── 7. Key Verification (Out of Band) ───────────────────────────────────
const aliceCode = generateVerificationCode(aliceIdPk, bobIdPk, conversationId);
const bobCode   = generateVerificationCode(bobIdPk, aliceIdPk, conversationId);
// Alice and Bob compare these codes over a phone call
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
# Clone
git clone https://github.com/BeratVural/vollcrypt.git
cd vollcrypt

# Run all tests
cargo test --workspace

# Check formatting and lints
cargo fmt --all -- --check
cargo clippy --workspace -- -D warnings

# Build Node.js native addon
cd node && npm install && npm run build && cd ..

# Build WebAssembly package
cd wasm && wasm-pack build --target web --out-dir pkg && cd ..

# Run usage examples
cd vollcrypt-example && npm install
npx ts-node src/09_full_flow.ts
```

---

## Architecture

```
vollcrypt/
├── core/               Rust cryptographic core (no I/O, no_std compatible)
│   └── src/
│       ├── symmetric.rs      AES-256-GCM encryption / decryption
│       ├── pqc.rs            ML-KEM-768 + Hybrid KEM + Authenticated KEM
│       ├── keys.rs           Ed25519 and X25519 keypair operations
│       ├── kdf.rs            HKDF, PBKDF2, SRK and WindowKey derivation
│       ├── ratchet.rs        PCS ratchet (post-compromise security)
│       ├── transcript.rs     Message hash chain (session integrity)
│       ├── sealed_sender.rs  Sender privacy layer
│       ├── verification.rs   Key verification codes (numeric + emoji)
│       ├── key_log.rs        Key Transparency log (hash-linked, signed)
│       ├── envelope.rs       Binary message envelope packing
│       ├── wrap.rs           AES-256-KW key wrapping
│       ├── bip39.rs          BIP-39 mnemonic generation and seed derivation
│       └── device.rs         Device registry and revocation
├── node/               N-API native binding (@vollcrypt/node)
├── wasm/               wasm-bindgen WebAssembly binding (@vollcrypt/wasm)
├── packages/
│   └── license-server/ License validation and MAU tracking server
└── vollcrypt-example/  Runnable usage examples (01 through 10)
```

### Message Envelope Format

Every AES-256-GCM ciphertext is packed into a standard binary envelope:

```
┌──────────────┬──────────────┬──────────────────┬──────────────┬──────────────────┐
│ Window Index │      IV      │    AAD Hash      │  Ciphertext  │   Auth Tag       │
│   4 bytes    │   12 bytes   │    32 bytes      │  variable    │   16 bytes       │
│  (BE uint32) │  (OsRng)     │  SHA-256(AAD)    │  AES-256-GCM │  GCM MAC         │
└──────────────┴──────────────┴──────────────────┴──────────────┴──────────────────┘
```

The window index tells the recipient which WindowKey to derive. The AAD hash ensures the message cannot be moved to a different conversation or attributed to a different sender.

---

## Security Considerations

### Things the Library Does For You

- Generates IVs internally using `OsRng` — you cannot pass an IV manually
- Zeroizes sensitive memory (`zeroize` crate) after use in all Rust code
- Uses `subtle::ConstantTimeEq` for all security-sensitive comparisons
- Enforces distinct HKDF context strings for every key derivation purpose

### Things You Are Responsible For

**Do not store raw key bytes in persistent memory in JavaScript.** Import DEK and SRK bytes into `SubtleCrypto` with `extractable: false` immediately after receiving them from the WASM layer, then zero the raw buffer:

```ts
const dekCryptoKey = await crypto.subtle.importKey(
  'raw', rawDekBuffer, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt'],
);
new Uint8Array(rawDekBuffer).fill(0); // zero immediately after import
```

**Do not store raw keys in React state, Redux, or localStorage.** A key stored in JavaScript memory is accessible to any XSS payload on the page.

**Verify keys out of band.** The library provides verification codes, but humans must compare them. An unverified session is authenticated only against the server's honesty.

**Rotate keys after compromise.** Key Transparency logs key changes, but it does not automatically rotate keys. Your application must trigger a new authenticated KEM handshake after device compromise or revocation.

---

## Licensing

Vollcrypt is dual-licensed:

- **Open source:** [GNU General Public License v3.0](LICENSE) — free for open source projects
- **Commercial:** Contact [licensing@vollsign.io](mailto:licensing@vollsign.io) for a commercial license that removes the GPL copyleft requirement

| Tier       | Monthly Active Users | Price       |
| ---------- | -------------------- | ----------- |
| Free       | Up to 500            | Free        |
| Starter    | Up to 5 000          | $5 / month  |
| Pro        | Up to 50 000         | $49 / month |
| Enterprise | Unlimited            | Contact us  |

Commercial licenses include a private build without GPL obligations and priority support. See [vollsign.io/pricing](https://vollsign.io/pricing).

---

## Contributing

Contributions are welcome. Before opening a pull request, please read [CONTRIBUTING.md](CONTRIBUTING.md).

All contributors must sign the Contributor License Agreement (CLA) before their first pull request is merged. This allows Vollcrypt to be offered under both the GPL and a commercial license.

**Security issues:** Please do not open public GitHub issues for security vulnerabilities. Follow the process in [SECURITY.md](SECURITY.md).

---

<div align="center">

Built with Rust · Powered by [RustCrypto](https://github.com/RustCrypto) and [dalek-cryptography](https://github.com/dalek-cryptography)

</div><div align="center">
# Vollcrypt


# Vollcrypt
