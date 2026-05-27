<div align="center">

# Vollcrypt Messages

**E2EE Message Encryption and Session Management module for Node.js, WebAssembly, and Rust**

[![npm (node)](https://img.shields.io/npm/v/@vollcrypt/messages-node?label=%40vollcrypt%2Fmessages-node&color=cb3837)](https://www.npmjs.com/package/@vollcrypt/messages-node)
[![npm (wasm)](https://img.shields.io/npm/v/@vollcrypt/messages-wasm?label=%40vollcrypt%2Fmessages-wasm&color=cb3837)](https://www.npmjs.com/package/@vollcrypt/messages-wasm)

</div>

---

This module contains the cryptographic primitives and session managers needed to build secure end-to-end encrypted (E2EE) messaging systems. It is compiled from a single Rust core to three targets: Node.js (native bindings), WebAssembly, and native Rust.

## Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [API Reference](#api-reference)
  - [Identity and Key Exchange](#identity-and-key-exchange)
  - [Post-Quantum Cryptography](#post-quantum-cryptography)
  - [Symmetric Encryption](#symmetric-encryption)
  - [Key Derivation](#key-derivation)
  - [Session Security (PCS Ratchet & Hashing)](#session-security)
  - [Sealed Sender](#sealed-sender)
  - [Key Verification Codes](#key-verification-codes)
  - [Key Transparency Log](#key-transparency-log)
  - [Device Registry](#device-registry)
- [Full E2EE Flow Example](#full-e2ee-flow-example)

---

## Installation

### Node.js (Server-side & Native Addon)

```bash
npm install @vollcrypt/messages-node
```

Prebuilt native binaries are provided for:
- Linux x64 (`linux-x64-gnu`)
- macOS x64 (`darwin-x64`)
- Windows x64 (`win32-x64-msvc`)

### WebAssembly (Browser / React / Next.js)

```bash
npm install @vollcrypt/messages-wasm
```

### Rust (Cargo)

In a Cargo workspace:
```toml
vollcrypt-core = { path = "../vollcrypt/src/core" }
```

---

## Quick Start

### Node.js — Generate Keys and Encrypt a Message

```ts
import {
  generateEd25519Keypair,
  encryptAesGcm,
  decryptAesGcm,
} from '@vollcrypt/messages-node';
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
} from '@vollcrypt/messages-wasm';

await init();

const [identitySecret, identityPublic] = generateEd25519Keypair();
const sessionKey = crypto.getRandomValues(new Uint8Array(32));
const plaintext  = new TextEncoder().encode('Hello, Vollcrypt');

const ciphertext = encryptAesGcm(sessionKey, plaintext, null);
const decrypted  = decryptAesGcm(sessionKey, ciphertext, null);
console.log(new TextDecoder().decode(decrypted));
```

---

## API Reference

All examples below use the Node.js binding. The WASM binding exposes identical function names with `snake_case` convention. The Rust API mirrors the same logic in the `vollcrypt_core` crate.

### Identity and Key Exchange

#### `generateEd25519Keypair() → [secretKey, publicKey]`
Generates a new Ed25519 keypair. Use for user and device identity.
```ts
const [secretKey, publicKey] = generateEd25519Keypair();
```

#### `signMessage(secretKey, message) → signature`
Signs a message with an Ed25519 private key.
```ts
const signature = signMessage(secretKey, message);
```

#### `verifySignature(publicKey, message, signature) → boolean`
Verifies an Ed25519 signature.
```ts
const valid = verifySignature(publicKey, message, signature);
```

#### `generateX25519Keypair() → [secretKey, publicKey]`
Generates a new X25519 keypair. Use for ECDH key exchange.
```ts
const [x25519Secret, x25519Public] = generateX25519Keypair();
```

---

### Post-Quantum Cryptography

#### `generateMlKem768Keypair() → [encapsKey, decapsKey]`
Generates a new ML-KEM-768 keypair (NIST FIPS 203).
```ts
const [encapsKey, decapsKey] = generateMlKem768Keypair();
```

#### `hybridKemEncapsulate(recipientX25519Pub, recipientMlkemPub) → [ciphertext, sharedSecret]`
Performs a hybrid KEM encapsulation combining X25519 ECDH and ML-KEM-768.
```ts
const [ciphertext, sharedSecret] = hybridKemEncapsulate(bobX25519Public, bobMlkemEncapsKey);
```

#### `hybridKemDecapsulate(ourX25519Secret, ciphertext, ourMlkemDecapsKey) → sharedSecret`
Decapsulates a hybrid KEM ciphertext.
```ts
const sharedSecret = hybridKemDecapsulate(myX25519Secret, receivedCiphertext, myMlkemDecapsKey);
```

#### `authenticatedKemEncapsulate(recipientX25519Pub, recipientMlkemPub, senderIdentitySk) → [ciphertext, sharedSecret]`
Performs a hybrid KEM encapsulation and signs the ciphertext with the sender's Ed25519 identity key.
```ts
const [authCiphertext, sharedSecret] = authenticatedKemEncapsulate(bobX25519Pub, bobMlkemEncaps, aliceIdSk);
```

#### `authenticatedKemDecapsulate(ciphertext, ourX25519Secret, ourMlkemDecapsKey, senderIdentityPk) → sharedSecret`
Verifies the sender's signature before decapsulating. Throws if the signature is invalid.
```ts
const sharedSecret = authenticatedKemDecapsulate(receivedAuthCiphertext, myX25519Secret, myMlkemDecapsKey, aliceIdPk);
```

---

### Symmetric Encryption

#### `encryptAesGcm(key, plaintext, aad?) → ciphertext`
Encrypts using AES-256-GCM. The IV is generated internally and prepended to the output.
```ts
const ciphertext = encryptAesGcm(sessionKey, plaintext, aad);
```

#### `decryptAesGcm(key, ciphertext, aad?) → plaintext`
Decrypts and verifies an AES-256-GCM ciphertext.
```ts
const plaintext = decryptAesGcm(sessionKey, ciphertext, aad);
```

---

### Key Derivation

#### `deriveHkdf(ikm, salt?, info?, length) → key`
Derives a key using HKDF-SHA256.
```ts
const sessionRootKey = deriveHkdf(sharedSecret, chatId, Buffer.from('vollchat-srk-v1'), 32);
```

#### `derivePbkdf2(password, salt, iterations?, length?) → key`
Derives a key from a password using PBKDF2-SHA256.
```ts
const wrappingKey = derivePbkdf2(Buffer.from(userPassword), salt, 100_000, 32);
```

#### `deriveSrk(sharedSecret, chatId) → sessionRootKey`
Derives a Session Root Key from a hybrid KEM shared secret and a conversation identifier.

#### `deriveWindowKey(sessionRootKey, windowIndex) → windowKey`
Derives a time-window-specific encryption key from the Session Root Key.

---

### Session Security

#### `generateRatchetKeypair() → RatchetKeyPairObj`
Generates an ephemeral X25519 keypair for a PCS ratchet step.

#### `ratchetKp.computeRatchet(currentSrk, theirRatchetPub, chatId, ratchetStep) → newSrk`
Performs one Post-Compromise Security (PCS) ratchet step.

#### `shouldRatchet(messageCount, windowChanged, messagesPerRatchet, ratchetOnNewWindow) → boolean`
Returns `true` if a ratchet step should be performed.

#### Transcript Hashing
Transcript hashing maintains a running SHA-256 hash chain over the message sequence.
```ts
// Initialize
let chainState = transcriptNew(Buffer.from(conversationId));
// Update
const msgHash = transcriptComputeMessageHash(messageId, senderId, timestamp, ciphertext);
chainState = transcriptUpdate(chainState, msgHash);
// Verify
const inSync = transcriptVerifySync(myChainState, theirChainState);
```

---

### Sealed Sender

Sealed sender hides the sender's identity from the server.

#### `sealMessage(recipientX25519Pub, senderId, content) → sealedPacket`
Encrypts `senderId` together with `content`.
```ts
const sealed = sealMessage(bobX25519Public, senderId, ciphertext);
```

#### `unsealMessage(sealedPacket, ourX25519Secret) → [senderId, content]`
Decrypts the sealed packet.
```ts
const [senderId, content] = unsealMessage(sealed, myX25519Secret);
```

---

### Key Verification Codes

Verification codes let users confirm each other's public keys through a separate channel (numeric or emoji).

#### `generateVerificationCode(keyA, keyB, conversationId) → VerificationCodeResult`
```ts
const result = JSON.parse(generateVerificationCode(alicePublicKey, bobPublicKey, conversationId));
console.log(result.numeric.formatted); // E.g. "25437 81920 ..."
console.log(result.emoji.formatted);   // E.g. "🔥💧🌊⚡🎯 ..."
```

---

### Key Transparency Log

An append-only, Ed25519-signed, hash-linked record of every public key publication.

#### `keyLogCreateEntry(identity, pubKey, timestamp, prevEntryHash, action, identitySecret) → entryJson`
Creates a signed Key Transparency log entry.

#### `keyLogVerifyChain(logJson) → boolean`
Verifies the integrity and signatures of the log chain.

---

### Device Registry

Manages multiple registered devices per user with support for instant revocation.

#### `addDevice(registry, device) / revokeDevice(registry, deviceId)`
Adds or revokes a device from the user registry state.

---

## Full E2EE Flow Example

```ts
import {
  generateEd25519Keypair,
  generateX25519Keypair,
  generateMlKem768Keypair,
  authenticatedKemEncapsulate,
  authenticatedKemDecapsulate,
  deriveSrk,
  deriveWindowKey,
  transcriptNew,
  transcriptComputeMessageHash,
  transcriptUpdate,
  transcriptVerifySync,
  encryptAesGcm,
  decryptAesGcm,
  sealMessage,
  unsealMessage,
  generateVerificationCode
} from '@vollcrypt/messages-node';

// 1. Key Generation
const [aliceIdSk, aliceIdPk] = generateEd25519Keypair();
const [aliceX25519Sk, aliceX25519Pk] = generateX25519Keypair();
const [aliceMlkemEncaps, aliceMlkemDecaps] = generateMlKem768Keypair();

const [bobIdSk, bobIdPk] = generateEd25519Keypair();
const [bobX25519Sk, bobX25519Pk] = generateX25519Keypair();
const [bobMlkemEncaps, bobMlkemDecaps] = generateMlKem768Keypair();

// 2. Handshake
const conversationId = Buffer.from('conv-alice-bob-001');
const [authCiphertext, aliceSharedSecret] = authenticatedKemEncapsulate(
  bobX25519Pk, bobMlkemEncaps, aliceIdSk,
);
const bobSharedSecret = authenticatedKemDecapsulate(
  authCiphertext, bobX25519Sk, bobMlkemDecaps, aliceIdPk,
);

// 3. Key Derivation
const srk = deriveSrk(aliceSharedSecret, conversationId);
const windowIndex = Math.floor(Date.now() / 1000 / 3600);
const windowKey = deriveWindowKey(srk, windowIndex);

// 4. Transcript Initialization
let aliceChain = transcriptNew(conversationId);
let bobChain   = transcriptNew(conversationId);

// 5. Sealed Sender Message
const messageId  = Buffer.from('msg-001');
const senderId   = Buffer.from('alice@example.com');
const timestamp  = Math.floor(Date.now() / 1000);
const aad        = Buffer.concat([messageId, senderId, Buffer.from(timestamp.toString())]);
const plaintext  = Buffer.from('Hello Bob');

const ciphertext = encryptAesGcm(windowKey, plaintext, aad);
const sealed     = sealMessage(bobX25519Pk, senderId, ciphertext);

// Update Alice Transcript
const msgHash  = transcriptComputeMessageHash(messageId, senderId, timestamp, ciphertext);
aliceChain     = transcriptUpdate(aliceChain, msgHash);

// 6. Decryption
const [revealedSender, revealedCiphertext] = unsealMessage(sealed, bobX25519Sk);
const bobWindowKey = deriveWindowKey(deriveSrk(bobSharedSecret, conversationId), windowIndex);
const decrypted = decryptAesGcm(bobWindowKey, revealedCiphertext, aad);
bobChain = transcriptUpdate(bobChain, msgHash);

console.log(decrypted.toString());                       // Hello Bob
console.log(transcriptVerifySync(aliceChain, bobChain)); // true
```
