# Vollcrypt File Cryptography Engine

Vollcrypt File is a cross-platform, hybrid quantum-resistant file encryption and metadata package. It is designed to secure file payloads and their associated headers for high-security applications, such as digital signature systems (VollSign) and lawyer communication platforms (KanzleiLink).

## License

This package is dual-licensed under:
- GPL-3.0-only (for open-source distribution)
- Commercial License (for proprietary software integrations)

---

## Technical Specifications

### Cryptographic Algorithms

- **Symmetric Encryption**: AES-256-GCM
- **Key Wrapping**: AES-256-Key-Wrap (AES-KW)
- **Key Derivation (KDF)**: PBKDF2 (SHA-256) or Argon2id (customizable iterations/memory cost)
- **Asymmetric Exchange (Hybrid KEM)**: ML-KEM-768 (Kyber) combined with X25519
- **Signatures**: Ed25519 (RFC 8032)
- **Integrity**: Merkle Tree leaf hashing over chunk envelopes

### Binary Layouts

#### Header Format (Version 1 & 2)

Headers are parsed dynamically to maintain backward compatibility. Version 2 introduces Ed25519 signatures and metadata blocks.

| Offset (Bytes) | Field Name | Type | Description / Value |
|:---|:---|:---|:---|
| 0 | Magic Bytes | `[u8; 4]` | ASCII "VOLL" |
| 4 | Version | `u8` | `1` (Legacy) or `2` (Signature-supported) |
| 5 | Mode | `u8` | `0` = Password, `1` = Recipient (Hybrid KEM), `2` = Group |
| 6 | Cipher ID | `u8` | `0` = AES-256-GCM |
| 7..23 | File ID | `[u8; 16]` | Universally unique file identifier |
| 23..27 | Chunk Size | `u32` | Chunk size in bytes (Big Endian) |
| 27..35 | Plaintext Size | `u64` | Total size of unencrypted payload (Big Endian) |
| 35..67 | Merkle Root | `[u8; 32]` | Merkle tree root hash of all chunk envelopes |
| 67..69 | Wraps Count | `u16` | Number of key wrapping entries (Big Endian) |
| 69.. | Wrap Entries | Variable | Array of serialized wrap entries |
| Variable | Signed Metadata | Variable | Present only in Version 2 headers |
| Variable | Signature | `[u8; 64]` | Present only in Version 2 headers |

#### Wrap Entry Format

Each wrap entry serializes based on its type.

| Field | Type | Password (PBKDF2/Argon2) | Hybrid KEM | Group Wrap |
|:---|:---|:---|:---|:---|
| Wrap Type | `u8` | `0` (PBKDF2) / `1` (Argon2) | `2` | `3` |
| Parameters | Variable | Salt (16B), Iterations / Costs | Recipient ID (16B), GK Version (u32), Ephemeral PK (32B), ML-KEM Ciphertext (1088B) | Group ID (16B), GK Version (u32) |
| Wrapped DEK | `[u8; 40]` | AES-KW wrapped DEK | AES-KW wrapped DEK | AES-KW wrapped DEK |

---

## Quick Start

### Node.js Integration

```typescript
import { 
  generateDek, 
  generateFileId, 
  encryptChunk, 
  decryptChunk 
} from "@vollcrypt/files-node";

// 1. Generate keys
const dek = generateDek();
const fileId = generateFileId();

// 2. Encrypt chunk
const plaintext = Buffer.from("Sensitive legal document content...");
const envelope = encryptChunk(dek, fileId, 0, plaintext);

// 3. Decrypt chunk
const decrypted = decryptChunk(dek, fileId, 0, envelope);
console.log(decrypted.toString()); // Sensitive legal document content...
```

### WebAssembly (Browser) Integration

```javascript
import init, { generateDek, generateFileId } from "./pkg/vollcrypt_file_wasm.js";

async function run() {
  await init();
  
  const dek = generateDek();
  const fileId = generateFileId();
  console.log("DEK generated:", dek);
}
run();
```

---

## API Reference (Bindings)

- `generateDek()`: Generate a cryptographically secure 32-byte Data Encryption Key.
- `generateFileId()`: Generate a cryptographically secure 16-byte File ID.
- `generateSalt()`: Generate a cryptographically secure 16-byte Salt.
- `generateGk()`: Generate a cryptographically secure 32-byte Group Key.
- `encryptChunk(dek, fileId, chunkIndex, plaintext)`: Encrypt a single block of plaintext.
- `decryptChunk(dek, fileId, chunkIndex, envelope)`: Decrypt a single chunk envelope.
- `wrapDekWithPassword(dek, password, kdf)`: Wrap a DEK with a password.
- `unwrapDekWithPassword(wrapEntry, password)`: Unwrap a password-wrapped DEK.
- `generateRecipientKeypair()`: Generate an ML-KEM-768 + X25519 keypair.
- `wrapKeyToRecipient(key, recipientId, gkVersion, recipientPk)`: Encrypt a key to an asymmetric recipient.
- `unwrapKeyWithRecipientKey(wrapEntry, recipientSk)`: Decrypt a key using recipient secret key.
- `wrapDekForGroup(dek, groupId, gkVersion, gk)`: Wrap the DEK with the Group Key.
- `unwrapDekWithGroupKey(wrapEntry, gk)`: Unwrap a GroupWrap entry using the Group Key.
- `ed25519KeypairGenerate()`: Generate a signing keypair.
- `ed25519Sign(sk, message)`: Sign a message.
- `ed25519Verify(pk, message, signature)`: Verify a signature.

---

## Building and Testing

### Build Node.js Crate
```bash
cd node
npm install
npm run build:debug
npm test
```

### Build WebAssembly Crate
```bash
cd wasm
npm install
npm run build
npm test
```
