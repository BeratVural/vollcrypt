<div align="center">

# Vollcrypt Files (Under Active Development)

**High-performance, chunk-based E2EE file/stream encryption core for Node.js, WebAssembly, and Rust**

</div>

---

> [!NOTE]
> The Files module is currently under active development. Some bindings and APIs are subject to change.

This module provides high-performance stream encryption and chunk integrity verification, designed for handling large files safely without loading them entirely into memory.

## Workspace Structure

*   `vollcrypt-file/core/`: The core Rust implementation containing file format serialization, streaming cipher utilities, and Merkle tree calculations.
*   `vollcrypt-file/node/` *(Planned)*: High-performance native Node.js bindings for stream encryption (compatible with Node `stream.Readable` and `stream.Writable`).
*   `vollcrypt-file/wasm/` *(Planned)*: WebAssembly bindings for client-side browser file encryption (supporting browser Streams API and `File` object chunking).

---

## Technical Architecture

### 1. File Format Structure
Vollcrypt Files uses a secure, chunked envelope format to ensure both privacy and instant random access:

```
+-------------------------------------------------------------------+
| HEADER (Version, KDF/KEM parameters, encrypted DEK envelope)      |
+-------------------------------------------------------------------+
| CHUNK 0: [12B IV] [Ciphertext] [16B Auth Tag]                      |
+-------------------------------------------------------------------+
| CHUNK 1: [12B IV] [Ciphertext] [16B Auth Tag]                      |
+-------------------------------------------------------------------+
| ...                                                               |
+-------------------------------------------------------------------+
| MERKLE TREE ROOT & SIGNATURE (Validates total chunk structure)    |
+-------------------------------------------------------------------+
```

### 2. Chunk-Based Stream Encryption
- Files are split into standard chunks (e.g., 64KB or 1MB).
- Each chunk is encrypted independently using **AES-256-GCM** with a unique IV.
- Prevents memory exhaustion when encrypting or decrypting multi-gigabyte files.

### 3. Merkle Tree Integrity Verification
- To prevent chunk-substitution attacks (where a malicious server replaces chunk $N$ of file A with chunk $N$ of file B), a Merkle tree is computed over the authentication tags of all chunks.
- The Merkle root is signed or verified at the end of the stream.
- Allows random-access seek/verification: you can verify the integrity of chunk $N$ using its Merkle proof without downloading or decrypting any other chunk.

---

## Security Principles

- **Zero-Knowledge Storage:** The storage provider cannot read the filename, structure, or content of the file.
- **Cryptographic Domain Separation:** Keys derived for file encryption use distinct HKDF context labels (`vollcrypt-file-kdf-v1`) separate from messaging keys.
- **Recipient Management:** Supports multi-recipient files by encrypting the single Data Encryption Key (DEK) under multiple recipients' public keys inside the file header.
