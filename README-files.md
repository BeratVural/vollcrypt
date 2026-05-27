# Vollcrypt Files

High-performance, chunk-based End-to-End Encrypted (E2EE) file/stream encryption core for Node.js, WebAssembly, and Rust.

---

This module provides high-performance stream encryption, cryptographic access control, and chunk integrity verification, designed for handling large files safely without loading them entirely into memory.

## Workspace Structure

*   `vollcrypt-file/core/`: The core Rust implementation containing file format serialization, streaming cipher utilities, post-quantum hybrid KEM, and the signed group manifest.
*   `vollcrypt-file/node/` (Planned): Native Node.js bindings for stream encryption (compatible with Node `stream.Readable` and `stream.Writable`).
*   `vollcrypt-file/wasm/` (Planned): WebAssembly bindings for client-side browser file encryption (supporting browser Streams API and `File` object chunking).

---

## Key Capabilities

### 1. Multi-Mode Key Wrapping
Vollcrypt Files supports multiple ways to wrap and protect the file-specific Data Encryption Key (DEK):
*   **Password-Based Wrapping:** Derives a Key Encryption Key (KEK) using PBKDF2-SHA256 (600k iterations) or Argon2id (default/interactive parameters), wrapping the DEK with AES-256 Key Wrap (AES-KW).
*   **Asymmetric Recipient Wrapping:** Uses a Post-Quantum Hybrid Key Encapsulation Mechanism (X25519 + ML-KEM-768) to encapsulate the DEK. The KEK is derived via HKDF-SHA256 using the classical and post-quantum shared secrets.
*   **Group wrapping:** Supports encrypting the DEK under a symmetric Group Key (GK), which is itself managed and rotated through a signed, hash-linked Group Manifest.

### 2. Stream-Friendly Symmetric Engine
*   **Chunk-Based Encryption:** Files are split into standard chunks (default: 4096 bytes). Each chunk is encrypted independently using AES-256-GCM.
*   **Cryptographic Domain Separation:** Rather than using the DEK directly, each chunk is encrypted using a unique subkey derived via HKDF-SHA256 from the DEK, the 16-byte random file ID, and the chunk index.
*   **Out-of-Order Decryption:** Allows instant random-access seeking. Any chunk can be decrypted independently given its index, without decrypting preceding chunks.

### 3. Signed, Hash-Linked Group Manifest
To support multi-member groups:
*   **Operation Log:** The manifest records the lifecycle of the group through operations: `Genesis`, `AddMember`, and `RemoveMember`.
*   **Ed25519 Signatures:** Every operation in the log must be signed by the group's founder/admin.
*   **Cryptographic Chaining:** Each operation contains the SHA-256 hash of the complete preceding operation, forming an immutable hash chain starting from the Genesis block.
*   **Lazy Revocation:** Removing a member does not require immediate re-encryption of all historical files. The removed member is immediately blocked from acquiring future keys from the manifest, while historical access is technically retained via previously cached keys.

### 4. Merkle Tree Integrity Verification
*   **Chunk-Substitution Protection:** To prevent malicious storage servers from replacing or swapping chunks, a Merkle Tree is constructed over the authentication tags of all chunk envelopes.
*   **Merkle Proofs:** Individual chunks can be verified for integrity by validating their chunk leaf hash and associated Merkle proof against the trusted root hash stored in the file header.

---

## Technical Specifications

### File Header Binary Layout
The header contains critical file metadata and the wraps protecting the DEK:

| Offset | Length | Type | Description |
| :--- | :--- | :--- | :--- |
| 0 | 8 | Bytes | Magic Bytes (`VOLLCRYPT`) |
| 8 | 1 | u8 | Version (1) |
| 9 | 1 | u8 | Mode (0: Password, 1: Recipient, 2: Group) |
| 10 | 1 | u8 | Cipher ID (0: AES-256-GCM) |
| 11 | 4 | u32 BE | Chunk Size (e.g. 4096) |
| 15 | 8 | u64 BE | Plaintext Size (in bytes) |
| 23 | 16 | Bytes | File ID (Randomly generated) |
| 39 | 32 | Bytes | Merkle Root |
| 71 | 2 | u16 BE | Wrap Count |
| 73 | Var | Structs | Concatenated list of `WrapEntry` |

### Wrap Entry Binary Layouts
Each wrap entry starts with a 1-byte `wrap_type` and a 2-byte BE `payload_len`.

#### Type 0: Password PBKDF2 (Payload Length = 60)
*   `0..4`: Iterations (u32 BE)
*   `4..20`: Salt (16 bytes)
*   `20..60`: Wrapped DEK (40 bytes AES-KW)

#### Type 1: Password Argon2id (Payload Length = 68)
*   `0..4`: Memory Cost (u32 BE)
*   `4..8`: Time Cost (u32 BE)
*   `8..12`: Parallelism Cost (u32 BE)
*   `12..28`: Salt (16 bytes)
*   `28..68`: Wrapped DEK (40 bytes AES-KW)

#### Type 2: Hybrid KEM (Payload Length = 1180)
*   `0..16`: Recipient ID (16 bytes)
*   `16..20`: Group Key Version (u32 BE)
*   `20..52`: X25519 Ephemeral Public Key (32 bytes)
*   `52..1140`: ML-KEM-768 Ciphertext (1088 bytes)
*   `1140..1180`: Wrapped Key (40 bytes AES-KW)

#### Type 3: Group Wrap (Payload Length = 60)
*   `0..16`: Group ID (16 bytes)
*   `16..20`: Group Key Version (u32 BE)
*   `20..60`: Wrapped DEK (40 bytes AES-KW)

---

## Cryptographic Security Policies

1.  **Memory Protection:** All sensitive keying materials (including Key Encryption Keys, ephemeral Diffie-Hellman secrets, and recipient secret keys) implement the `Zeroize` and `ZeroizeOnDrop` traits to ensure they are scrubbed from memory immediately after use.
2.  **Hybrid KDF Context:** The KDF derivation for hybrid KEM KEKs uses the context info buffer: `vollcrypt-file-hybrid-kem-v1 || recipient_id (16B) || gk_version (4B BE)`.
3.  **Chunk Key Context:** The subkey for chunk $i$ is derived using the context info buffer: `vollcrypt-file-chunk-kdf-v1-chunk- || chunk_index (4B BE)`.
4.  **No Unsafe Code:** The entire codebase is implemented in 100% safe Rust, ensuring memory safety guarantees.
