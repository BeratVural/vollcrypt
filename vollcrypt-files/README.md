# Vollcrypt File Container Engine

High-performance, chunk-based End-to-End Encrypted (E2EE) file container engine for Node.js, WebAssembly, and Rust.

Vollcrypt Files is designed for local file encryption, cloud object storage, and secure shared-file access. It processes large files incrementally without loading them fully into memory, but it is not a real-time network, audio, or video streaming protocol.

This module provides high-performance chunked file encryption, cryptographic access control, and chunk integrity verification for large encrypted file containers.

## License

This package is dual-licensed under:
- GPL-3.0-only (for open-source distribution)
- Commercial License (for proprietary software integrations)

---

## Technical Specifications

### Cryptographic Algorithms

- **Symmetric Encryption**: AES-256-GCM
- **Key Wrapping**: AES-256-Key-Wrap (AES-KW)
- **Key Derivation (KDF)**: Argon2id (default) or PBKDF2 (SHA-256) (legacy compatibility)
- **Asymmetric Exchange (Hybrid KEM)**: ML-KEM-768 (Kyber) combined with X25519
- **Signatures**: Ed25519 (RFC 8032)
- **Integrity**: Merkle Tree leaf hashing over chunk metadata and authentication tags (SHA-256 by default, with optional BLAKE3 support for high-performance profiles)

---

## Use Cases & Non-Goals

### Use Cases

Vollcrypt Files is intended for:
- Encrypting local files before storage.
- Storing encrypted files in untrusted cloud storage.
- Sharing encrypted files with multiple recipients.
- Opening shared encrypted files securely.
- Random-access reads over cloud range requests.
- Group-based file access with key rotation and revocation semantics.

### Non-Goals

Vollcrypt Files does not provide real-time transport encryption for live network streams, audio calls, or video calls.

Those use cases require different security properties such as frame ordering, packet-loss tolerance, replay windows, rekeying, jitter handling, and low-latency authentication. They are intended to be handled by separate Vollcrypt protocol profiles such as:
- `@vollcrypt/streaming`
- `@vollcrypt/voice`

Vollcrypt Files focuses on encrypted file containers for local storage, cloud storage, and secure file sharing.

---

## Architecture and File Container Design

Vollcrypt Files operates on a chunk-by-chunk file container model. The format is optimized for large local files, cloud-stored encrypted objects, random-access reads, and secure shared-file opening.

```
+-----------------------------------------------------------+
|                      FILE CONTAINER                       |
+-----------------------------------------------------------+
| Header:                                                   |
|   - Magic Bytes ("VOLLVALT")                              |
|   - Version & Container Flags                             |
|   - File ID & Merkle Root                                 |
|   - Wrap Table & Extension Table                          |
|   - Signature (Optional, v2 only)                         |
+-----------------------------------------------------------+
| Chunk Envelopes:                                          |
|   +-----------------------------------------------------+ |
|   | Chunk 1: Index (4B) | IV (12B) | Cipher | Tag (16B) | |
|   +-----------------------------------------------------+ |
|   | Chunk 2: Index (4B) | IV (12B) | Cipher | Tag (16B) | |
|   +-----------------------------------------------------+ |
|   | ...                                                 | |
|   +-----------------------------------------------------+ |
+-----------------------------------------------------------+
|                  Merkle Root in Header                    |
|                            /\                             |
|                           /  \                            |
|                          /    \                           |
|                         /      \                          |
|                        /\      /\                         |
|                       /  \    /  \                        |
|                      /    \  /    \                       |
|                   Leaf 1 Leaf 2 Leaf 3 Leaf 4             |
+-----------------------------------------------------------+
|  Leaf 1: LeafHashV1(Chunk 1)                              |
|  LeafHashV1 = SHA-256("vollcrypt-file-merkle-leaf-v1" ||  |
|                file_id || index || len || IV1 || Tag1)    |
+-----------------------------------------------------------+
```

### 1. Header Layout

The layout of the file container header is length-prefixed and dynamically parsed.

| Offset | Length | Type | Description |
| :--- | :--- | :--- | :--- |
| 0 | 8 | Bytes | Magic Bytes (`VOLLVALT`) |
| 8 | 1 | u8 | Format Version |
| 9 | 1 | u8 | Container Flags |
| 10 | 1 | u8 | Cipher Suite ID |
| 11 | 1 | u8 | Header Encoding Version |
| 12 | 4 | u32 BE | Header Length |
| 16 | 16 | Bytes | File ID |
| 32 | 4 | u32 BE | Chunk Size |
| 36 | 8 | u64 BE | Plaintext Size |
| 44 | 32 | Bytes | Merkle Root |
| 76 | 4 | u32 BE | Wrap Count |
| 80 | 4 | u32 BE | Wrap Table Length |
| 84 | 4 | u32 BE | Extension Table Length |
| 88 | Var | Structs | Wrap Table |
| 88 + Wrap Table Length | Var | Structs | Extension Table |

#### Container Flags
The container does not have a single exclusive wrapping mode. Supported access methods are determined by the list of `WrapEntry` records. A file may contain password, recipient, and group wraps at the same time.

#### Wrap Table Length
`Wrap Table Length` is the total byte length of all concatenated `WrapEntry` records. Parsers MUST reject headers where the sum of parsed wrap entry sizes does not exactly equal `Wrap Table Length`.

#### Extension Table Length
Extensions may be marked as critical or non-critical. Implementations MUST reject files containing unknown critical extensions and MAY ignore unknown non-critical extensions.

### 2. Chunked File Container Engine

Vollcrypt Files supports streaming I/O internally, meaning files can be processed incrementally. This should not be confused with real-time transport streaming. Real-time network, media, and voice encryption are separate protocol profiles planned for future Vollcrypt modules.

#### Chunk Size Limits
Default chunk size: 1 MiB.

Recommended range:
- Minimum: 4 KiB
- Typical: 1 MiB to 16 MiB
- Large-file optimized: 16 MiB to 64 MiB

Very large chunk sizes may increase memory pressure, reduce random-access granularity, and are not recommended for general use even if the parser accepts them.

#### Sequential Full-File Decryption
The decryption engine can consume encrypted container bytes sequentially for full-file decryption, without requiring random seeks during normal full-file reads. Random-access reads are supported separately by seeking directly to chunk envelope offsets and verifying the selected chunk against the Merkle Root.

#### Cryptographic Access Control (Wrap Entries)
Each wrap entry starts with a 1-byte `wrap_type` and a 2-byte BE `payload_len`. `payload_len` excludes the 3-byte entry prefix (`wrap_type || payload_len`). Therefore, the total serialized size of a wrap entry is `3 + payload_len`.

- **Type 0: Password PBKDF2**
  - Payload Length: 60 bytes (Total Entry Length: 63 bytes)
  - Salt (16B) || Iterations (4B BE) || Wrapped DEK (40B)
- **Type 1: Password Argon2id**
  - Payload Length: 68 bytes (Total Entry Length: 71 bytes)
  - Salt (16B) || m_cost (4B BE) || t_cost (4B BE) || p_cost (4B BE) || Wrapped DEK (40B)
- **Type 2: Hybrid KEM Recipient Wrap**
  - Payload Length: 1188 bytes (Total Entry Length: 1191 bytes)
  - Recipient ID (16B) || Recipient Key Version / Wrap Context Version (4B BE) || Ephemeral X25519 PK (32B) || ML-KEM Ciphertext (1088B) || Wrapped DEK (40B)
  - For direct recipient wrapping, the version field represents the recipient key version. For group-mediated recipient wrapping, it MAY represent the group key epoch, depending on the wrap profile. Group-mediated recipient wraps MUST use a separate context label.
- **Type 3: Group Wrap**
  - Payload Length: 60 bytes (Total Entry Length: 63 bytes)
  - Group ID (16B) || GK Version (4B BE) || Wrapped DEK (40B)

> [!NOTE]
> **File Container Write Model**
> Vollcrypt Files stores the Merkle Root in the file header. During encryption, implementations may either:
> 1. Write a placeholder header, encrypt chunks sequentially, compute the Merkle Root, and then rewrite the header on seekable outputs such as local files; or
> 2. Build the encrypted container in a temporary buffer/file and write the final header once the Merkle Root is known.
>
> This design is intentional for encrypted file containers. Vollcrypt Files is not intended to be used as a live real-time transport stream protocol.

---

## Technical Foundations

### Password-Based Wrapping
Derives a Key Encryption Key (KEK) using Argon2id by default. PBKDF2-SHA256 is supported only for compatibility and legacy profiles. The DEK is wrapped using AES-256 Key Wrap (AES-KW).

New containers SHOULD use Argon2id. PBKDF2-based wrapping SHOULD only be used when compatibility with constrained or legacy environments is required.

### Hybrid KEM KEK Derivation
For Hybrid KEM recipient wraps, the KEK is derived as:

```
hybrid_secret = x25519_shared_secret || ml_kem_shared_secret

KEK = HKDF-SHA256(
  ikm = hybrid_secret,
  salt = file_id,
  info =
    "vollcrypt-file-hybrid-kem-v1" ||
    recipient_id[16] ||
    recipient_key_version_u32_be ||
    kem_suite_id ||
    cipher_suite_id,
  length = 32
)
```

### Chunk Key and IV Derivation
For chunk `i`, implementations derive separate AEAD key and IV material using domain-separated HKDF labels.

Recommended normative form:
```
chunk_key_i = HKDF-SHA256(
  ikm = DEK,
  salt = file_id,
  info = "vollcrypt-file-chunk-key-v1" || chunk_index_u32_be,
  length = 32
)

chunk_iv_i = HKDF-SHA256(
  ikm = DEK,
  salt = file_id,
  info = "vollcrypt-file-chunk-iv-v1" || chunk_index_u32_be,
  length = 12
)
```
The same `(chunk_key, chunk_iv)` pair MUST never be reused for different plaintext chunks.

### Chunk AEAD Associated Data
Each AES-256-GCM chunk encryption authenticates the following associated data:

```
AAD_FileChunk_V1 =
  "vollcrypt-file-chunk-aad-v1" ||
  header_hash[32] ||
  file_id[16] ||
  chunk_index_u32_be ||
  chunk_size_u32_be ||
  plaintext_size_u64_be ||
  chunk_plaintext_len_u32_be
```
Implementations MUST reject chunks if AEAD authentication fails. The header hash is derived as:
```
header_hash = SHA-256(canonical_header_without_mutable_fields)
```

### Merkle Tree Integrity Verification
To prevent malicious storage servers from replacing, reordering, or swapping chunk envelopes, Vollcrypt Files constructs a Merkle Tree over canonical chunk leaf hashes.

For format version 1, each leaf is computed using SHA-256 by default:
```
LeafHashV1_Sha256 =
SHA-256(
  "vollcrypt-file-merkle-leaf-v1" ||
  file_id[16] ||
  chunk_index_u32_be ||
  chunk_plaintext_len_u32_be ||
  iv[12] ||
  auth_tag[16]
)
```

For the optional BLAKE3 high-performance profile, `LeafHashV1` and internal Merkle tree nodes are computed using BLAKE3:
```
LeafHashV1_Blake3 =
BLAKE3(
  "vollcrypt-file-merkle-leaf-v1" ||
  file_id[16] ||
  chunk_index_u32_be ||
  chunk_plaintext_len_u32_be ||
  iv[12] ||
  auth_tag[16]
)
```
The ciphertext payload is intentionally excluded from the Merkle leaf because AES-256-GCM already authenticates the ciphertext through the authentication tag.

### Merkle Proof Storage Modes
Vollcrypt Files supports the following verification modes:

1. **Full-file verification**: The reader verifies the complete container by processing all chunk tags and recomputing the Merkle Root. No external proof storage is required.
2. **Embedded proof index**: Merkle proofs or proof indexes are stored inside the encrypted container metadata. This mode is suitable for self-contained shared files and cloud range reads.
3. **Sidecar proof file**: Proof metadata is stored in a separate `.vproof` sidecar file. The sidecar file hash MUST be bound to the main container header.
4. **Remote metadata service**: Proofs may be fetched from a metadata service. The service is not trusted; all proofs MUST verify against the Merkle Root stored in the signed/trusted file header.

### Canonical Encoding and Parser Rules
Implementations MUST:
- Parse all multibyte integers as Big-Endian.
- Reject non-canonical header encodings.
- Reject duplicate critical extensions.
- Reject headers where `header_len`, `wrap_count`, and `wrap_table_len` disagree.
- Reject unknown critical extensions.
- Reject trailing bytes inside the declared header region.
- Reject chunk envelopes whose encoded chunk index does not match their expected position.
- Reject containers with zero valid wraps unless explicitly opened in a shredded/deleted-key inspection mode.

A container with zero wraps may be parsed for inspection, but it is not decryptable through normal APIs. Normal encrypted containers MUST contain at least one valid `WrapEntry`. Zero-wrap containers MAY be used to represent key-shredded files whose ciphertext remains stored but whose DEK can no longer be recovered.

### Revocation & Manifest Limits

#### Revocation Model
Vollcrypt group revocation has multiple modes:
1. **Lazy Revocation**: Removed members stop receiving future group keys. Historical files may remain decryptable if the removed member previously cached the required keys.
2. **Forward-Only Revocation**: New files are encrypted under a new group key epoch. Old files are not automatically re-encrypted.
3. **Strict Revocation**: Existing files are rewrapped or re-encrypted under a new key epoch. This is more expensive but prevents removed members from opening files.

#### Manifest Scaling
For large groups, manifest size and verification cost grow with the number of operations and members. Applications targeting very large groups should consider checkpointing, manifest compaction, or epoch snapshots.

---

## Quick Start

### High-Level API Usage

```typescript
import { files } from "@vollcrypt/files";

// Encrypt file
const header = await files.encryptFile({
  input: "report.pdf",
  output: "report.pdf.voll",
  password: "my-secure-password",
  recipients: [aliceRecipientId],
});

// Decrypt file
await files.decryptFile({
  input: "report.pdf.voll",
  output: "report.pdf",
  password: "my-secure-password",
});

// Open a shared file
const keyHandle = await files.openSharedFile({
  input: "report.pdf.voll",
  recipientKey: myRecipientKey,
});
```

### Advanced Asynchronous Pipelined File API (Zero-Copy)

```typescript
import { 
  generateDek, 
  generateFileId, 
  encryptFilePipelinedAsync, 
  decryptFilePipelinedAsync 
} from "@vollcrypt/files-node";

const dek = generateDek();
const fileId = generateFileId();

// Asynchronously encrypt a file using 4 parallel thread workers
const header = await encryptFilePipelinedAsync(
  "./input.txt",
  "./input.enc",
  dek,
  fileId,
  65536, // 64 KB chunk size
  [],    // wraps
  0,     // mode (0 = Password)
  4,     // thread workers
  null   // optional signInfo
);

// Asynchronously decrypt the file
await decryptFilePipelinedAsync(
  "./input.enc",
  "./input.dec",
  dek,
  4      // thread workers
);
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

## Advanced API Reference (Bindings)

- `generateDek()`: Generate a cryptographically secure 32-byte Data Encryption Key.
- `generateFileId()`: Generate a cryptographically secure 16-byte File ID.
- `generateSalt()`: Generate a cryptographically secure 16-byte Salt.
- `generateGk()`: Generate a cryptographically secure 32-byte Group Key.
- `encryptChunk(dek, file_id, chunkIndex, plaintext)`: Encrypt a single block of plaintext.
- `decryptChunk(dek, file_id, chunkIndex, envelope)`: Decrypt a single chunk envelope.
- `encryptFilePipelinedAsync(sourcePath, destPath, dek, fileId, chunkSize, wraps, mode, numWorkers, signInfo)`: Asynchronously encrypts a file from disk using parallel thread workers (Zero-Copy V8 heap footprint).
- `decryptFilePipelinedAsync(sourcePath, destPath, dek, numWorkers)`: Asynchronously decrypts a file from disk using parallel thread workers (Zero-Copy V8 heap footprint).
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

#### Low-Level Random-Access Parsing Example:
```typescript
const { header, headerLen } = await Header.readFrom(file, {
  maxHeaderSize: 16 * 1024 * 1024
});

Implementations MUST NOT assume a fixed small header size. The header is length-prefixed and may grow with the number of recipients, group metadata, and extensions.

const keyHandle = await files.openKeyFromPassword(password, header);

// Fetch a single chunk out-of-order
const chunkIndex = 42;
const envelope = await fetchChunkEnvelope(file, header, chunkIndex);

// Validate and check parsed index matches the expectation
if (envelope.chunkIndex !== chunkIndex) {
  throw new Error(`Chunk index mismatch: expected ${chunkIndex}, got ${envelope.chunkIndex}`);
}

const plaintext = await files.decryptChunk(envelope, keyHandle);

// Verify leaf integrity locally
const leafHash = chunkLeafHash({
  fileId: header.fileId,
  chunkIndex: envelope.chunkIndex,
  chunkPlaintextLen: plaintext.length,
  iv: envelope.iv,
  tag: envelope.tag
});
assert.ok(verifyMerkleProof(leafHash, chunkIndex, totalChunks, proof, header.merkleRoot));

keyHandle.destroy();
```

---

## Memory & Sandbox Protection

### JavaScript/WASM Memory Caveat
Rust-owned secret material is zeroized using `Zeroize` and `ZeroizeOnDrop`.

When using Node.js or WebAssembly bindings, JavaScript runtimes may copy secrets in ways that cannot be fully zeroized by the native library. Callers SHOULD avoid immutable strings for passwords and SHOULD clear user-owned `Uint8Array` / `Buffer` values after use.

### Unsafe Code Scope
The Rust cryptographic core is implemented without `unsafe` code. Node.js and WebAssembly bindings are thin wrappers around the safe Rust core.

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
By default, the WebAssembly module compiles with 128-bit SIMD acceleration enabled (`target-feature=+simd128`).
To compile:
```bash
cd wasm
npm install
npm run build
npm test
```
To compile a portable fallback build without SIMD features, override the target flags:
```bash
RUSTFLAGS="" npm run build
```

---

## Performance & Optimizations

Vollcrypt File has undergone targeted performance optimizations to achieve peak single-core throughput and resolve encryption/decryption asymmetry:

- **Merkle Leaf Hash Optimization:** Omits ciphertext payload from Merkle tree leaf hashing, only hashing the canonical chunk metadata and authentication tag: `domain || file_id || chunk_index || chunk_plaintext_len || iv || tag`. This avoids double-pass processing (AES-GCM + SHA-256) of full file contents.
- **Deterministic IV Derivation:** Derives chunk key material and IV material from the DEK using domain-separated HKDF labels, avoiding per-chunk `OsRng` calls while preserving nonce uniqueness under the file-specific DEK and file ID.
- **Optional BLAKE3 Hashing Profile:** Supports swapping SHA-256 for BLAKE3 within the Merkle tree verification process, yielding massive speedups on systems without hardware-accelerated SHA-NI instructions.
- **WebAssembly 128-bit SIMD Acceleration:** Compiles the browser WebAssembly package with the `+simd128` target feature flag, allowing Rust cryptographic primitives to run with SIMD parallel hardware instructions directly inside modern browsers.
- **Architecture-Specific Speedups:** Set default compilation profile targeting `x86-64-v3`, allowing optional native overrides (`RUSTFLAGS="-C target-cpu=native"`) to fully unlock hardware acceleration (AVX2, AES-NI, SHA-NI).

### Benchmark Results (AMD Ryzen 5 7500F @ 3.70 GHz)

#### Device Profile for Tests:
- **CPU:** AMD Ryzen 5 7500F @ 3.70 GHz (6 physical cores, 12 logical threads)
- **GPU:** NVIDIA GeForce GTX 1660 SUPER
- **Disk:** D:\ [HDD] (733.8 GB free / 931.5 GB total); C:\ [SSD] (27.4 GB free / 465.1 GB total)
- **RAM Utilized:** Min 39.5%, Max 59.0%, Avg 43.1%
- **CPU Utilized:** Min 11.7%, Max 63.8%, Avg 20.5%

#### Pipelined Performance Metrics Suite
| Metric | Balanced Profile (256MB, 1MB chunk) | Max Profile (1GB, 8MB chunk) | Detail |
| --- | --- | --- | --- |
| Throughput | 1.56 GB/s | 1.79 GB/s | Aggregate gigabytes per second |
| Cycles/Byte | 2.21 | 1.92 | CPU clock cycles per byte encrypted |
| Instructions/Byte | 2.77 | 2.40 | CPU instructions executed per byte |
| Allocations/Chunk | 2 | 2 | Number of heap allocations per chunk |
| Bytes Copied/Byte Encrypted | 2.0 | 2.0 | Total buffer copy amplification ratio |
| Cache Misses/GB | 150,122 | 150,015 | Modeled cache misses per gigabyte |
| Branch Misses/GB | 50,460 | 50,057 | Modeled branch mispredictions per gigabyte |
| Worker Idle Time | 0.0% | 0.0% | Time workers spent waiting for queue |
| Queue Wait Time | 0.1% | 0.1% | Average time chunks spent in queue |
| I/O Wait Time | 0.5% | 0.5% | Average time spent in disk/stream I/O |
| Merkle Time / Total | 0.02% | 0.01% | Percentage of time spent in Merkle tree |
| HKDF Time / Total | 0.06% | 0.01% | Percentage of time spent in HKDF subkeys |
| AEAD Time / Total | 112.08% | 124.65% | Percentage of time spent in AEAD crypto |
| Energy Estimate | 48.13 J/GB | 41.85 J/GB | Estimated energy consumption per GB |
| Time to First Verified Plaintext | 0.47 ms | 3.64 ms | Latency to verify and decrypt chunk 0 |

#### Chunk Latency & Throughput (Single-Core)
| Operation | Input Size | Latency (median) | Latency (p99) | Throughput |
| --- | --- | --- | --- | --- |
| `encrypt_chunk` | 4 KB | 2.80 μs | 6.70 μs | 1395.09 MB/s |
| `decrypt_chunk` | 4 KB | 2.90 μs | 4.10 μs | 1346.98 MB/s |
| `encrypt_chunk` | 64 KB | 36.00 μs | 55.20 μs | 1736.11 MB/s |
| `decrypt_chunk` | 64 KB | 36.90 μs | 55.10 μs | 1693.77 MB/s |
| `encrypt_chunk` | 1 MB | 880.90 μs | 1059.20 μs | 1135.20 MB/s |
| `decrypt_chunk` | 1 MB | 723.00 μs | 896.40 μs | 1383.13 MB/s |
| `encrypt_chunk` | 4 MB | 2683.20 μs | 3146.60 μs | 1490.76 MB/s |
| `decrypt_chunk` | 4 MB | 2658.80 μs | 2678.50 μs | 1504.44 MB/s |
| `encrypt_chunk` | 16 MB | 10543.30 μs | 11821.10 μs | 1517.55 MB/s |
| `decrypt_chunk` | 16 MB | 10669.50 μs | 11022.40 μs | 1499.60 MB/s |

#### Competitor Comparison (1 GB Single-Threaded)
All baseline timings measured dynamically on the same AMD Ryzen 5 7500F test system:
- **Vollcrypt File:** 6.76 s (measured)
- **OpenSSL Baseline:** 0.78 s (measured on device)
- **Age Baseline:** 1.63 s (measured on device)

### Benchmark CLI

Vollcrypt Files includes a dedicated benchmark and resource monitoring harness binary named `vollcrypt`. You can use this CLI to run automated suites, sweep configurations, profile specific parameters, and inspect real-time CPU/RAM/Disk stats:

```bash
# Run the full automated suite (generates markdown files under reports/)
cargo run --release -p vollcrypt-files-bench --bin vollcrypt -- bench --suite auto

# Profile specific configurations with JSON output
cargo run --release -p vollcrypt-files-bench --bin vollcrypt -- bench --profile balanced --json

# Profile max configuration and compare against local OpenSSL/Age baselines
cargo run --release -p vollcrypt-files-bench --bin vollcrypt -- bench --profile max --compare

# Sweep chunk sizes (from 4 KB to 16 MB)
cargo run --release -p vollcrypt-files-bench --bin vollcrypt -- bench --sweep chunk-size

# Sweep worker threads to evaluate parallel scaling
cargo run --release -p vollcrypt-files-bench --bin vollcrypt -- bench --sweep workers
```

### Test & Security Scorecard

The current test suite includes stress, fuzzing, tampering, replay, and forgery-resistance tests. Passing these tests does not constitute a formal proof or third-party audit, but it provides implementation-level hardening coverage for the tested attack classes.

- Bit-flip tests: 8,000 modified ciphertext bits tested, 0 accepted.
- Tag forgery tests: 1,000,000 random forged tags tested, 0 accepted.
- Header tampering tests: modified header fields rejected.
- Replay/substitution tests: tested against cross-file and chunk substitution attempts.
- Linter: 100% clean Clippy builds under `-- -D warnings` on all target formats.

---

## Vollcrypt Protocol Family

Vollcrypt is designed as a family of interoperable E2EE protocol profiles.

Each profile uses shared cryptographic primitives from `@vollcrypt/core`, but each profile has its own domain separation labels, metadata format, and threat model.

Current profiles:
- `files`: encrypted file containers;
- `messages`: message payload encryption.

Planned profiles:
- `streaming`: real-time stream encryption;
- `voice`: low-latency media encryption.
