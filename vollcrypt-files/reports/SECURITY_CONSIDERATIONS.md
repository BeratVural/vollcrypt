# SECURITY CONSIDERATIONS

## 1. Guarantees Enforced by the Library

The following table summarizes the cryptographic and security guarantees enforced by the library and verified dynamically by the adversarial test suite:

| Guarantee | Attack Vector Mitigated | Enforcing Mechanism | Adversarial Test | Verdict |
|---|---|---|---|---|
| **Chunk Confidentiality** | Plaintext exposure, eavesdropping | AES-256-GCM encryption with unique nonces | `Bit-flip Resistance` | **✓ Secure** |
| **Cross-Chunk Integrity** | Chunk deletion, reordering, truncation | RFC 6962 domain separated Merkle Tree (`0x00` leaf / `0x01` internal node) + length binding (total chunk count u64 BE bound to root) | `A.1`, `A.2`, `A.3` | **✓ Secure** |
| **Header-Body Binding** | Replay, chunk splicing across files | Merkle root, `file_id`, and `chunk_index` bound as AAD for each chunk | `A.3`, `B.1` | **✓ Secure** |
| **Header Authenticity** | Unsigned configuration tampering | Plain/Sealed signed metadata with cryptographic signature | `B.1`, `B.2` | **✓ Secure** |
| **Downgrade Resistance** | Stripping signatures to bypass checks | Enforced policy checks: rejecting legacy headers/manifests when `require_signed` or `require_pq_signature` is enabled | `B.2`, `H_downgrade` | **✓ Secure** |
| **DoS Mitigation** | Resource exhaustion (Memory/CPU) | `chunk_size` limit (capped at 16MB) and Argon2 KDF param checks (capping $m \le 64\text{MB}$, $t \le 5$) | `C.1`, `C.2`, `C.3` | **✓ Secure** |
| **Hybrid KEM Binding** | Key substitution, recipient identity swap | X-Wing combiner: `combined_key = SHA3-256(LABEL || ss_mlkem || ss_x || ct_x || pk_x || recipient_id || gk_version)` | `D.1`, `D.2`, `D.3` | **✓ Secure** |
| **Rollback Detection** | Reverting manifest ledger to old state | Monotonic epoch verification + client-side state pinning | `F.2` | **✓ Secure** |
| **Sealed Metadata Privacy** | Timing and error-type side channels | Constant error status (`WrongGroupKey`) + unified constant-time verification fallback | `G.1` | **✓ Secure** |
| **WASM Side-Channel Resistance** | Cache timing attacks on WebAssembly | Software AES-256-GCM implemented via bitsliced, fixslice constant-time operations | `G.2` | **✓ Secure** |
| **Post-Quantum Authenticity** | Shor's algorithm signature forgery | Ed25519 + ML-DSA-65 hybrid signature (AND-combiner) | `H.1_ed_only_forge`, `H.1_mldsa_only_forge`, `H_key_substitution` | **✓ Secure** |

---

## 2. Consumer Contract (Application Responsibilities)

The library operates in a stateless manner for many of its core operations. Consequently, the calling application **must** adhere to the following contract to maintain system-wide security:

1. **Authenticity Enforcement**:
   - The application must actively pass `require_signed: true` or `require_pq_signature: true` to the header and manifest verification functions. If left disabled, the library will parse legacy unsigned (version 1) or classical-only (version 2) configurations without raising an error. Authenticity must be explicitly enforced at policy enforcement boundaries.
2. **State Pinning against Rollbacks**:
   - To defend against manifest rollbacks (`F.2`), the client must persist the last known `manifest_head()` (comprising the `head_hash` and `epoch`) in local, secure storage. When loading the manifest next, this pin must be passed to `verify_manifest_with_pin`. Without this local pin, a stateless client will accept any valid historical manifest prefix.
3. **Equivocation Detection**:
   - Conflicting manifest forks (`F.1`) signed by the same authorized administrator cannot be prevented by a stateless client. The application must invoke `detect_equivocation()` and resolve conflicts by comparing heads out-of-band (e.g., using a gossip protocol, transparency ledger, or consensus witness).
4. **Eager Revocation Sequence**:
   - To revoke a group member's access, the application must execute the **eager sequence**: `removeMember` followed immediately by `rotateGroupKey` and a file `rewrap` operation. 
   - Calling `removeMember` only prevents the member from getting updates; they can still decrypt historical files using the old group key (`E.2`).
   - Furthermore, a revoked member who already possesses the decrypted Data Encryption Key (DEK) can decrypt historical files indefinitely (`E.1`). True revocation of historical data requires re-encrypting the data with a fresh DEK.

---

## 3. Conscious Design Limitations

The following properties represent intentional design trade-offs made in the library. Applications must model their threat assessments accordingly:

### E.1: `rotation_dek_invariance` (Forward Secrecy Limitation)
* **What**: Running a `rewrap` operation rotates the Key Encrypting Key (KEK) using a new Group Key but leaves the underlying Data Encryption Key (DEK) and chunk subkeys unchanged.
* **Why**: Re-encrypting gigabytes or terabytes of file data to rotate a DEK is computationally and I/O expensive, especially on mobile or resource-constrained devices.
* **Mitigation**: Once a member has obtained the plaintext of a DEK for a specific file version, rotating the Group Key and executing a `rewrap` will not cryptographically revoke their access to the historical plaintext of that file. Verified plaintext already shared with a member is cryptographically impossible to revoke. If absolute forward secrecy (ensuring a revoked member cannot read new additions to the file, or preventing historical read capabilities of modified files) is required, the application must perform a full re-encryption of the file payload using a newly generated DEK.

### E.2: `lazy_revocation_window` (Revocation Delay)
* **What**: The `removeMember` operation modifies the group manifest but does not automatically rotate the Group Key. The removed member can still access and decrypt files encrypted under the active group key until a rotation occurs.
* **Why**: Automatic rotation on every member removal requires distributing new wrapped keys to all remaining members, creating significant write amplification and requiring active network coordination.
* **Mitigation**: Applications must execute the eager revocation sequence (`removeMember` -> `rotateGroupKey` -> `rewrap`) to close this window immediately. For improved API ergonomics, it is recommended that the calling wrapper either automatically trigger a key rotation when `removeMember` is called, or explicitly return a warning status/signal indicating that access has not yet been cryptographically revoked.

### F.1: `manifest_fork` (Equivocation)
* **What**: An administrator can sign two conflicting ledger operations pointing to the same parent epoch, creating two valid diverging histories.
* **Why**: In a single-administrator append-only log without a consensus mechanism or distributed consistency anchor, preventing equivocation is mathematically impossible.
* **Mitigation**: Stateless clients must use `detect_equivocation()` to identify conflicting manifests. To prevent equivocation, applications must compare manifest heads out-of-band. It is recommended to publish signed manifest heads (`manifest_head()`) to a public, append-only log (similar to Certificate Transparency), or use a decentralized consensus witness network to enforce a single canonical state timeline.

### G.3: `aes_kw_determinism` (Key Wrap Determinism)
* **What**: The AES Key Wrap algorithm (RFC 3394) is deterministic. Wrapping the same DEK under the same KEK multiple times will yield identical ciphertexts.
* **Why**: The standard key wrap does not require random nonces, saving space and preventing entropy depletion attacks in low-resource environments.
* **Mitigation**: An attacker monitoring the header can identify duplicate DEK usage across different wrapped files or recipients. This does not compromise key secrecy or data confidentiality. This is a low-risk design trade-off. If this leakage is unacceptable, applications should derive unique KEKs per wrap or use a per-wrap randomized key derivation scheme.

---

## 4. Post-Quantum Hybrid Signature Architecture (Ed25519 + ML-DSA-65)

Vollcrypt File implements a **hybrid post-quantum digital signature scheme** combining:
* **Classical Security**: Ed25519 (via the `ed25519-dalek` crate).
* **Post-Quantum Security**: ML-DSA-65 (FIPS 204 final standard).

### Strict AND-Combiner
For a hybrid signature verification to succeed, it must pass verification under **both** algorithms:
$$\text{Verify}_{\text{Hybrid}}(\text{Sig}) = \text{Verify}_{\text{Ed25519}}(\text{Sig}_{\text{classical}}) \land \text{Verify}_{\text{ML-DSA-65}}(\text{Sig}_{\text{pq}})$$

This design provides cryptographic hedging: the system remains secure even if one of the underlying algorithms is completely broken (e.g., if a cryptanalytically relevant quantum computer breaks Ed25519 using Shor's algorithm, the ML-DSA-65 signature still protects authenticity; conversely, if a structural weakness is found in ML-DSA-65, Ed25519 remains intact). The combiner is fail-closed.

### Cryptographic Transcript Binding & Domain Separation
To prevent key substitution, identity misbinding, and replay attacks, both public keys and a domain separation label are bound into the message signed by the cryptographic primitives.

Instead of signing the raw payload $M$ directly, both algorithms sign the modified message $M'$ defined as:
$$M' = \text{DOMAIN\_LABEL} \mathbin{\Vert} \text{PK}_{\text{ed25519}} \mathbin{\Vert} \text{PK}_{\text{mldsa}} \mathbin{\Vert} \text{Len}(\text{Context})_{\text{2B BE}} \mathbin{\Vert} \text{Context} \mathbin{\Vert} M$$

The domain label separates signatures by context:
* **`vollf-hdr-plain`**: For version 3 plain headers.
* **`vollf-hdr-sealed`**: For version 3 sealed group headers.
* **`vollf-manifest-op`**: For group manifest ledger operations.
* **`vollf-keylog-entry`**: For key registry events.

### Hedged Signing & Fault Mitigation
ML-DSA signature generation is randomized (hedged) by default. The signing algorithm ingests system entropy (via `rand::rngs::OsRng`) as a seed.
* **Side-Channel/Fault Protection**: Purely deterministic signing algorithms (where the signature is a deterministic function of the secret key and message) are vulnerable to differential fault analysis (DFA). If an attacker induces a hardware glitch during signing, they can recover the secret key. Introducing fresh entropy during signing disrupts deterministic relations, protecting the secret key against fault injection and side-channel analysis.

### Downgrade Protection & Policy Enforcements
Vollcrypt File maintains backward compatibility with version 1 (unsigned) and version 2 (Ed25519-only) headers and manifests. However, this introduces a risk of **downgrade attacks**, where an active attacker strips the PQ signature component to force the client into classical-only verification.

When the high-security policy flag `require_pq_signature: bool` is set to `true`:
* Any legacy v1 or v2 headers are rejected immediately with `IntegrityError`.
* Any manifest operations lacking an ML-DSA-65 signature component are rejected.
* Legacy classical-only public keys or device registrations in the `KeyLog` are rejected.

This ensures that clients operating in PQ-security mode cannot be tricked into accepting classical-only authenticity proofs.

### Key and Signature Encodings
The hybrid primitives result in significantly larger structures compared to classical-only cryptography. Developers must account for the following binary sizes when managing storage and network allocations:

| Structure | Classical Component | PQ Component | Hybrid Structure Size |
|---|---|---|---|
| **PublicKey** | Ed25519 (32 bytes) | ML-DSA-65 (1952 bytes) | **1984 bytes** |
| **SecretKey** | Ed25519 (32 bytes) | ML-DSA-65 (4032 bytes) | **4064 bytes** |
| **Signature** | Ed25519 (64 bytes) | ML-DSA-65 (3309 bytes) + Len (2B) | **3375 bytes** |

### Zeroization of Sensitive Memory
Memory safety and key secrecy are critical. All structures holding sensitive cryptographic material, including the `SecretKey` and temporary buffers used during key encapsulation and signature generation, implement the `Zeroize` trait (or utilize types that zero-on-drop). This ensures that key material is scrubbed from RAM immediately after use, mitigating memory exposure attacks and cold-boot vulnerabilities.

---

## 5. Cryptographic Suite Summary (v0.1)

The following table summarizes the cryptographic algorithms and parameters utilized in Vollcrypt File:

| Primitive | Algorithm | Output/Key Sizes | Security Profile |
|---|---|---|---|
| **Bulk Encryption** | AES-256-GCM | 256-bit key, 96-bit nonce, 128-bit tag | Classical Symmetric |
| **KDF / Subkey Derivation** | HKDF-SHA256 | 256-bit derived key material | Classical Symmetric |
| **Integrity Tree** | SHA-256 Merkle Tree | 256-bit root, domain prefixes `0x00`/`0x01` | Classical Hash |
| **Key Wrapping** | AES-256-KW (RFC 3394) | 40-byte wrapped output | Classical Symmetric |
| **Password KDF** | PBKDF2-HMAC-SHA256 / Argon2id | Parameter-capped ($m\le64\text{MB}$) | Classical Symmetric |
| **Key Transport** | X-Wing (X25519 + ML-KEM-768) | 256-bit combined shared secret | **Post-Quantum Hybrid** |
| **Digital Signatures** | Ed25519 + ML-DSA-65 | 1984-byte PK, 3375-byte Signature | **Post-Quantum Hybrid** |

---

## 6. Closing Note

This document reflects the security state verified dynamically by the Vollcrypt File adversarial test suite. Any changes to the adversarial suite must be accompanied by updates to this document within the same commit.

> [!WARNING]
> The verdict "Identified Findings: None" denotes that the library is clean against the specific set of attack vectors represented in the adversarial suite. It does not replace an independent external cryptographic and implementation audit (e.g., by entities such as Trail of Bits, NCC Group, or Cure53) which must be completed prior to General Availability (GA).
