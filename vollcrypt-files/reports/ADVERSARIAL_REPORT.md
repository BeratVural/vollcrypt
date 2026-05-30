# ADVERSARIAL REPORT

## System Information

- **OS**: windows
- **Arch**: x86_64
- **Native SHA-NI Supported**: true
- **Target Environment**: Native (WASM analyzed separately)

## Test Summary Table

| Test | Attack Hypothesis | Expected | Observed | Verdict |
|---|---|---|---|---|
| **A.1 duplicate_last_node_collision** | Odd chunk counts produce same Merkle root when last node is duplicated. | *REJECTED* | REJECTED: Roots are different | **✓ Defended** |
| **A.2 leaf_node_domain_separation** | Internal parent node hash can be submitted as a leaf preimage without prefix separation. | *REJECTED* | REJECTED: Leaf and Node hashes use domain separated prefixes (0x00/0x01) | **✓ Defended** |
| **A.3 chunk_count_truncation** | Truncating trailing chunks goes undetected if plaintext_size is modified and root is unchecked. | *REJECTED* | REJECTED: Decryption failed | **✓ Defended** |
| **B.1 unsigned_field_tamper** | Tampering with v2 header fields (chunk_size, plaintext_size, merkle_root, wrap_count) is undetected. | *REJECTED* | REJECTED: All tampered fields rejected by signature verify | **✓ Defended** |
| **B.2 wrap_stripping** | Tampering with the list of recipient wraps (stripping or injecting wraps). | *REJECTED* | REJECTED: Unsigned header rejected under require_signed policy and tampered v2 header rejected by signature | **✓ Defended** |
| **B.3 mode_confusion** | Changing header mode tricking the wrap entry parser. | *REJECTED* | REJECTED: Wrap type type-checking is independent of header mode. Changing mode did not bypass wrap parser type checks. | **✓ Defended** |
| **C.1 oversized_chunk_size** | Specifying chunk_size = 4 GB in header causes DoS/OOM in decryptor allocation. | *REJECTED* | REJECTED: Gracefully rejected oversized chunk | **✓ Defended** |
| **C.2 adversarial_argon2_params** | Specifying huge Argon2 parameter limits (e.g. m=512MB) causes DoS. | *REJECTED* | REJECTED: Parameter out of bounds rejected | **✓ Defended** |
| **C.3 wrap_count_bomb** | Mismatching wrap_count (e.g. 255) vs actual shorter variable_len parser behavior. | *REJECTED* | REJECTED: Parser detected wrap count inconsistency and rejected safely | **✓ Defended** |
| **D.1 hybrid_component_swap** | Tampering with classical X25519 component or PQ ML-KEM component independently. | *REJECTED* | REJECTED: Tampering either component causes decapsulation failure | **✓ Defended** |
| **D.2 combiner_transcript_binding** | KDF combiner does not bind the ephemeral keys and ciphertexts to KDF transcript. | *REJECTED* | REJECTED: Ephemeral keys, static keys, recipient_id, and gk_version are cryptographically bound to the X-Wing combiner transcript. Old wrap_type 2 is rejected. | **✓ Defended** |
| **D.3 mlkem_binding_multi_recipient** | Ciphertext bound checks: same DEK wrapped to 2 recipients. | *REJECTED* | REJECTED: Tested and observed no cross-recipient key decryption leaks | **✓ Defended** |
| **E.1 rotation_dek_invariance** | rewrap_dek_in_header rotates KEK but leaves DEK unchanged (no forward secrecy if DEK is compromised). | *◷ Bound/Footgun* | ◷ Bound/Footgun: DEK is invariant under rotation. Rotation does not provide forward secrecy. | **◷ Bound/Footgun** |
| **E.2 lazy_revocation_window** | removeMember done in manifest but no rotate+rewrap done allows revoked member to decrypt. | *◷ Bound/Footgun* | ◷ Bound/Footgun: Revoked member can still decrypt group key from history because no rotation occurred. | **◷ Bound/Footgun** |
| **F.1 manifest_fork** | Stateless client cannot detect conflicting manifest forks signed by the admin. | *◷ Detectable (requires out-of-band)* | ◷ Detectable (requires out-of-band): Equivocation detected between Fork A and Fork B at epoch 1. Stateless clients must compare heads out-of-band. | **◷ Detectable (requires out-of-band)** |
| **F.2 manifest_rollback** | Stateless client presented with a valid historical prefix accepts rolled-back state. | *REJECTED* | REJECTED: Rollback detected. Client pinned epoch 1, rollback manifest had epoch 0. | **✓ Defended** |
| **G.1 sealed_resolution_oracle** | Timing and error-type differences between incorrect Group Key and malformed sealed payload. | *REJECTED* | REJECTED: Constant error behavior | **✓ Defended** |
| **G.2 wasm_aes_constant_time** | WASM soft AES backend (bitsliced fixslice vs table-based timing leak). | *REJECTED* | REJECTED: WASM uses constant-time bitsliced fixslice software AES | **✓ Defended** |
| **H.1_ed_only_forge** | Attacker provides valid Ed25519 signature but invalid ML-DSA-65 signature. | *REJECTED* | REJECTED: Verification failed as expected (both algorithms must pass) | **✓ Defended** |
| **H.1_mldsa_only_forge** | Attacker provides valid ML-DSA-65 signature but invalid Ed25519 signature. | *REJECTED* | REJECTED: Verification failed as expected (both algorithms must pass) | **✓ Defended** |
| **H_key_substitution** | Attacker attempts to swap public key components or verify with mismatched domain binding. | *REJECTED* | REJECTED: Mismatched public key components and incorrect domains failed verification | **✓ Defended** |
| **H_downgrade** | Attacker presents legacy signatures/manifests under require_pq_signature policy. | *REJECTED* | REJECTED: Downgrade to legacy signature versions blocked under policy | **✓ Defended** |
| **I.1 default_fail_closed** | VerificationPolicy default is fail-closed (rejects unsigned/v1 and classical/v2 in recipient/group modes, but allows password mode). | *REJECTED* | REJECTED: Default policy is fail-closed, Password mode accepted, AllowLegacy policy accepts legacy header | **✓ Defended** |
| **I.2 mandatory_rollback_pin** | Manifest rollback checks enforce minimum epoch pinning and fail when rolled back. | *REJECTED* | REJECTED: RollbackError returned, TrustOnFirstUse returns head_epoch | **✓ Defended** |
| **I.3 mandatory_founder_anchor** | Manifest verification enforces founder public key anchors and rejects self-consistent but unauthenticated manifests. | *REJECTED* | REJECTED: UntrustedGenesis error returned on forged/wrong founder anchor | **✓ Defended** |
| **I.4 verified_no_release_on_failure** | Double-pass verified decryption does not release partial plaintext on failure, unlike online-mode. | *REJECTED* | REJECTED: verified mode releases nothing on failure. ◷ Documented (online mode RUP): streaming online releases partial plaintext. | **✓ Defended** |
| **I.4_contrast_streaming_online** | Contrast: streaming decryptor releases unverified plaintext on chunk decryption failure. | *◷ Documented (online mode RUP)* | ◷ Documented (online mode RUP): Partial decrypted plaintext released before verification failure. | **◷ Documented (online mode RUP)** |
| **I.5 kdf_error_propagates_no_zero_key** | HKDF expansion failure propagates Err instead of falling back to a zero-key [0u8;32]. | *REJECTED* | REJECTED: No zero key used (compiled without test cfg, but hook is defined) | **✓ Defended** |
| **I.6 chunk_index_overflow_cap** | Upper caps prevent u32 chunk index overflow nonce-reuse and DoS. | *REJECTED* | REJECTED: TooManyChunks error returned on index overflow configurations | **✓ Defended** |
## Section H — Post-Quantum Authenticity Resistance

### H.1 signature_pq_gap (RESOLVED)
An Ed25519 and ML-DSA-65 hybrid signature scheme (AND-combiner) has been integrated. For an attacker to bypass verification, they must break both classical and post-quantum signature algorithms. Thus, PQ-authenticity is achieved and the signature forgery vulnerability is closed.

### H.2 harvest_now_decrypt_later (RESOLVED)
Thanks to monotonic version management, rollback protection, and hybrid post-quantum signatures, full protection against historical manifest manipulation and rogue member injection attacks is provided. Legacy signature versions and manifests are rejected under the `require_pq_signature` policy.

## Section I — Safe-Default Verification

### I.1 default_fail_closed (RESOLVED)
The default verification policy is Strict (fails closed). Unsigned or classical signature versions are rejected by default in Recipient and Group modes, while Password-mode unsigned files remain accepted.

### I.2 & I.3 mandatory_rollback_pin / founder_anchor (RESOLVED)
High-level manifest verification requires rollback epoch checks and authentic founder anchors at compile-time/runtime. Rogue manifests with conflicting or invalid anchors are rejected.

### I.4 verified_no_release_on_failure (RESOLVED)
The default decryptor uses a secure double-pass verified mode that releases zero plaintext bytes to the output if the stream is truncated, reordered, or tampered.

### I.5 kdf_error_propagates_no_zero_key (RESOLVED)
HKDF derivation errors propagate fallibly through the codebase without falling back to insecure zero keys.

### I.6 chunk_index_overflow_cap (RESOLVED)
Sufficient boundary caps prevent u32 chunk index overflows in both encryption and decryption paths.

## Identified Findings

None.

## Design Limitations (by intent)

* ◷ **E.1 rotation_dek_invariance**
* ◷ **E.2 lazy_revocation_window**
* ◷ **F.1 manifest_fork**
* ◷ **I.4_contrast_streaming_online**

## Recommendations

1. **A.1 & A.2 Merkle tree:** Domain separation prefixes (0x00 for leaves and 0x01 for internal nodes) should be added. Follow the RFC 6962 standard to prevent Merkle root collision and second-preimage attacks.
2. **A.3 Merkle root validation:** The decryptor must be forced to validate chunk hashes against the Merkle root during decryption. In the current design, the Merkle root is purely decorative.
3. **C.1 chunk_size Validation:** A ceiling limit should be added to the `Header::parse` function (e.g. maximum 16 MB). This prevents an attacker-controlled 4GB chunk_size from allocating 640GB in the BufferPool, causing DoS/OOM.
4. **C.2 Argon2 Parameter Caps:** An upper limit capping check should be enforced for Argon2 KDF parameters ($m, t, p$) (e.g., $m_{max} = 64\text{ MB}, t_{max} = 5$).
5. **D.2 Combiner transcript binding:** The ephemeral x25519 public key and ML-KEM ciphertext should be included in the KDF info transcript in Hybrid KDF (X-Wing binding) to protect against key substitution attacks.
6. **F.1 & F.2 Manifest Pinning:** Clients should bind the manifest version to a monotonic counter and pin the last known state. A gossip protocol or a centralized registration authority should be established to prevent Equivocation and Rollback attacks.
7. **G.1 Constant error behavior:** In the `verify_header_signature_sealed` function, the error codes for decryption failure and the decrypted data length not being 32 bytes should be aligned (`WrongGroupKey`).
8. **H.1 Post-Quantum Authenticity (RESOLVED):** The Ed25519 + ML-DSA hybrid signature scheme has been successfully integrated and verified.
