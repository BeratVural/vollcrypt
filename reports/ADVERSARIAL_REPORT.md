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
| **C.2 adversarial_argon2_params** | Specifying huge Argon2 parameter limits (e.g. m=4GB) causes DoS. | *REJECTED* | REJECTED: Parameter out of bounds rejected | **✓ Defended** |
| **C.3 wrap_count_bomb** | Mismatching wrap_count (e.g. 255) vs actual shorter variable_len parser behavior. | *REJECTED* | REJECTED: Parser detected wrap count inconsistency and rejected safely | **✓ Defended** |
| **D.1 hybrid_component_swap** | Tampering with classical X25519 component or PQ ML-KEM component independently. | *REJECTED* | REJECTED: Tampering either component causes decapsulation failure | **✓ Defended** |
| **D.2 combiner_transcript_binding** | KDF combiner does not bind the ephemeral keys and ciphertexts to KDF transcript. | *REJECTED* | REJECTED: Ephemeral keys, static keys, recipient_id, and gk_version are cryptographically bound to the X-Wing combiner transcript. Old wrap_type 2 is rejected. | **✓ Defended** |
| **D.3 mlkem_binding_multi_recipient** | Ciphertext bound checks: same DEK wrapped to 2 recipients. | *REJECTED* | REJECTED: Tested and observed no cross-recipient key decryption leaks | **✓ Defended** |
| **E.1 rotation_dek_invariance** | rewrap_dek_in_header rotates KEK but leaves DEK unchanged (no forward secrecy if DEK is compromised). | *◷ Sınır/Footgun* | ◷ Sınır/Footgun: DEK is invariant under rotation. rotation veri forward-secrecy SAĞLAMAZ. | **◷ Sınır/Footgun** |
| **E.2 lazy_revocation_window** | removeMember done in manifest but no rotate+rewrap done allows revoked member to decrypt. | *◷ Sınır/Footgun* | ◷ Sınır/Footgun: Revoked member can still decrypt group key from history because no rotation occurred. | **◷ Sınır/Footgun** |
| **F.1 manifest_fork** | Stateless client cannot detect conflicting manifest forks signed by the admin. | *◷ Detectable (out-of-band gerektirir)* | ◷ Detectable (out-of-band gerektirir): Equivocation detected between Fork A and Fork B at epoch 1. Stateless clients must compare heads out-of-band. | **◷ Detectable (out-of-band gerektirir)** |
| **F.2 manifest_rollback** | Stateless client presented with a valid historical prefix accepts rolled-back state. | *REJECTED* | REJECTED: Rollback detected. Client pinned epoch 1, rollback manifest had epoch 0. | **✓ Defended** |
| **G.1 sealed_resolution_oracle** | Timing and error-type differences between incorrect Group Key and malformed sealed payload. | *REJECTED* | REJECTED: Constant error behavior | **✓ Defended** |
| **G.2 wasm_aes_constant_time** | WASM soft AES backend (bitsliced fixslice vs table-based timing leak). | *REJECTED* | REJECTED: WASM uses constant-time bitsliced fixslice software AES | **✓ Defended** |
| **H.1_ed_only_forge** | Attacker provides valid Ed25519 signature but invalid ML-DSA-65 signature. | *REJECTED* | REJECTED: Verification failed as expected (both algorithms must pass) | **✓ Defended** |
| **H.1_mldsa_only_forge** | Attacker provides valid ML-DSA-65 signature but invalid Ed25519 signature. | *REJECTED* | REJECTED: Verification failed as expected (both algorithms must pass) | **✓ Defended** |
| **H_key_substitution** | Attacker attempts to swap public key components or verify with mismatched domain binding. | *REJECTED* | REJECTED: Mismatched public key components and incorrect domains failed verification | **✓ Defended** |
| **H_downgrade** | Attacker presents legacy signatures/manifests under require_pq_signature policy. | *REJECTED* | REJECTED: Downgrade to legacy signature versions blocked under policy | **✓ Defended** |
## Bölüm H — Post-Quantum Authenticity Direnci

### H.1 signature_pq_gap (RESOLVED)
Ed25519 ve ML-DSA-65 hibrit imza şeması (AND-combiner) entegre edilmiştir. Saldırganın doğrulamayı geçmesi için hem klasik hem de post-quantum imza algoritmalarını kırması gerekir. Böylece PQ-authenticity sağlanmış ve imza sahteciliği açığı kapatılmıştır.

### H.2 harvest_now_decrypt_later (RESOLVED)
Monotonic sürüm yönetimi, rollback koruması ve hibrit post-quantum imzalar sayesinde tarihsel manifest manipülasyonu ve sahte üye ekleme saldırılarına karşı tam koruma sağlanmıştır. Eski sürüm imzalar ve manifestler `require_pq_signature` politikası altında reddedilir.

## Identified Findings

None.

## Design Limitations (by intent)

* ◷ **E.1 rotation_dek_invariance**
* ◷ **E.2 lazy_revocation_window**
* ◷ **F.1 manifest_fork**

## Recommendations

1. **A.1 & A.2 Merkle tree:** Merkle ağacı yaprakları için `0x00` ve iç düğümler için `0x01` domain separation prefix'leri eklenmeli. RFC 6962 standardı takip edilerek Merkle root collision ve second-preimage saldırıları engellenmeli.
2. **A.3 Merkle root validation:** Decryptor'ın dosyayı deşifre ederken chunk'ların hash'lerini Merkle root ile doğrulaması zorunlu kılınmalı. Şu anki tasarımda Merkle root sadece dekoratif durumdadır.
3. **C.1 chunk_size Validation:** `Header::parse` fonksiyonuna üst sınır limiti eklenmeli (örneğin maksimum 16 MB). Bu sayede saldırgan kontrollü 4GB chunk_size değerinin BufferPool'da 640GB bellek tahsis ederek DoS/OOM yaratması engellenmeli.
4. **C.2 Argon2 Parameter Caps:** Argon2 KDF parametreleri ($m, t, p$) için üst sınır capping kontrolü getirilmeli (örneğin $m_{max} = 64\text{ MB}, t_{max} = 5$).
5. **D.2 Combiner transcript binding:** Hybrid KDF'de (KDF info) ephemeral x25519 public key ve ML-KEM ciphertext'leri KDF info transcript'ine dahil edilerek (X-Wing binding) key substitution saldırılarına karşı korunmalı.
6. **F.1 & F.2 Manifest Pinning:** İstemciler manifest sürümünü monotonic bir sayaca bağlamalı ve son bilinen durumu pinlemelidir. Equivocation ve Rollback saldırılarını engellemek için gossip protokolü veya merkezi tescil otoritesi kurulmalı.
7. **G.1 Constant error behavior:** `verify_header_signature_sealed` fonksiyonunda, decryption başarısızlığı ile deşifre olan verinin 64 byte olmaması durumunun hata kodları eşitlenmeli (`WrongGroupKey`).
8. **H.1 Post-Quantum Authenticity (RESOLVED):** Ed25519 + ML-DSA hibrit imza şeması başarıyla entegre edilmiş ve doğrulanmıştır.
