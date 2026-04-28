# Vollcrypt — Security Design Document

**Version:** 1.0

**Status:** Internal — Pre-Audit Draft

**Last Updated:** 2026

This document describes the security architecture of Vollcrypt. It is intended for independent security auditors, cryptography reviewers, and engineers who need to reason about the library's security properties in depth.

This is not end-user documentation. For integration guidance, see [README.md](README.md). For contribution rules, see [CONTRIBUTING.md](CONTRIBUTING.md).

---

## Table of Contents

* [1. Scope](#1-scope)
* [2. Threat Model](#2-threat-model)
  * [2.1 Assets](#21-assets)
  * [2.2 Adversary Capabilities](#22-adversary-capabilities)
  * [2.3 Trust Boundaries](#23-trust-boundaries)
  * [2.4 Attack Scenarios and Mitigations](#24-attack-scenarios-and-mitigations)
  * [2.5 Out of Scope Threats](#25-out-of-scope-threats)
* [3. Algorithm Selection Rationale](#3-algorithm-selection-rationale)
  * [3.1 Symmetric Encryption — AES-256-GCM](#31-symmetric-encryption--aes-256-gcm)
  * [3.2 Classical Key Exchange — X25519](#32-classical-key-exchange--x25519)
  * [3.3 Post-Quantum KEM — ML-KEM-768](#33-post-quantum-kem--ml-kem-768)
  * [3.4 Digital Signatures — Ed25519](#34-digital-signatures--ed25519)
  * [3.5 Key Derivation — HKDF-SHA256](#35-key-derivation--hkdf-sha256)
  * [3.6 Password-Based Derivation — PBKDF2-SHA256](#36-password-based-derivation--pbkdf2-sha256)
  * [3.7 Key Wrapping — AES-256-KW](#37-key-wrapping--aes-256-kw)
  * [3.8 Recovery Phrase — BIP-39](#38-recovery-phrase--bip-39)
* [4. Key Hierarchy and Lifecycle](#4-key-hierarchy-and-lifecycle)
  * [4.1 Key Hierarchy Overview](#41-key-hierarchy-overview)
  * [4.2 Session Establishment Flow](#42-session-establishment-flow)
  * [4.3 Time-Windowed Encryption — WindowKey Chain](#43-time-windowed-encryption--windowkey-chain)
  * [4.4 Post-Compromise Security — PCS Ratchet](#44-post-compromise-security--pcs-ratchet)
  * [4.5 Key Storage and Zeroization](#45-key-storage-and-zeroization)
* [5. Protocol Constructions](#5-protocol-constructions)
  * [5.1 Binary Message Envelope](#51-binary-message-envelope)
  * [5.2 Authenticated KEM](#52-authenticated-kem)
  * [5.3 Sealed Sender](#53-sealed-sender)
  * [5.4 Transcript Hashing](#54-transcript-hashing)
  * [5.5 Key Verification Codes](#55-key-verification-codes)
  * [5.6 Key Transparency Log](#56-key-transparency-log)
* [6. Known Limitations and Accepted Risks](#6-known-limitations-and-accepted-risks)
* [7. Test Coverage](#7-test-coverage)
* [8. Cryptographic Dependencies](#8-cryptographic-dependencies)

---

## 1. Scope

This document covers the security design of the following components:

| Component          | Description                             |
| ------------------ | --------------------------------------- |
| `vollcrypt-core` | Rust cryptographic core (`core/src/`) |
| `vollcrypt-node` | Node.js N-API binding (`node/`)       |
| `vollcrypt-wasm` | WebAssembly binding (`wasm/`)         |

The license server (`packages/license-server/`) is out of scope for this document. Its security relies on standard web application practices (HTTPS, parameterized queries, Stripe webhook signature verification) rather than custom cryptographic design.

---

## 2. Threat Model

### 2.1 Assets

The following assets are protected by Vollcrypt:

| Asset                       | Description                       | Protection Goal                                            |
| --------------------------- | --------------------------------- | ---------------------------------------------------------- |
| **Message plaintext** | The content of encrypted messages | Confidentiality, integrity                                 |
| **Sender identity**   | Who sent a given message          | Privacy (Sealed Sender)                                    |
| **Session keys**      | SRK, WindowKey, DEK               | Confidentiality, forward secrecy, post-compromise security |
| **Identity keys**     | Ed25519 keypairs                  | Authenticity, non-repudiation                              |
| **Key history**       | Record of published public keys   | Integrity, auditability                                    |
| **Recovery phrase**   | BIP-39 mnemonic                   | Confidentiality (user responsibility)                      |

### 2.2 Adversary Capabilities

Vollcrypt is designed to protect against adversaries with the following capabilities:

**Network adversary (assumed in all threat scenarios):**

* Full control of network traffic between clients and server
* Can read, delay, drop, replay, and reorder messages
* Cannot break AES-256, Ed25519, X25519, or ML-KEM-768 within the security parameters used

**Compromised server:**

* The server is treated as an honest-but-curious adversary by default
* The server stores ciphertexts and routes messages but never sees plaintext
* A fully malicious server can attempt key substitution attacks (mitigated by Authenticated KEM and Key Transparency)

**Future quantum adversary:**

* A cryptographically relevant quantum computer capable of breaking X25519 and Ed25519
* Cannot break AES-256-GCM or ML-KEM-768 with known quantum algorithms
* Mitigated by the hybrid KEM construction (breaking X25519 alone is insufficient)

**Compromised client (partial):**

* An adversary who obtains a snapshot of client memory or storage at a specific point in time
* Cannot recover messages from before the compromise (Forward Secrecy)
* Can decrypt messages within the current and future time windows until the next PCS ratchet step heals the session (mitigated by PCS ratchet)

**The following adversary capabilities are out of scope:**

* Full and persistent compromise of both endpoints simultaneously
* Physical access to a device with an unlocked session
* Coercion of users to reveal their credentials or recovery phrase

### 2.3 Trust Boundaries

```
┌─────────────────────────────────────────────────────────────────┐
│  Client A (trusted)                                             │
│  ┌─────────────────┐    ┌────────────────────────────────────┐  │
│  │ Application     │    │ Vollcrypt (vollcrypt-core / WASM)  │  │
│  │                 │───▶│ Key material lives here            │  │
│  │ UI / Business   │    │ Plaintext visible only here        │  │
│  │ Logic           │◀───│                                    │  │
│  └─────────────────┘    └────────────────────────────────────┘  │
└─────────────────────────────┬───────────────────────────────────┘
                              │ Ciphertext only
                              │ (Server never sees plaintext)
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  Server (untrusted — honest-but-curious model)                  │
│  Routes sealed packets. Stores ciphertexts. Serves public keys. │
│  Cannot decrypt. Cannot forge sender signatures.                │
└─────────────────────────────┬───────────────────────────────────┘
                              │ Ciphertext only
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  Client B (trusted)                                             │
└─────────────────────────────────────────────────────────────────┘
```

**Key rule:** Key material never crosses the trust boundary from client to server. The server stores only:

* Public keys (by definition safe to store)
* Ciphertexts (opaque without the session key)
* Sealed sender packets (sender identity encrypted inside)
* Key Transparency log entries (signed, verifiable, no plaintext)

### 2.4 Attack Scenarios and Mitigations

| Attack                                   | Description                                                           | Mitigation                                                                                                        |
| ---------------------------------------- | --------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------- |
| **Passive eavesdropping**          | Adversary captures ciphertext in transit                              | AES-256-GCM — ciphertext reveals nothing without the session key                                                 |
| **Ciphertext tampering**           | Adversary modifies ciphertext bits                                    | AES-256-GCM authentication tag — decryption fails on any modification                                            |
| **Message reordering**             | Adversary delivers messages out of order                              | Transcript hashing — chain hash mismatch detected                                                                |
| **Message deletion**               | Adversary drops a message                                             | Transcript hashing — gap in hash chain detected                                                                  |
| **Replay attack**                  | Adversary re-delivers an old message                                  | Window index in envelope + transcript hash — detected as out-of-window or chain mismatch                         |
| **Key substitution (MITM)**        | Server replaces Bob's public key with its own                         | Authenticated KEM — Alice's Ed25519 signature over KEM ciphertext; Key Verification codes for human confirmation |
| **Server compromise (historical)** | Server is compromised after the fact                                  | Forward Secrecy — old WindowKeys are deleted; server never had plaintext                                         |
| **Session key compromise**         | Attacker obtains current SRK                                          | PCS ratchet — session heals within N messages (default: 50)                                                      |
| **Sender identity leakage**        | Server learns who sent what                                           | Sealed Sender — sender ID encrypted inside packet; server sees only recipient                                    |
| **Silent key rotation**            | Server silently replaces user's public key                            | Key Transparency log — all key changes are hash-chained and Ed25519-signed; any modification breaks the chain    |
| **MITM at human layer**            | User unknowingly communicates with attacker                           | Key Verification codes — short numeric or emoji codes compared out of band                                       |
| **Harvest-now decrypt-later**      | Adversary stores ciphertext to decrypt with a future quantum computer | Hybrid KEM (X25519 + ML-KEM-768) — session establishment is quantum-resistant                                    |
| **IV reuse**                       | Two messages encrypted under the same key and IV                      | IV is generated internally by OsRng per message; no API exists to pass an IV manually                             |
| **Key confusion**                  | Key derived for purpose A is used for purpose B                       | Distinct HKDF context strings for every derivation purpose (`vollchat-srk-v1`,`vollchat-window-key-v1`, etc.) |
| **Memory disclosure**              | Attacker reads process memory after session                           | `zeroize`crate — all key material zeroed before variables go out of scope                                      |
| **Timing side channel**            | Attacker measures comparison timing to learn secrets                  | `subtle::ConstantTimeEq`— all security-sensitive comparisons are constant-time                                 |

### 2.5 Out of Scope Threats

The following threats are explicitly outside the scope of Vollcrypt's cryptographic design:

* **Compromised endpoint operating system.** If the OS is fully controlled by an adversary, no cryptographic library can provide meaningful protection.
* **Compromised Rust toolchain or supply chain.** Vollcrypt relies on the correctness of the Rust compiler and its audited dependencies.
* **Denial of service.** Vollcrypt does not implement rate limiting or resource controls. These are the responsibility of the application layer.
* **Physical attacks.** Cold boot attacks, hardware implants, and TEMPEST-style attacks are out of scope.
* **User credential theft.** The library does not control how the master password or recovery phrase is obtained from the user.

---

## 3. Algorithm Selection Rationale

### 3.1 Symmetric Encryption — AES-256-GCM

**Chosen over:** AES-128-GCM, AES-CBC, ChaCha20-Poly1305.

AES-256-GCM provides authenticated encryption with associated data (AEAD), combining confidentiality and integrity in a single operation. The 256-bit key size provides a post-quantum security level of 128 bits under Grover's algorithm, which is the accepted minimum for long-term security.

AES-CBC was excluded because it does not provide authentication, requires separate HMAC, is vulnerable to padding oracle attacks, and has a poor history of implementation errors. AES-ECB was excluded because it is trivially insecure for message-length data.

ChaCha20-Poly1305 is a reasonable alternative and was considered. AES-GCM was preferred because hardware AES acceleration (AES-NI) is available on all modern x86 and ARM platforms targeted by Vollcrypt, making AES-GCM equal or faster in practice while benefiting from a longer field history.

**IV generation:** All IVs are 12 bytes, generated by `OsRng::fill_bytes()` inside the library. There is no API for callers to supply an IV. This eliminates IV reuse as a caller error class.

**Authentication tag:** 16 bytes (128-bit). No truncation is performed.

### 3.2 Classical Key Exchange — X25519

**Chosen over:** ECDH on P-256, ECDH on P-384, RSA-OAEP, finite-field DH.

X25519 (Curve25519 ECDH) provides approximately 128-bit classical security with a compact 32-byte public key and fast, constant-time scalar multiplication. The curve was designed to resist a wide class of implementation errors and side-channel attacks by construction.

RSA was excluded because it is vulnerable to quantum attacks (Shor's algorithm), has larger keys, and has a long history of subtle implementation vulnerabilities (PKCS#1 v1.5 padding oracle, Bleichenbacher attacks).

P-256 and P-384 were considered but excluded in favor of X25519 for its stronger implementation safety properties and the elimination of cofactor-related edge cases.

X25519 alone does not provide post-quantum security. It is always used in the hybrid KEM construction alongside ML-KEM-768.

### 3.3 Post-Quantum KEM — ML-KEM-768

**Chosen over:** ML-KEM-512, ML-KEM-1024, BIKE, HQC, Classic McEliece.

ML-KEM (formerly CRYSTALS-Kyber) was standardized as NIST FIPS 203 in August 2024. The 768 parameter set provides approximately 180-bit classical security and 164-bit quantum security — well above the NIST Category 3 requirement and the recommended minimum for new deployments.

ML-KEM-512 was excluded because its security margin is too low for a cryptographic library targeting multi-year deployments. ML-KEM-1024 was not chosen because the additional security margin over 768 is not warranted given current threat models, and the larger key and ciphertext sizes impose a meaningful cost.

BIKE and HQC are finalists in the NIST process but have not yet been standardized. Classic McEliece has very large key sizes unsuitable for the intended use cases.

**Hybrid construction:** ML-KEM-768 is never used alone. It is combined with X25519 in a hybrid KEM:

```
shared_secret = HKDF-SHA256(
  ikm:  x25519_shared || mlkem_shared,
  info: "vollchat-hybrid-kem-v1",
  len:  32
)
```

The hybrid construction is secure if either component is secure. A classical adversary who cannot break X25519 gains nothing from breaking ML-KEM-768. A quantum adversary who breaks X25519 (with Shor's algorithm) still cannot recover the session key because ML-KEM-768 remains secure.

### 3.4 Digital Signatures — Ed25519

**Chosen over:** ECDSA (P-256, P-384, secp256k1), RSA-PSS, RSA-PKCS1.

Ed25519 (Edwards-curve Digital Signature Algorithm) provides approximately 128-bit security with 32-byte public keys and 64-byte signatures. Crucially, Ed25519 signing is deterministic — the nonce is derived from the private key and the message using a hash function. This eliminates the class of vulnerabilities where a weak or reused nonce leaks the private key (as demonstrated by the PlayStation 3 ECDSA breach and multiple Bitcoin wallet attacks).

ECDSA over P-256 was excluded specifically because of its randomized nonce requirement. While RFC 6979 defines deterministic nonce generation for ECDSA, this is not universally implemented, and the historical record of failures is long. Ed25519's determinism is built into the specification.

RSA was excluded for the same reasons as in key exchange: quantum vulnerability and larger key sizes.

**Note on post-quantum signatures:** Ed25519 is vulnerable to quantum attacks via Shor's algorithm. ML-DSA (CRYSTALS-Dilithium, NIST FIPS 204) is the post-quantum replacement. The current design uses Ed25519 for identity keys and signatures. Migration to ML-DSA is a known future work item (see [Section 6](#6-known-limitations-and-accepted-risks)).

### 3.5 Key Derivation — HKDF-SHA256

**Chosen over:** HKDF-SHA512, direct SHA-256, BLAKE2, BLAKE3.

HKDF (RFC 5869) is the standard construction for key derivation from a shared secret. It separates the extract and expand phases, providing strong domain separation through the `info` parameter.

SHA-256 is used as the underlying hash function because it is well-analyzed, hardware-accelerated on target platforms, and provides adequate security for the key sizes used (32-byte outputs).

All HKDF derivations in Vollcrypt use distinct, versioned `info` context strings:

| Derived Key                  | Context String                |
| ---------------------------- | ----------------------------- |
| Session Root Key (SRK)       | `vollchat-srk-v1`           |
| WindowKey                    | `vollchat-window-key-v1`    |
| Hybrid KEM shared secret     | `vollchat-hybrid-kem-v1`    |
| Sealed Sender encryption key | `vollchat-sealed-sender-v1` |
| PCS ratchet new SRK          | `vollchat-pcs-ratchet-v1`   |

Context string versioning ensures that a future change to a derivation can be deployed without ambiguity about which version produced a given key.

### 3.6 Password-Based Derivation — PBKDF2-SHA256

**Chosen over:** Argon2id, bcrypt, scrypt.

PBKDF2 with 100,000 iterations is used exclusively for deriving the key wrapping key from the user's master password. This is the only place in the library where a low-entropy human-chosen secret is processed.

Argon2id is the current recommendation for new designs due to its memory-hardness. It was considered but not adopted for the following reasons:

1. Memory-hard functions are more difficult to deploy consistently across all target platforms (particularly WASM with its memory constraints).
2. The primary threat model for password-derived keys is offline brute force after a server breach. 100,000 PBKDF2-SHA256 iterations provides reasonable resistance for this scenario given current hardware.
3. Argon2id's parameter selection (memory, parallelism, iterations) requires careful tuning and is more likely to be misconfigured.

Migration to Argon2id is tracked as future work and will require a versioned key derivation scheme.

### 3.7 Key Wrapping — AES-256-KW

**Chosen over:** AES-256-GCM for key wrapping, direct storage.

AES-256-KW (RFC 3394) is specifically designed for wrapping key material. Unlike AES-256-GCM, it does not require a separately managed IV — the IV is derived from the key being wrapped and a fixed constant, making it safe for wrapping short, high-entropy keys without IV management overhead.

AES-256-GCM could also be used for key wrapping but introduces the requirement for a caller-managed IV. For key wrapping — where the input is always high-entropy key material rather than variable-length plaintext — AES-256-KW is the appropriate standard.

### 3.8 Recovery Phrase — BIP-39

**Chosen over:** custom mnemonic, raw hex, base58.

BIP-39 with 24 words provides 256 bits of entropy, well-established tooling, and a checksum for error detection. The standardized word list is widely recognized and has been used in practice for over a decade in the cryptocurrency ecosystem.

The recovery phrase is the root of the user's key hierarchy. Its loss means permanent loss of the ability to recover past messages. Its compromise means full compromise of all historical and future messages (on devices that share the same root key).

---

## 4. Key Hierarchy and Lifecycle

### 4.1 Key Hierarchy Overview

```
Recovery Phrase (BIP-39, 24 words)
│  256-bit entropy. Never stored digitally in plaintext.
│  Used only during onboarding and disaster recovery.
│
└──▶ Master Seed (PBKDF2-SHA256, 100K iter)
     │  64 bytes. Derived from Recovery Phrase + empty passphrase.
     │
     └──▶ DEK (Data Encryption Key, AES-256)
          │  32 bytes. Derived from Master Seed via HKDF.
          │  Lives in RAM only during active session.
          │  Stored wrapped (AES-256-KW) under Master Password key.
          │  In browser: imported as SubtleCrypto CryptoKey (extractable: false).
          │
          └──▶ SRK (Session Root Key, per conversation)
               │  32 bytes. Derived from Hybrid KEM shared secret + chat_id.
               │  DEK is used to wrap SRKs for storage.
               │
               └──▶ WindowKey_n (per time window)
                    32 bytes. Derived from SRK + window_index.
                    Window index = floor(unix_time / 3600).
                    Deleted from RAM when window expires.
                    Used directly for AES-256-GCM encryption.

Identity Key (IK, Ed25519)
│  Per device. Used for signatures and Key Transparency log.
│  Stored wrapped under DEK.
│
└──▶ Device authentication, message signing, KEM authentication

KEM Keys (X25519 + ML-KEM-768)
     Per device. Used for session establishment.
     Public keys published to server.
     Private keys stored wrapped under DEK.
```

### 4.2 Session Establishment Flow

```
Alice                                    Server                    Bob
  │                                         │                       │
  │──── Fetch Bob's public keys ───────────▶│                       │
  │◀─── X25519_pub_B, MLKEM_pub_B ─────────│                       │
  │                                         │                       │
  │  authenticated_kem_encapsulate(          │                       │
  │    X25519_pub_B,                        │                       │
  │    MLKEM_pub_B,                         │                       │
  │    alice_identity_sk                    │                       │
  │  ) → (auth_ciphertext, shared_secret_A) │                       │
  │                                         │                       │
  │──── Send auth_ciphertext ──────────────▶│──── Forward ─────────▶│
  │                                         │                       │
  │                                         │  authenticated_kem_   │
  │                                         │  decapsulate(         │
  │                                         │    auth_ciphertext,   │
  │                                         │    bob_x25519_sk,     │
  │                                         │    bob_mlkem_dk,      │
  │                                         │    alice_identity_pk  │
  │                                         │  ) → shared_secret_B  │
  │                                         │                       │
  │  shared_secret_A == shared_secret_B     │                       │
  │                                         │                       │
  │  SRK = HKDF(shared_secret, chat_id, "vollchat-srk-v1")         │
```

The server forwards the ciphertext but cannot compute the shared secret — it does not have Bob's private keys. Alice's Ed25519 signature over the ciphertext ensures Bob can detect if the server substituted a different ciphertext.

### 4.3 Time-Windowed Encryption — WindowKey Chain

```
SRK (32 bytes)
 │
 ├──▶ WindowKey_0 = HKDF(SRK, window_0_bytes, "vollchat-window-key-v1")
 │    Used for: messages in hour 0
 │    Deleted: when clock advances past hour 0
 │
 ├──▶ WindowKey_1 = HKDF(SRK, window_1_bytes, "vollchat-window-key-v1")
 │    Used for: messages in hour 1
 │    Deleted: when clock advances past hour 1
 │
 └──▶ WindowKey_n = HKDF(SRK, window_n_bytes, "vollchat-window-key-v1")
      window_n = floor(unix_timestamp / 3600)
```

**Forward Secrecy guarantee:** Compromising WindowKey_n reveals only the messages encrypted in that time window. WindowKey_{n-1}, WindowKey_{n-2}, etc. are already deleted. WindowKey_{n+1} cannot be computed from WindowKey_n alone — it requires SRK.

**Blast radius:** If SRK is compromised, all past and future WindowKeys for that conversation can be derived. This is mitigated by the PCS ratchet.

### 4.4 Post-Compromise Security — PCS Ratchet

The PCS ratchet limits the damage from an SRK compromise. After every N messages (default: 50) or every new time window, both parties perform an ephemeral X25519 key exchange and derive a new SRK:

```
Trigger: message_count % 50 == 0 OR new_window == true

Alice generates: ephemeral_kp_A = (eph_sk_A, eph_pk_A)
Bob generates:   ephemeral_kp_B = (eph_sk_B, eph_pk_B)

Each party exchanges their ephemeral public key.

new_SRK = HKDF(
  ikm:  current_SRK || ECDH(eph_sk_A, eph_pk_B),
        ← same as ECDH(eph_sk_B, eph_pk_A) by ECDH symmetry
  salt: ratchet_step.to_be_bytes(),
  info: "vollchat-pcs-ratchet-v1",
  len:  32
)

current_SRK.zeroize()
current_SRK = new_SRK
ratchet_step += 1
```

**Post-Compromise Security guarantee:** An adversary who obtains the SRK at step N cannot compute the SRK at step N+1 without also obtaining one of the ephemeral private keys exchanged at step N+1. Those ephemeral keys are generated fresh and deleted after use.

**Combined guarantee:** WindowKey PFS protects individual time windows. PCS ratchet limits how many future windows an attacker can access after compromising the SRK.

### 4.5 Key Storage and Zeroization

| Key                         | Storage Location         | Protected By                                                            | Zeroization                                      |
| --------------------------- | ------------------------ | ----------------------------------------------------------------------- | ------------------------------------------------ |
| Recovery Phrase             | Physical only            | User responsibility                                                     | N/A                                              |
| Master Password             | Never stored             | User memory                                                             | N/A                                              |
| Master Seed                 | RAM only during recovery | Never persisted                                                         | `zeroize`after DEK derivation                  |
| DEK                         | RAM (active session)     | SubtleCrypto (extractable: false) in browser; process memory in Node.js | `zeroize`on session end                        |
| DEK (at rest)               | IndexedDB / server       | AES-256-KW under password-derived key                                   | N/A (wrapped)                                    |
| SRK                         | RAM only                 | Process memory                                                          | `zeroize`after WindowKey derivation or ratchet |
| WindowKey                   | RAM only                 | Process memory                                                          | `zeroize`when window expires                   |
| Identity Key (private)      | Wrapped storage          | AES-256-KW under DEK                                                    | `zeroize`after signing                         |
| Ephemeral ratchet key       | RAM only                 | Process memory                                                          | `zeroize`after ratchet step                    |
| Ephemeral sealed sender key | RAM only                 | Process memory                                                          | `zeroize`after encryption                      |

The `zeroize` crate is used throughout the Rust core to overwrite sensitive data before variables go out of scope. Structs that hold secrets derive `ZeroizeOnDrop` to ensure automatic cleanup.

---

## 5. Protocol Constructions

### 5.1 Binary Message Envelope

Every AES-256-GCM ciphertext is packed into the following binary format:

```
Offset   Length   Field            Description
──────   ──────   ─────            ───────────
0        4        window_index     Big-endian u32. Identifies which WindowKey to derive.
4        12       iv               OsRng-generated AES-GCM nonce.
16       32       aad_hash         SHA-256(message_id || sender_id || timestamp). Authenticated but not encrypted.
48       N        ciphertext       AES-256-GCM encrypted plaintext.
48+N     16       auth_tag         GCM authentication tag.
```

**AAD hash design:** The AAD (Additional Authenticated Data) is hashed rather than included in full to bound the envelope size. SHA-256(AAD) is included in the envelope and the same AAD must be provided for decryption. This ensures:

* The message cannot be moved to a different conversation (chat_id in AAD)
* The message cannot be attributed to a different sender (sender_id in AAD)
* The timestamp cannot be altered (timestamp in AAD)

**Format stability:** This format is permanent. It cannot be changed without breaking backward compatibility. Any evolution must introduce a new version field.

### 5.2 Authenticated KEM

Standard `hybrid_kem_encapsulate` does not bind the ciphertext to a sender. An authenticated variant signs the KEM ciphertext with the sender's Ed25519 identity key:

```
Authenticated ciphertext format:
[2 bytes: kem_ct_len (big-endian u16)]
[kem_ct_len bytes: KEM ciphertext]
[64 bytes: Ed25519 signature over KEM ciphertext]
```

**Security property:** The recipient verifies the signature before decapsulating. If the server substituted a different KEM ciphertext, the signature will not verify against the claimed sender's identity key, and decapsulation is refused.

**Signing decision:** The KEM ciphertext is signed, not the shared secret. Signing the shared secret would bind the signature to a value that changes with each decapsulation attempt, complicating verification. Signing the ciphertext is sufficient because the ciphertext uniquely determines the shared secret.

### 5.3 Sealed Sender

```
Sealed packet format:
[32 bytes: ephemeral_public_key]
[12 bytes: AES-GCM IV]
[N bytes: AES-256-GCM ciphertext of inner_plaintext]
[16 bytes: AES-GCM auth tag]

inner_plaintext format:
[2 bytes: sender_id_len (big-endian u16)]
[sender_id_len bytes: sender_id]
[remaining bytes: message content]
```

**Key derivation for sealed sender:**

```
shared = ECDH(ephemeral_sk, recipient_x25519_pub)
encryption_key = HKDF(
  ikm:  shared,
  salt: ephemeral_pub_key_bytes,
  info: "vollchat-sealed-sender-v1",
  len:  32
)
```

Using the ephemeral public key as the HKDF salt binds the encryption key to this specific ephemeral exchange, preventing key reuse across sealed packets.

**Privacy guarantee:** The server sees only the recipient's identifier and the opaque sealed packet. The sender's identity is inside the encrypted inner plaintext. Since a new ephemeral key is generated per message, sealed packets from the same sender are unlinkable by the server.

### 5.4 Transcript Hashing

```
chain_hash_0 = SHA-256(session_id)

message_hash_n = SHA-256(message_id || sender_id || timestamp || ciphertext)

chain_hash_n = SHA-256(chain_hash_{n-1} || message_hash_n)
```

Both sender and receiver maintain independent chain state. Divergence indicates reordering, deletion, or insertion of messages. The chain state can be compared out of band (e.g., during key verification) to confirm session integrity.

**Limitation:** Transcript hashing detects message manipulation but does not prevent it. The application layer must define how to handle a detected chain mismatch (alert user, re-sync, etc.).

### 5.5 Key Verification Codes

```
fingerprint = SHA-256(
  "vollchat-key-verification-v1" ||
  min(key_a, key_b) ||     ← lexicographic order (symmetry)
  max(key_a, key_b) ||
  conversation_id
)
```

**Numeric code:** The 32-byte fingerprint is mapped to 60 decimal digits grouped as 12 × 5. Each pair of bytes produces a 4-digit decimal value (0000–9999); 15 pairs produce 60 digits.

**Emoji code:** The fingerprint is parsed as a bitstream; every 6 bits selects one of 64 predefined emoji. The first 120 bits (20 emoji) are used, grouped as 4 × 5.

**Symmetry:** Keys are sorted lexicographically before hashing. This ensures `generate(alice, bob, conv)` == `generate(bob, alice, conv)` regardless of which party computes the code.

**Collision resistance:** A false match requires finding a second pre-image of SHA-256 for a given pair of keys, which is computationally infeasible. The code is not a commitment scheme and is not used in any automated verification — it is only compared by humans out of band.

### 5.6 Key Transparency Log

Each log entry contains:

```
Entry fields (canonical body for signing):
[4 bytes: user_id_len (big-endian u32)]
[user_id_len bytes: user_id]
[32 bytes: ed25519_public_key]
[8 bytes: timestamp (big-endian u64, UNIX seconds)]
[32 bytes: prev_entry_hash]
[1 byte: action (0x01=Add, 0x02=Update, 0x03=Revoke)]

Entry hash:
SHA-256(canonical_body || ed25519_signature)

Signature:
Ed25519(signing_key, canonical_body)
```

**Chain integrity:** Each entry commits to the hash of the previous entry. Modifying any entry invalidates the hashes of all subsequent entries. `verify_chain()` walks the full log and detects any break.

**Signing key for verification:**

* `Add` and `Update`: the entry's own `public_key` field is used to verify the signature. The user proves ownership of the new key by signing with the corresponding private key.
* `Revoke`: the most recent previous `Add` or `Update` key is used. This proves that the entity authorizing the revocation actually controlled the key being revoked.

**Genesis entry:** The first entry for any user must have `prev_entry_hash == [0u8; 32]` (the genesis constant). Any first entry with a non-zero `prev_entry_hash` is rejected by `verify_chain()`.

---

## 6. Known Limitations and Accepted Risks

| Limitation                                                     | Impact                                                                                                                                 | Mitigation / Future Work                                                                                                                                  |
| -------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Ed25519 is quantum-vulnerable**                        | A cryptographically relevant quantum computer could forge signatures on Key Transparency log entries and authenticated KEM ciphertexts | Migration to ML-DSA (NIST FIPS 204) is planned. Session confidentiality is quantum-resistant via ML-KEM-768; only authentication is affected.             |
| **PBKDF2 instead of Argon2id**                           | PBKDF2 is less resistant to GPU/ASIC brute force than memory-hard functions                                                            | 100,000 iterations provides reasonable resistance for current hardware. Argon2id migration is tracked for a future version.                               |
| **No transcript mismatch recovery**                      | The library detects transcript chain mismatches but does not define a recovery protocol                                                | Recovery is the responsibility of the application layer.                                                                                                  |
| **Sealed sender provides sender privacy, not anonymity** | A powerful network adversary with timing correlation capabilities may be able to link sealed packets to senders via traffic analysis   | Sealed sender is not designed to defeat global passive adversaries. Applications requiring stronger anonymity should use a mixnet or onion routing layer. |
| **Key Transparency log requires server availability**    | The log is served by the server. A malicious server could serve a stale or truncated log                                               | Future work: gossip protocol between clients to cross-check log state.                                                                                    |
| **PCS ratchet requires both parties to be online**       | Ratchet steps require an ephemeral key exchange. Asynchronous ratchet (like Signal's Double Ratchet) would be more robust              | Current design requires periodic online presence for PCS to advance. Future work: async ratchet design.                                                   |
| **Window size is fixed at 1 hour**                       | If a WindowKey is compromised, messages within its 1-hour window are exposed                                                           | Window size is a configurable constant. Applications with higher security requirements can reduce it.                                                     |
| **No post-quantum signatures**                           | Forward-secrecy is quantum-resistant; authentication is not                                                                            | Tracked for future ML-DSA integration.                                                                                                                    |

---

## 7. Test Coverage

### Unit Tests by Module

| Module               | Test Count | Areas Covered                                                                                                                                                                                                                      |
| -------------------- | ---------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `symmetric.rs`     | 4          | Encrypt/decrypt roundtrip, wrong key rejection, AAD mismatch rejection, ciphertext modification rejection                                                                                                                          |
| `pqc.rs`           | 7          | Hybrid KEM roundtrip, authenticated KEM roundtrip, wrong identity key rejection, tampered ciphertext rejection, truncated ciphertext rejection, format validation, classical-only baseline                                         |
| `keys.rs`          | 3          | Ed25519 sign/verify, wrong key rejection, X25519 ECDH shared secret equality                                                                                                                                                       |
| `kdf.rs`           | 5          | PBKDF2 determinism and salt sensitivity, HKDF determinism and context sensitivity, SRK derivation, WindowKey derivation and index sensitivity                                                                                      |
| `ratchet.rs`       | 6          | New SRK differs from old, sender/receiver produce same SRK, different steps produce different SRKs, ephemeral key isolation, message count trigger, window change trigger                                                          |
| `transcript.rs`    | 8          | Session ID sensitivity, update changes hash, same sequence same hash, order sensitivity, missing message detection, serialization roundtrip, timing-safe comparison, message hash determinism                                      |
| `sealed_sender.rs` | 8          | Roundtrip, per-call randomness, sender identity hidden, wrong key rejection, tampered packet rejection, truncated packet rejection, empty content, large content                                                                   |
| `verification.rs`  | 10         | Symmetry, different keys produce different codes, determinism, conversation ID sensitivity, numeric format (length, characters, groups), emoji format (count, groups), match positive, match negative, palette uniqueness          |
| `key_log.rs`       | 10         | Single entry valid, multi-entry valid, tampered entry detection, wrong prev_hash rejection, current key after update, current key after revoke is None, key at timestamp, multi-user isolation, history ordering, hash determinism |
| `device.rs`        | 3          | Add device, revoke device, revoked device rejection                                                                                                                                                                                |
| `bip39.rs`         | 2          | Mnemonic generation and seed restoration                                                                                                                                                                                           |
| `wrap.rs`          | 2          | Wrap/unwrap roundtrip, wrong wrapping key rejection                                                                                                                                                                                |

**Total: 68 unit tests**

### Property-Based Testing

All core functions with deterministic behavior are tested for:

* Same inputs always produce the same output
* Different inputs (key, salt, context, index) produce independent outputs

### Platform Testing

CI runs all tests on:

* Linux x64 (ubuntu-latest)
* macOS x64 (macos-latest)
* Windows x64 (windows-latest)

### What Is Not Tested

| Gap                     | Reason                                                | Risk                                                                              |
| ----------------------- | ----------------------------------------------------- | --------------------------------------------------------------------------------- |
| Side-channel resistance | Requires specialized tooling (e.g., ctgrind, TIMECOP) | Low —`subtle::ConstantTimeEq`is used throughout;`OsRng`is platform-provided  |
| Formal verification     | Requires significant additional tooling investment    | Medium — mitigated by algorithm standardization                                  |
| Interoperability        | No reference implementation to test against           | Low for standard primitives; medium for Vollcrypt-specific protocol constructions |
| Fault injection         | Requires hardware or VM-level tooling                 | Low for software-only deployments                                                 |

---

## 8. Cryptographic Dependencies

All cryptographic primitives are implemented by audited crates from the [RustCrypto](https://github.com/RustCrypto) and [dalek-cryptography](https://github.com/dalek-cryptography) ecosystems. Vollcrypt does not implement any cryptographic algorithm from scratch.

| Crate                  | Version            | Purpose                  | Audit Status                           |
| ---------------------- | ------------------ | ------------------------ | -------------------------------------- |
| `aes-gcm`            | RustCrypto         | AES-256-GCM encryption   | RustCrypto audited by NCC Group (2020) |
| `ml-kem`             | RustCrypto         | ML-KEM-768 (FIPS 203)    | RustCrypto ecosystem                   |
| `x25519-dalek`       | dalek-cryptography | X25519 ECDH              | Audited by iSEC Partners (2019)        |
| `ed25519-dalek`      | dalek-cryptography | Ed25519 signatures       | Audited by iSEC Partners (2019)        |
| `hkdf`               | RustCrypto         | HKDF-SHA256              | RustCrypto audited by NCC Group (2020) |
| `pbkdf2`             | RustCrypto         | PBKDF2-SHA256            | RustCrypto audited by NCC Group (2020) |
| `aes-kw`             | RustCrypto         | AES-256-KW (RFC 3394)    | RustCrypto ecosystem                   |
| `sha2`               | RustCrypto         | SHA-256                  | RustCrypto audited by NCC Group (2020) |
| `zeroize`            | RustCrypto         | Memory zeroization       | RustCrypto audited by NCC Group (2020) |
| `subtle`             | dalek-cryptography | Constant-time operations | Audited by iSEC Partners (2019)        |
| `rand`/`rand_core` | rust-random        | OsRng, CSPRNG            | Widely reviewed                        |

**Policy:** No cryptographic algorithm is implemented by Vollcrypt itself. If a required primitive is not available in an audited crate, a new crate must be selected or a formal audit of the implementation must be commissioned before inclusion. Pull requests that introduce custom cryptographic implementations will not be merged.
