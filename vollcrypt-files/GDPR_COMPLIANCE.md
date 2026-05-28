# GDPR Compliance Matrix for Vollcrypt File

This document outlines how the Vollcrypt File engine enables systems to satisfy strict European General Data Protection Regulation (GDPR) requirements. By using cryptographic enforcement, Vollcrypt transforms regulatory obligations into mathematical guarantees.

---

## 1. Article 17: Right to Erasure ("Right to be Forgotten")

Under GDPR Article 17, data subjects have the right to demand that their personal data be erased without undue delay. Traditional physical erasure is often difficult or impossible in distributed backups or immutable storage systems. Vollcrypt solves this via **Kriptografik İmha (Crypto-Shredding)**.

### File-Level Crypto-Shredding
- **Mechanism**: The `cryptoShredHeader` API zeroes out all key-wrapping entries (`wraps`) in the file header.
- **Result**: The Data Encryption Key (DEK) becomes permanently unrecoverable. Even if the encrypted ciphertext chunks remain on server storage, back-up tapes, or CDN caches, they are rendered mathematically equivalent to random noise.
- **Application**: Use this when a client requests the erasure of a specific file or document.

### Group-Level Crypto-Shredding
- **Mechanism**: The `GroupManifest.shredGroupKey` API cryptographically shreds a specific Group Key (GK) version and records the deletion reasoning in the signed operation log.
- **Result**: Any file encrypted using that GK version becomes permanently undecryptable.
- **Application**: Use this when a user is removed from a group and their historically generated keys must be destroyed to prevent retroactive decryption of backup logs.

---

## 2. Revocation Strategies and GDPR Alignment

Vollcrypt supports both **Lazy Revocation** and **Eager Revocation** models. The choice of revocation impacts how erasure requests are handled:

```
+-------------------+-----------------------------------------+-----------------------------------------+
| Feature           | Lazy Revocation                         | Eager Revocation                        |
+-------------------+-----------------------------------------+-----------------------------------------+
| Trigger           | Member is removed from group.           | Member is removed + Group Key rotated.   |
| Key Rotation      | Deferred until next file modification.  | Immediate GK rotation + header rewrap.  |
| Cryptographic     | Moderate (revoked member holds old GK;  | High (revoked member immediately        |
| Isolation         | can read old files but no new files).   | loses access to both old & new data).    |
| GDPR Compliance   | Acceptable for low-risk data.           | Recommended for sensitive personal data  |
|                   |                                         | (Article 9 Special Categories).         |
+-------------------+-----------------------------------------+-----------------------------------------+
```

To guarantee compliance with GDPR Article 17 erasure requests for group resources, **Eager Revocation** should be combined with GK shredding:
1. Revoke the user device/membership.
2. Rotate the Group Key to a new version.
3. Call `rewrapDekInHeader` on existing files.
4. Shred the old Group Key version using `shredGroupKey`.

---

## 3. Article 28: Processor Obligations (Access Control)

GDPR Article 28 requires processors to implement technical and organizational measures to protect personal data.
- **Cryptographic Access Control**: Data is never stored in cleartext. Only authenticated group members or authorized recipients possessing valid private keys (protected under hybrid quantum KEM exchange) can decrypt the file DEK.
- **Multi-Tenant Separation**: Files are cryptographically tied to a `groupId` or `recipientId`. Even if a malicious actor gains access to the database containing all files, they cannot read any document without being explicitly registered as a recipient or member.

---

## 4. Article 30: Records of Processing Activities (Auditing)

Article 30 requires maintaining records of processing activities.
- **KeyLog Audit Trail**: The `KeyLog` class maintains a cryptographically verified, hash-linked log of all device registrations and revocations. Each log entry is signed by the authority.
- **Immutable Timestamping**: When headers are signed (using plain or sealed signatures), the signature covers the `timestamp` and the `keyLogId`, producing a tamper-proof record of who signed the file and when.
- **Metadata Protection**: In sealed signatures, the signer's identity (public key) is encrypted under the Group Key, protecting employee identity from unauthorized public viewing while allowing compliance auditors to resolve the signer using `resolveSender`.

---

## 5. Article 32: Security of Processing

Article 32 mandates that processors implement a level of security appropriate to the risk, including encryption and system integrity.
- **Post-Quantum Cryptography**: Integrates ML-KEM-768 combined with X25519 to defend against "harvest now, decrypt later" attacks by nation-states or future quantum computers.
- **Authenticated Encryption**: Uses AES-256-GCM for chunks to ensure both confidentiality and ciphertext integrity.
- **Merkle Tree Integrity**: Ensures file integrity. Individual chunk envelopes are hashed into a Merkle Tree, preventing packet injection, file corruption, or tampering.
- **Zeroization**: Sensitive memory blocks holding DEKs, GKs, and private keys are immediately overwritten with zeroes upon completion of cryptographic operations to prevent RAM leakage or core-dump exposure.
