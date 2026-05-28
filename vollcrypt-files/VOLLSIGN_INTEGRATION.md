# VollSign Document Lifecycle Integration Guide

This guide details how to integrate the `@vollcrypt/files-node` or `@vollcrypt/files-wasm` bindings into a digital signature platform like **VollSign** to achieve both eIDAS compliance and GDPR alignment.

---

## 1. Cryptographic Key Hierarchy

VollSign uses a three-tier key management architecture:

1. **Data Encryption Key (DEK)**: A symmetric AES-256 key generated per document. It encrypts the actual PDF payload chunks.
2. **Group Key (GK)**: A symmetric AES-256 key representing an organization or tenant group. It encrypts the DEK.
3. **Asymmetric Keypairs**:
   - **Recipient Keys (X25519 + ML-KEM-768)**: Used by members to wrap and unwrap the Group Key.
   - **Device Keys (Ed25519)**: Held by tescil-registered devices in the `KeyLog` to sign document headers.

---

## 2. Document Lifecycle Workflow

### Phase A: Document Creation and Encryption (Sender)

When a lawyer uploads a secret PDF document to VollSign:
1. **Generate Keys**: Generate a unique `DEK` and `File ID` using `generateDek()` and `generateFileId()`.
2. **Chunk Payload**: Split the PDF into chunks (e.g., 64KB blocks).
3. **Encrypt Chunks**: Encrypt each chunk using `encryptChunk(dek, fileId, chunkIndex, chunkData)`.
4. **Generate Merkle Tree**: Calculate chunk hashes using `chunkLeafHash(envelope)` and get the Merkle root using `merkleRoot(hashes)`.
5. **Wrap DEK**: Encrypt the DEK under the current organization Group Key using `wrapDekForGroup(dek, groupId, gkVersion, gk)`.
6. **Construct Header**: Create the `HeaderObj` containing metadata and the wrap entry.
7. **Sign Header**: The sender signs the header using their Ed25519 device key with `signHeaderSealed()`. The signer's public key is encrypted (sealed) under the group key for privacy.
8. **Store**: Store the encrypted chunks and the signed header. Clear the DEK from application memory immediately.

### Phase B: Document Access and Verification (Recipient)

When an authorized group member downloads the document:
1. **Verify Header**: Parse the header using `HeaderClass.parse(bytes)`. Verify the Ed25519 signature.
2. **Resolve Signer**: Call `resolveSender(header, keyLog, gk)` to determine the identity of the signer and check if their device was active at the signature timestamp.
3. **Decrypt GK**: Retrieve the member's keywrap entry from the `GroupManifest` and decrypt the Group Key using `unwrapKeyWithRecipientKey()`.
4. **Decrypt DEK**: Decrypt the DEK from the header wraps using `unwrapDekWithGroupKey(wrap, gk)`.
5. **Verify Chunks**: Recompute chunk leaf hashes and verify the Merkle proof for each chunk before decryption to prevent tampering.
6. **Decrypt Chunks**: Decrypt chunks using `decryptChunk(dek, fileId, chunkIndex, envelope)` and reassemble the PDF.

### Phase C: Group Lifecycle & Revocation (Admin)

If a member leaves the organization (e.g. employee offboarding):
1. **Remove Member**: Update the manifest to remove the user using `manifest.removeMember()`.
2. **Rotate Group Key**: Generate a new group key `gk2 = generateGk()` and call `manifest.rotateGroupKey(gk2, adminPk, adminSk, timestamp)`. The manifest wraps `gk2` only for active members.
3. **Header Rewrapping (Eager Revocation)**: To prevent the departed user from accessing historical documents:
   - For all active documents, call `rewrapDekInHeader(oldHeaderBytes, gk1, gk2, 2)`.
   - Update file headers on the server.
4. **Shred old GK**: Destroy the old Group Key version using `manifest.shredGroupKey(1, "Member Revocation", ...)`. The revoked member can no longer decrypt any historical or future files.

### Phase D: GDPR Erasure Request (Right to Forgotten)

If a client requests the permanent deletion of their signed document:
1. **Execute Crypto-Shred**: Call `cryptoShredHeader(headerBytes)`.
2. **Save**: Save the cleared header back to the storage database.
3. **Result**: The document is now mathematically unrecoverable. The storage space can be cleaned up lazily, ensuring immediate compliance with GDPR Article 17.

---

## 3. eIDAS Compatibility Guidelines

Under the eIDAS regulation, signatures must be uniquely linked to the signatory and created using data under their sole control:
- **Sole Control**: Ed25519 private keys must be generated and stored on the user's local device (e.g. browser LocalStorage, device keychain, or secure enclave) and never transmitted to the backend.
- **Tescil via KeyLog**: The registration of the device's public key in the `KeyLog` (anchored by the organization authority) establishes a cryptographically secure identity binding.
- **Sealed Identity**: By using `signHeaderSealed()`, the signatory's public key is hidden from passive database observers but remains accessible to authorized compliance auditors who hold the group key.
