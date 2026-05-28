import {
  generateDek,
  generateFileId,
  generateRecipientKeypair,
  wrapKeyToRecipient,
  unwrapKeyWithRecipientKey,
  encryptChunk,
  decryptChunk
} from "@vollcrypt/files-node";

async function main() {
  console.log("=== Example 02: Hybrid KEM (X25519 + ML-KEM-768) Recipient Encryption ===");

  // 1. Generate quantum-resistant keypair for recipient Bob
  console.log("Generating recipient keypair for Bob (X25519 + ML-KEM-768)...");
  const bobKeypair = generateRecipientKeypair();
  const bobRecipientId = Buffer.alloc(16);
  bobRecipientId.write("Bob_Recipient_ID"); // 16 bytes limit

  console.log(`Bob Recipient ID: ${bobRecipientId.toString()}`);
  console.log(`Bob X25519 Public Key: ${bobKeypair.publicKey.x25519.toString("hex")}`);
  console.log(`Bob ML-KEM-768 Public Key (Length): ${bobKeypair.publicKey.mlKem.length} bytes`);

  // 2. Generate DEK and File ID on Alice's side
  const dek = generateDek();
  const fileId = generateFileId();
  console.log(`\nAlice is generating DEK and File ID for the secret document...`);
  console.log(`DEK: ${dek.toString("hex")}`);

  // 3. Alice wraps DEK using Bob's public key (Hybrid KEM)
  console.log(`\nAlice is wrapping the DEK with Bob's public key...`);
  const wrapEntry = wrapKeyToRecipient(
    dek,
    bobRecipientId,
    1, // GK Version (normally 1 for individual recipients)
    bobKeypair.publicKey
  );
  console.log("WrapEntry created:");
  console.log(`  Kind: ${wrapEntry.kind}`);
  console.log(`  Ephemeral X25519: ${wrapEntry.ephemeralX25519?.toString("hex")}`);
  console.log(`  Wrapped DEK: ${wrapEntry.wrappedKey.toString("hex")}`);

  // 4. Alice encrypts the file with this DEK
  const plaintext = Buffer.from("This text can only be read by Bob.");
  const envelope = encryptChunk(dek, fileId, 0, plaintext);
  console.log(`\nAlice encrypted the file. Encrypted data: ${envelope.ciphertext.toString("hex").substring(0, 40)}...`);

  // 5. Bob unwraps the wrapped key using his secret key
  console.log(`\nBob is unwrapping the wrapped key using his secret key...`);
  const unwrappedDek = unwrapKeyWithRecipientKey(wrapEntry, bobKeypair.secretKey);
  console.log(`Unwrapped DEK by Bob: ${unwrappedDek.toString("hex")}`);
  console.log(`Matches original DEK: ${dek.equals(unwrappedDek) ? "Yes" : "No"}`);

  // 6. Bob decrypts the file using this DEK
  const decrypted = decryptChunk(unwrappedDek, fileId, 0, envelope);
  console.log(`Decrypted Plaintext: ${decrypted.toString()}`);
}

main().catch((err) => {
  console.error("An error occurred:", err);
});
