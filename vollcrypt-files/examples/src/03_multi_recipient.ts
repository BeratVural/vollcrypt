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
  console.log("=== Example 03: Multi-Recipient File Sharing ===");

  // 1. Generate shared file DEK and File ID
  const dek = generateDek();
  const fileId = generateFileId();
  console.log(`Shared DEK: ${dek.toString("hex")}`);

  // 2. Define recipient identities and keypairs for Bob and Carol
  const bobId = Buffer.alloc(16);
  bobId.write("Bob_Recipient_ID");
  const bobKeypair = generateRecipientKeypair();

  const carolId = Buffer.alloc(16);
  carolId.write("Carol_Recip_ID"); // 16 bytes
  const carolKeypair = generateRecipientKeypair();

  console.log("\nRecipient keys for Bob and Carol have been generated.");

  // 3. Wrapping the same DEK for both Bob and Carol (multi-wrap)
  console.log("\nAlice is wrapping the same DEK for both Bob and Carol...");
  
  const bobWrap = wrapKeyToRecipient(dek, bobId, 1, bobKeypair.publicKey);
  const carolWrap = wrapKeyToRecipient(dek, carolId, 1, carolKeypair.publicKey);

  // Both wraps are stored side-by-side in the file header wraps array
  const headerWraps = [bobWrap, carolWrap];
  console.log(`Number of wraps in header (Wraps Count): ${headerWraps.length}`);

  // 4. Encrypt the file
  const plaintext = Buffer.from("Vollcrypt multi-recipient secure sharing test payload.");
  const envelope = encryptChunk(dek, fileId, 0, plaintext);
  console.log("\nFile encrypted with shared DEK.");

  // 5. Bob finds his wrap entry in the header and unwraps the DEK
  console.log("\nBob is looking for his recipient wrap in the header...");
  const bobFoundWrap = headerWraps.find(
    (w) => w.recipientId && Buffer.compare(w.recipientId, bobId) === 0
  );
  if (!bobFoundWrap) throw new Error("Bob's wrap entry not found");
  
  const bobDek = unwrapKeyWithRecipientKey(bobFoundWrap, bobKeypair.secretKey);
  console.log(`Bob unwrapped DEK: ${bobDek.toString("hex")}`);
  console.log(`Bob decrypted payload: ${decryptChunk(bobDek, fileId, 0, envelope).toString()}`);

  // 6. Carol finds her wrap entry in the header and unwraps the DEK
  console.log("\nCarol is looking for her recipient wrap in the header...");
  const carolFoundWrap = headerWraps.find(
    (w) => w.recipientId && Buffer.compare(w.recipientId, carolId) === 0
  );
  if (!carolFoundWrap) throw new Error("Carol's wrap entry not found");

  const carolDek = unwrapKeyWithRecipientKey(carolFoundWrap, carolKeypair.secretKey);
  console.log(`Carol unwrapped DEK: ${carolDek.toString("hex")}`);
  console.log(`Carol decrypted payload: ${decryptChunk(carolDek, fileId, 0, envelope).toString()}`);

  // 7. Verify both keys are identical
  console.log(`\nKeys match (Bob === Carol): ${bobDek.equals(carolDek) ? "Yes" : "No"}`);
}

main().catch((err) => {
  console.error("An error occurred:", err);
});
