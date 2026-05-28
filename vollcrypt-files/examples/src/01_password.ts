import { 
  generateDek, 
  generateFileId, 
  encryptChunk, 
  decryptChunk, 
  wrapDekWithPassword, 
  unwrapDekWithPassword 
} from "@vollcrypt/files-node";

async function main() {
  console.log("=== Example 01: Password-Based File Encryption and Decryption ===");

  // 1. Generate required keys and identifiers
  const dek = generateDek();
  const fileId = generateFileId();
  console.log(`Data Encryption Key (DEK): ${dek.toString("hex")}`);
  console.log(`File ID: ${fileId.toString("hex")}`);

  // 2. Wrap the DEK with a password (using Argon2id parameters)
  const password = "VollcryptStrongPassword2026!";
  const kdfChoice = {
    kind: "Argon2id",
    mCost: 16384,
    tCost: 1,
    pCost: 1
  };

  console.log(`\nWrapping DEK with password (Argon2id)...`);
  const wrapEntry = wrapDekWithPassword(dek, password, kdfChoice);
  console.log("WrapEntry successfully created:");
  console.log(`  Kind: ${wrapEntry.kind}`);
  console.log(`  Salt: ${wrapEntry.salt?.toString("hex")}`);
  console.log(`  Wrapped DEK: ${wrapEntry.wrappedKey.toString("hex")}`);

  // 3. Encrypt a single chunk of the file
  const chunkIndex = 0;
  const plaintext = Buffer.from("German Federal Bar (beA) integration confidential document.");
  console.log(`\nPlaintext to encrypt: ${plaintext.toString()}`);

  const envelope = encryptChunk(dek, fileId, chunkIndex, plaintext);
  console.log("Chunk encrypted:");
  console.log(`  Chunk Index: ${envelope.chunkIndex}`);
  console.log(`  IV: ${envelope.iv.toString("hex")}`);
  console.log(`  Ciphertext: ${envelope.ciphertext.toString("hex").substring(0, 40)}...`);
  console.log(`  Tag: ${envelope.tag.toString("hex")}`);

  // 4. Unwrap the DEK using the password
  console.log(`\nUnwrapping DEK with password...`);
  const unwrappedDek = unwrapDekWithPassword(wrapEntry, password);
  console.log(`Unwrapped DEK: ${unwrappedDek.toString("hex")}`);
  console.log(`Matches original DEK: ${dek.equals(unwrappedDek) ? "Yes" : "No"}`);

  // 5. Decrypt the encrypted chunk using the unwrapped DEK
  console.log(`\nDecrypting chunk...`);
  const decrypted = decryptChunk(unwrappedDek, fileId, chunkIndex, envelope);
  console.log(`Decrypted Text: ${decrypted.toString()}`);
  console.log(`Matches original plaintext: ${plaintext.equals(decrypted) ? "Yes" : "No"}`);
}

main().catch((err) => {
  console.error("An error occurred:", err);
});
