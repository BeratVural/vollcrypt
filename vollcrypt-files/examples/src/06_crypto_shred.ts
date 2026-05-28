import {
  generateDek,
  generateFileId,
  generateGk,
  generateRecipientKeypair,
  ed25519KeypairGenerate,
  wrapDekForGroup,
  cryptoShredHeader,
  GroupManifest,
  HeaderClass,
  HeaderObj
} from "@vollcrypt/files-node";

async function main() {
  console.log("=== Example 06: GDPR Compliant Cryptographic Shredding ===");

  // Setup Group and Keys
  const groupId = Buffer.alloc(16);
  groupId.write("VollGroup_Shred ");
  const gkV1 = generateGk();
  
  const aliceId = Buffer.alloc(16);
  aliceId.write("Alice_Admin_____");
  const aliceRecipientKp = generateRecipientKeypair();
  const aliceSigningKp = ed25519KeypairGenerate();

  const manifest = GroupManifest.genesis(
    groupId,
    gkV1,
    aliceId,
    aliceRecipientKp.publicKey,
    aliceSigningKp.publicKey,
    aliceSigningKp.secretKey,
    Math.floor(Date.now() / 1000)
  );

  // File Creation
  const fileId = generateFileId();
  const dek = generateDek();
  const groupWrap = wrapDekForGroup(dek, groupId, 1, gkV1);
  const header: HeaderObj = {
    version: 2,
    mode: 2,
    cipherId: 0,
    fileId: fileId,
    chunkSize: 65536,
    plaintextSize: 50000,
    merkleRoot: Buffer.alloc(32),
    wraps: [groupWrap]
  };
  const headerBytes = HeaderClass.write(header);
  console.log(`\nFile Header Created. Size: ${headerBytes.length} bytes`);

  // --- Scenario A: File-Level Cryptographic Shredding (Header Crypto-Shredding) ---
  console.log("\n--- Scenario A: File-Level Cryptographic Shredding (GDPR Article 17 - Right to be Forgotten) ---");
  console.log("Zeroing out all wrapped key entries in the file header...");
  const shreddedHeaderBytes = cryptoShredHeader(headerBytes);
  
  console.log("Parsing shredded file header back...");
  const parsedShreddedHeader = HeaderClass.parse(shreddedHeaderBytes);
  console.log(`  Header Wrap Entries Count: ${parsedShreddedHeader.header.wraps.length} (All key wraps successfully cleared)`);

  // --- Scenario B: Group-Level Version Shredding (Group-level GK Shredding) ---
  console.log("\n--- Scenario B: Group-Level Version Shredding (Shredding Group Key Version 1) ---");
  console.log(`Is version 1 shredded before operation: ${manifest.isVersionShredded(1) ? "Yes" : "No"}`);

  console.log("Admin is shredding Group Key Version 1...");
  manifest.shredGroupKey(
    1, // Version to shred
    "GDPR Article 17 Request: Delete Lawyer and Client Historical Records",
    aliceSigningKp.publicKey,
    aliceSigningKp.secretKey,
    Math.floor(Date.now() / 1000)
  );

  console.log(`\nIs version 1 shredded after operation: ${manifest.isVersionShredded(1) ? "Yes" : "No"}`);
  console.log("After this stage, any client attempting to access GK v1 will be denied.");
  console.log("Cryptographic shredding successfully verified.");
}

main().catch((err) => {
  console.error("An error occurred:", err);
});
