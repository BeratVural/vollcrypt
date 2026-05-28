import {
  generateDek,
  generateFileId,
  generateGk,
  generateRecipientKeypair,
  ed25519KeypairGenerate,
  encryptChunk,
  decryptChunk,
  chunkLeafHash,
  merkleRoot,
  merkleProof,
  verifyMerkleProof,
  wrapDekForGroup,
  unwrapDekWithGroupKey,
  unwrapKeyWithRecipientKey,
  signHeaderSealed,
  resolveSender,
  rewrapDekInHeader,
  KeyLog,
  GroupManifest,
  HeaderClass,
  HeaderObj
} from "@vollcrypt/files-node";

async function main() {
  console.log("=== Example 09: DoccA Compliant Enterprise End-to-End Document Lifecycle ===");

  // 1. System Setup: KeyLog and Group/Organization Manifest
  const authorityKp = ed25519KeypairGenerate();
  const keyLog = KeyLog.create(authorityKp.publicKey);

  const groupId = Buffer.alloc(16);
  groupId.write("DoccA_Org_001");
  const gkV1 = generateGk();

  // Founder Member: Alice (Admin)
  const aliceId = Buffer.alloc(16);
  aliceId.write("Alice_Admin_ID__");
  const aliceRecipientKp = generateRecipientKeypair();
  const aliceSigningKp = ed25519KeypairGenerate();
  const aliceDeviceKp = ed25519KeypairGenerate();

  // Register Alice's signing device
  const aliceRegTime = Math.floor(Date.now() / 1000) - 3600;
  const aliceKeyLogId = keyLog.registerDevice(
    aliceId,
    Buffer.from("Alice_Laptop_001"),
    aliceDeviceKp.publicKey,
    "Alice MacBook Pro",
    authorityKp.secretKey,
    aliceRegTime
  );

  // Genesis Manifest
  const manifest = GroupManifest.genesis(
    groupId,
    gkV1,
    aliceId,
    aliceRecipientKp.publicKey,
    aliceSigningKp.publicKey,
    aliceSigningKp.secretKey,
    Math.floor(Date.now() / 1000)
  );

  // Group Member: Bob (Lawyer)
  const bobId = Buffer.alloc(16);
  bobId.write("Bob_Lawyer_ID___");
  const bobRecipientKp = generateRecipientKeypair();
  const bobSigningKp = ed25519KeypairGenerate();
  
  // Add Bob to the group
  manifest.addMember(
    bobId,
    { recipient: bobRecipientKp.publicKey, signingPk: bobSigningKp.publicKey },
    gkV1,
    aliceSigningKp.publicKey,
    aliceSigningKp.secretKey,
    Math.floor(Date.now() / 1000)
  );

  console.log("Group and Devices Prepared. Alice (Admin) and Bob (Lawyer) registered.");

  // 2. Document Preparation and Encryption (3-page/chunk PDF Simulation)
  const pdfChunks = [
    Buffer.from("PDF Page 1: Confidential Commercial Agreement Details. Party A: DoccA, Party B: OfficeB."),
    Buffer.from("PDF Page 2: Service Fees and Payment Terms. Stripe Integration Details."),
    Buffer.from("PDF Page 3: beA Safe-ID and Electronic Signature Protocol. ISO-27001 Standards.")
  ];

  const fileId = generateFileId();
  const dek = generateDek();

  console.log(`\nAlice is chunking and encrypting the confidential PDF document...`);
  const envelopes = pdfChunks.map((chunk, index) => {
    return encryptChunk(dek, fileId, index, chunk);
  });

  // 3. Merkle Tree Calculation and Proof Validation
  console.log("\nGenerating Merkle Tree over chunk envelopes...");
  const leafHashes = envelopes.map(env => chunkLeafHash(env));
  const root = merkleRoot(leafHashes);
  console.log(`  Merkle Root: ${root.toString("hex")}`);

  // Validate integrity proof for Page 1 (Index 0)
  const proof = merkleProof(leafHashes, 0);
  const isProofValid = verifyMerkleProof(leafHashes[0], 0, leafHashes.length, proof, root);
  console.log(`  Page 1 Integrity Proof Validated: ${isProofValid ? "Yes" : "No"}`);

  // 4. File Header Creation and Sealed Signing
  const groupWrap = wrapDekForGroup(dek, groupId, 1, gkV1);
  const header: HeaderObj = {
    version: 2,
    mode: 2,
    cipherId: 0,
    fileId: fileId,
    chunkSize: 65536,
    plaintextSize: pdfChunks.reduce((acc, c) => acc + c.length, 0),
    merkleRoot: root,
    wraps: [groupWrap]
  };

  console.log("\nAlice is signing the header in Sealed Mode...");
  const signatureTime = Math.floor(Date.now() / 1000);
  const signedHeader = signHeaderSealed(
    header,
    aliceDeviceKp.publicKey,
    aliceDeviceKp.secretKey,
    aliceKeyLogId,
    signatureTime,
    groupId,
    1,
    gkV1
  );
  
  const finalFileHeaderBytes = HeaderClass.write(signedHeader);
  console.log(`Document File Header Prepared. Size: ${finalFileHeaderBytes.length} bytes`);

  // 5. Bob Accesses and Verifies the Document
  console.log("\n=== Bob Receives the Document and Initiates Verification ===");
  const bobParsedHeaderObj = HeaderClass.parse(finalFileHeaderBytes);
  const bobParsedHeader = bobParsedHeaderObj.header;

  // Resolve Sender Identity
  console.log("Bob is verifying sender identity via KeyLog and GK v1...");
  const senderInfo = resolveSender(bobParsedHeader, keyLog, gkV1);
  console.log("Sender Identity Decrypted:");
  console.log(`  Signer User ID: ${senderInfo.userId.toString()}`);
  console.log(`  Signing Device: ${senderInfo.humanLabel}`);
  console.log(`  Active Status: Device was active at signature timestamp.`);

  // Bob Unwraps the DEK
  console.log("\nBob retrieves his GK v1 wrap from manifest and decrypts the DEK...");
  const bobGkWrap = manifest.findMemberWrap(bobId);
  const bobUnwrappedGk = unwrapKeyWithRecipientKey(bobGkWrap, bobRecipientKp.secretKey);
  const bobUnwrappedDek = unwrapDekWithGroupKey(bobParsedHeader.wraps[0], bobUnwrappedGk);
  console.log(`Bob's unwrapped DEK: ${bobUnwrappedDek.toString("hex")}`);

  // Decrypt chunks and reassemble
  console.log("\nBob is decrypting the PDF chunks with the unwrapped DEK:");
  const decryptedChunks = envelopes.map((env, index) => {
    return decryptChunk(bobUnwrappedDek, fileId, index, env);
  });
  console.log("Decrypted PDF Document Contents:");
  decryptedChunks.forEach((c, idx) => console.log(`  Page ${idx + 1}: ${c.toString()}`));

  // 6. Eager Revocation: Offboard Bob and Rotate Group Key
  console.log("\n=== Eager Revocation: Bob is Offboarded & Group Key is Rotated ===");
  
  console.log("Alice removes Bob from the group...");
  manifest.removeMember(bobId, aliceSigningKp.publicKey, aliceSigningKp.secretKey, Math.floor(Date.now() / 1000));
  
  console.log("Alice rotates the Group Key (GK v1 -> GK v2)...");
  const gkV2 = generateGk();
  manifest.rotateGroupKey(gkV2, aliceSigningKp.publicKey, aliceSigningKp.secretKey, Math.floor(Date.now() / 1000));

  // Rewrap historical file headers with the new Group Key v2
  console.log("Migrating file headers to GK v2...");
  const rewrapRes = rewrapDekInHeader(finalFileHeaderBytes, gkV1, gkV2, 2);
  const updatedHeaderBytes = rewrapRes.header;

  console.log(`Updated Group Version: ${manifest.currentGkVersion()}`);
  console.log(`Active members in the group: ${manifest.currentMembers().map(m => m.toString()).join(", ")}`);

  // 7. Verify Bob can no longer access new or updated files
  console.log("\n=== Bob Authorization Check (Access Control Verification After Revocation) ===");
  try {
    console.log("Bob tries to find a GK v2 wrap in the updated manifest...");
    manifest.findMemberWrapForVersion(bobId, 2);
    console.log("FLAW: Bob was able to access the new GK version after being offboarded!");
  } catch (err: any) {
    console.log(`Bob's search for GK v2 wrap failed as expected:`);
    console.log(`  Error Message: ${err.message}`);
  }

  console.log("\nEnd-to-End DoccA Enterprise Document Lifecycle successfully simulated and verified.");
}

main().catch((err) => {
  console.error("An error occurred:", err);
});
