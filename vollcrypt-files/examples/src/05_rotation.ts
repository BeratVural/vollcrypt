import {
  generateDek,
  generateFileId,
  generateGk,
  generateRecipientKeypair,
  ed25519KeypairGenerate,
  wrapDekForGroup,
  unwrapDekWithGroupKey,
  unwrapKeyWithRecipientKey,
  rewrapDekInHeader,
  GroupManifest,
  HeaderClass,
  HeaderObj
} from "@vollcrypt/files-node";

async function main() {
  console.log("=== Example 05: Eager Revocation - Group Key Rotation and Header Rewrapping ===");

  // 1. Setup Founder and Group
  const groupId = Buffer.alloc(16);
  groupId.write("VollGroup_Rot_01");
  const gkV1 = generateGk();
  
  const aliceId = Buffer.alloc(16);
  aliceId.write("Alice_Admin_____");
  const aliceRecipientKp = generateRecipientKeypair();
  const aliceSigningKp = ed25519KeypairGenerate();

  // Genesis
  const manifest = GroupManifest.genesis(
    groupId,
    gkV1,
    aliceId,
    aliceRecipientKp.publicKey,
    aliceSigningKp.publicKey,
    aliceSigningKp.secretKey,
    Math.floor(Date.now() / 1000)
  );

  // Add Bob to the group
  const bobId = Buffer.alloc(16);
  bobId.write("Bob_User________");
  const bobRecipientKp = generateRecipientKeypair();
  const bobSigningKp = ed25519KeypairGenerate();

  manifest.addMember(
    bobId,
    { recipient: bobRecipientKp.publicKey, signingPk: bobSigningKp.publicKey },
    gkV1,
    aliceSigningKp.publicKey,
    aliceSigningKp.secretKey,
    Math.floor(Date.now() / 1000)
  );

  console.log("Group initialized with GK v1 and Bob added.");
  console.log(`  Group Version: ${manifest.currentGkVersion()}`);

  // 2. Create a file and encrypt under GK v1 (generate File Header)
  const fileId = generateFileId();
  const dek = generateDek();
  console.log(`\nCreating file: File ID=${fileId.toString("hex")}, DEK=${dek.toString("hex")}`);

  const initialGroupWrap = wrapDekForGroup(dek, groupId, 1, gkV1);
  const header: HeaderObj = {
    version: 2,
    mode: 2, // Group mode
    cipherId: 0, // AES-256-GCM
    fileId: fileId,
    chunkSize: 65536,
    plaintextSize: 100000,
    merkleRoot: Buffer.alloc(32), // dummy merkle root
    wraps: [initialGroupWrap]
  };

  const initialHeaderBytes = HeaderClass.write(header);
  console.log(`Initial File Header Written: ${initialHeaderBytes.length} bytes`);

  // 3. Eager Revocation: Rotate the Group Key (GK v1 -> GK v2)
  console.log("\n--- Rotating Group Key (GK v1 -> GK v2) ---");
  const gkV2 = generateGk();
  console.log(`New Group Key (GK v2): ${gkV2.toString("hex")}`);

  // Add rotation operation to manifest
  manifest.rotateGroupKey(
    gkV2,
    aliceSigningKp.publicKey,
    aliceSigningKp.secretKey,
    Math.floor(Date.now() / 1000)
  );
  console.log(`Manifest updated. New GK Version: ${manifest.currentGkVersion()}`);

  // 4. Rewrap the File Header (Header Rewrap)
  console.log("\nRewrapping the DEK in the File Header from GK v1 to GK v2...");
  const rewrapResult = rewrapDekInHeader(
    initialHeaderBytes,
    gkV1,
    gkV2,
    manifest.currentGkVersion() // 2
  );

  console.log(`Rewrapping completed:`);
  console.log(`  Updated wraps count: ${rewrapResult.updatedCount}`);
  console.log(`  New header size: ${rewrapResult.header.length} bytes`);

  // 5. Bob accesses the file using the new header and updated manifest
  console.log("\nBob is parsing the new header...");
  const parsedHeader = HeaderClass.parse(rewrapResult.header);
  const headerWrapForGkV2 = parsedHeader.header.wraps[0];
  console.log(`Target GK Version of the new wrap in header: ${headerWrapForGkV2.gkVersion}`);

  console.log("\nBob is looking for his GK v2 wrap in the updated manifest...");
  const bobWrapForV2 = manifest.findMemberWrapForVersion(bobId, 2);
  
  console.log("Bob is decrypting GK v2 with his private recipient key...");
  const bobUnwrappedGkV2 = unwrapKeyWithRecipientKey(bobWrapForV2, bobRecipientKp.secretKey);
  console.log(`Bob's unwrapped GK v2: ${bobUnwrappedGkV2.toString("hex")}`);
  console.log(`GK v2 verified: ${gkV2.equals(bobUnwrappedGkV2) ? "Yes" : "No"}`);

  console.log("\nBob is unwrapping the DEK from the header using GK v2...");
  const bobUnwrappedDek = unwrapDekWithGroupKey(headerWrapForGkV2, bobUnwrappedGkV2);
  console.log(`Bob's unwrapped DEK: ${bobUnwrappedDek.toString("hex")}`);
  console.log(`Matches original DEK: ${dek.equals(bobUnwrappedDek) ? "Yes" : "No"}`);
}

main().catch((err) => {
  console.error("An error occurred:", err);
});
