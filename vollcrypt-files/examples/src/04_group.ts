import {
  generateDek,
  generateGk,
  generateRecipientKeypair,
  ed25519KeypairGenerate,
  wrapDekForGroup,
  unwrapDekWithGroupKey,
  unwrapKeyWithRecipientKey,
  GroupManifest
} from "@vollcrypt/files-node";

async function main() {
  console.log("=== Example 04: Group Manifest and Group Encryption ===");

  // 1. Prepare founder member and group parameters
  const groupId = Buffer.alloc(16);
  groupId.write("VollGroup_000001"); // 16 bytes
  const initialGk = generateGk();
  console.log(`Group ID: ${groupId.toString()}`);
  console.log(`Initial Group Key (GK v1): ${initialGk.toString("hex")}`);

  // Founder keys
  const aliceId = Buffer.alloc(16);
  aliceId.write("Alice_Member_ID_"); // 16 bytes
  const aliceRecipientKp = generateRecipientKeypair();
  const aliceSigningKp = ed25519KeypairGenerate();

  // 2. Create the group (Genesis)
  console.log("\nAlice is starting the group (Genesis)...");
  const manifest = GroupManifest.genesis(
    groupId,
    initialGk,
    aliceId,
    aliceRecipientKp.publicKey,
    aliceSigningKp.publicKey,
    aliceSigningKp.secretKey,
    Math.floor(Date.now() / 1000)
  );

  console.log("GroupManifest established.");
  console.log(`  Current Members: ${manifest.currentMembers().map(m => m.toString()).join(", ")}`);
  console.log(`  Group Key Version: ${manifest.currentGkVersion()}`);

  // 3. Add a new member (Bob) to the group
  const bobId = Buffer.alloc(16);
  bobId.write("Bob_Member_ID___"); // 16 bytes
  const bobRecipientKp = generateRecipientKeypair();
  const bobSigningKp = ed25519KeypairGenerate();

  console.log("\nAdding Bob to the group...");
  const bobMemberPk = {
    recipient: bobRecipientKp.publicKey,
    signingPk: bobSigningKp.publicKey
  };

  manifest.addMember(
    bobId,
    bobMemberPk,
    initialGk,
    aliceSigningKp.publicKey,
    aliceSigningKp.secretKey,
    Math.floor(Date.now() / 1000)
  );

  console.log("New member added.");
  console.log(`  New Member List: ${manifest.currentMembers().map(m => m.toString()).join(", ")}`);

  // 4. Serialize and parse back the manifest (persistence check)
  console.log("\nSerializing manifest to binary data...");
  const manifestBytes = manifest.write();
  console.log(`Serialized size: ${manifestBytes.length} bytes`);

  console.log("Parsing manifest back from binary data...");
  const parsedManifest = GroupManifest.parse(manifestBytes);
  parsedManifest.verify();
  console.log("Manifest signature verified successfully.");

  // 5. Generate a DEK and encrypt targeting this group (GroupWrap)
  const dek = generateDek();
  console.log(`\nGenerating shared file DEK for the group: ${dek.toString("hex")}`);

  // Wrap DEK for the group
  const groupWrap = wrapDekForGroup(
    dek,
    groupId,
    parsedManifest.currentGkVersion(), // v1
    initialGk
  );
  console.log("WrapEntry successfully created:");
  console.log(`  Kind: ${groupWrap.kind}`);
  console.log(`  Group ID: ${groupWrap.groupId?.toString()}`);
  console.log(`  Group Key Version: ${groupWrap.gkVersion}`);
  console.log(`  Wrapped DEK: ${groupWrap.wrappedKey.toString("hex")}`);

  // 6. Bob finds his wrap entry in the manifest, decrypts the GK, and obtains the DEK
  console.log("\nBob is looking for his recipient wrap in the manifest...");
  const bobWrap = parsedManifest.findMemberWrap(bobId);
  console.log("Bob's wrap entry found. Decrypting GK v1 using Bob's private recipient key...");
  const bobUnwrappedGk = unwrapKeyWithRecipientKey(bobWrap, bobRecipientKp.secretKey);
  console.log(`Bob's unwrapped Group Key: ${bobUnwrappedGk.toString("hex")}`);
  console.log(`Matches original GK: ${initialGk.equals(bobUnwrappedGk) ? "Yes" : "No"}`);

  console.log("\nBob is decrypting the file DEK using the unwrapped Group Key...");
  const bobUnwrappedDek = unwrapDekWithGroupKey(groupWrap, bobUnwrappedGk);
  console.log(`Bob's unwrapped DEK: ${bobUnwrappedDek.toString("hex")}`);
  console.log(`Matches original DEK: ${dek.equals(bobUnwrappedDek) ? "Yes" : "No"}`);
}

main().catch((err) => {
  console.error("An error occurred:", err);
});
