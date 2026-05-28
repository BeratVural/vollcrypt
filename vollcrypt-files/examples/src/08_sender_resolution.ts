import {
  generateDek,
  generateFileId,
  generateGk,
  ed25519KeypairGenerate,
  wrapDekForGroup,
  signHeaderSealed,
  resolveSender,
  KeyLog,
  HeaderObj
} from "@vollcrypt/files-node";

async function main() {
  console.log("=== Example 08: Device Registration, Sealed Signature and Sender Identity Resolution via KeyLog ===");

  // 1. Setup KeyLog and Authority
  const authorityKp = ed25519KeypairGenerate();
  const keyLog = KeyLog.create(authorityKp.publicKey);
  console.log(`KeyLog Authority Public Key: ${authorityKp.publicKey.toString("hex")}`);

  // 2. User & Device Registration
  const userId = Buffer.alloc(16);
  userId.write("User_ID_Lawyer01"); // 16 bytes
  const deviceId = Buffer.alloc(16);
  deviceId.write("Device_Laptop_01"); // 16 bytes
  const deviceKp = ed25519KeypairGenerate();

  console.log(`\nRegistering device...`);
  console.log(`  User ID: ${userId.toString()}`);
  console.log(`  Device ID: ${deviceId.toString()}`);
  console.log(`  Device Public Key: ${deviceKp.publicKey.toString("hex")}`);

  const signatureTimestamp = Math.floor(Date.now() / 1000);
  const entryHash = keyLog.registerDevice(
    userId,
    deviceId,
    deviceKp.publicKey,
    "Ahmet Lawyer - Lenovo ThinkPad",
    authorityKp.secretKey,
    signatureTimestamp - 3600 // Registered 1 hour ago
  );
  console.log(`Device registration successful. Registry Entry Hash (KeyLogID): ${entryHash.toString("hex")}`);

  // 3. Create File Header and sign in Sealed Mode
  // Sealed Mode hides the signer's identity by encrypting it under the Group Key (GK).
  const dek = generateDek();
  const fileId = generateFileId();
  const groupId = Buffer.alloc(16);
  groupId.write("VollGroup_Sealed");
  const gk = generateGk();
  
  const groupWrap = wrapDekForGroup(dek, groupId, 1, gk);
  const header: HeaderObj = {
    version: 2,
    mode: 2,
    cipherId: 0,
    fileId: fileId,
    chunkSize: 65536,
    plaintextSize: 2048,
    merkleRoot: Buffer.alloc(32),
    wraps: [groupWrap]
  };

  console.log("\nSigning file header in Sealed Mode...");
  const signedHeader = signHeaderSealed(
    header,
    deviceKp.publicKey,
    deviceKp.secretKey,
    entryHash, // Cihaz registry entry hash as keyLogId
    signatureTimestamp,
    groupId,
    1, // GK Version 1
    gk
  );

  console.log("File Sealed-Signed Successfully.");
  console.log(`  signedMetadata.signerPubkey (Cleartext): ${signedHeader.signedMetadata?.signerPubkey?.toString("hex") || "NONE (Sealed/Encrypted)"}`);
  console.log(`  sealedPayload (Encrypted Device Public Key): ${signedHeader.signedMetadata?.sealedPayload?.toString("hex")}`);

  // 4. Resolve Sender
  console.log("\nResolving sender on recipient side (Resolve Sender)...");
  // Recipient holds the GK and the KeyLog registry database.
  const senderInfo = resolveSender(signedHeader, keyLog, gk);
  console.log("Resolved Sender Information:");
  console.log(`  Signing Device Key: ${senderInfo.signerPubkey.toString("hex")}`);
  console.log(`  User ID: ${senderInfo.userId.toString()}`);
  console.log(`  Device ID: ${senderInfo.deviceId.toString()}`);
  console.log(`  Device Label: ${senderInfo.humanLabel}`);
  console.log(`  Was device active at signature timestamp: ${senderInfo.deviceWasActive ? "Yes" : "No"}`);

  // 5. Revoke Device and check status again
  console.log("\n--- Revoking Device by Authority ---");
  const revokeTimestamp = Math.floor(Date.now() / 1000) + 10;
  keyLog.revokeDevice(deviceId, authorityKp.secretKey, revokeTimestamp);

  // Validate the signature's status after revocation
  console.log(`\nValidating historical signature status (signed at: ${signatureTimestamp}) after revocation...`);
  const resolvedAfterRevoke = resolveSender(signedHeader, keyLog, gk);
  console.log(`  Was device active at signature timestamp: ${resolvedAfterRevoke.deviceWasActive ? "Yes" : "No"}`);
  
  // What happens if we check device status at a point after the revocation timestamp?
  console.log(`\nChecking device active status for a timestamp after revocation...`);
  const isDeviceActiveNow = keyLog.deviceWasActiveAt(deviceId, revokeTimestamp + 100);
  console.log(`  Is device active now: ${isDeviceActiveNow ? "Yes" : "No"}`);
}

main().catch((err) => {
  console.error("An error occurred:", err);
});
