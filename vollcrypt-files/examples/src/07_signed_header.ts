import {
  generateDek,
  generateFileId,
  ed25519KeypairGenerate,
  wrapDekWithPassword,
  signHeaderPlain,
  verifyHeaderSignaturePlain,
  HeaderClass,
  HeaderObj
} from "@vollcrypt/files-node";

async function main() {
  console.log("=== Example 07: File Header Signing and Tampering Protection ===");

  // 1. Encrypt file and build header
  const dek = generateDek();
  const fileId = generateFileId();
  const kdfChoice = { kind: "Pbkdf2", rounds: 10000 };
  const wrapEntry = wrapDekWithPassword(dek, "SecurePassword", kdfChoice);

  const header: HeaderObj = {
    version: 2, // Version 2 supports signatures
    mode: 0,
    cipherId: 0,
    fileId: fileId,
    chunkSize: 65536,
    plaintextSize: 409600,
    merkleRoot: Buffer.alloc(32),
    wraps: [wrapEntry]
  };

  console.log(`Initial File Header Created. FileID: ${fileId.toString("hex")}`);

  // 2. Generate signing device Ed25519 keys and sign
  const deviceKp = ed25519KeypairGenerate();
  const keyLogId = Buffer.alloc(32); // Mock KeyLog entry hash
  keyLogId.write("Device_Registry_Entry_Hash");

  console.log("\nSigning file header with device key (Plain signature)...");
  const signedHeader = signHeaderPlain(
    header,
    deviceKp.publicKey,
    deviceKp.secretKey,
    keyLogId,
    Math.floor(Date.now() / 1000)
  );

  console.log("Header Signed:");
  console.log(`  Signature: ${signedHeader.signature?.toString("hex").substring(0, 40)}...`);
  console.log(`  Signing Device: ${signedHeader.signedMetadata?.signerPubkey?.toString("hex")}`);

  // 3. Verify the signed header
  console.log("\nVerifying signed header...");
  try {
    const verifiedPk = verifyHeaderSignaturePlain(signedHeader);
    console.log("Verification SUCCESSFUL!");
    console.log(`  Verified Public Key: ${verifiedPk.toString("hex")}`);
    console.log(`  Matches original public key: ${deviceKp.publicKey.equals(verifiedPk) ? "Yes" : "No"}`);
  } catch (err: any) {
    console.error("Verification Failed:", err.message);
  }

  // 4. Tampering Scenario: Modify the plaintext size field
  console.log("\n--- Tampering Scenario: Modifying File Size Field ---");
  const tamperedHeader: HeaderObj = {
    ...signedHeader,
    plaintextSize: 999999 // Mutated size
  };

  console.log(`Tampered file size: ${tamperedHeader.plaintextSize}`);
  console.log("Verifying tampered header...");
  try {
    verifyHeaderSignaturePlain(tamperedHeader);
    console.log("WARNING: Tampered header verified! Security flaw.");
  } catch (err: any) {
    console.log("Verification successfully REJECTED (Tampering Detected):");
    console.log(`  Error Details: ${err.message}`);
  }
}

main().catch((err) => {
  console.error("An error occurred:", err);
});
