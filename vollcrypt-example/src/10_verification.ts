// Run: npx ts-node src/10_verification.ts
//
// This example demonstrates the Key Verification primitive.
// Alice and Bob calculate and compare verification codes.

import * as vollcrypt from '@vollsign/crypto-node';

async function main() {
  console.log('=== Key Verification Demo ===\n');

  // --- Scenario 1: Legitimate communication ---
  // generateEd25519Keypair returns Array<Buffer> [secret, public]
  const alice = vollcrypt.generateEd25519Keypair();
  const bob   = vollcrypt.generateEd25519Keypair();
  const convId = Buffer.from('conv-alice-bob-001');

  // alice[1] is public key
  const codeAliceJson = vollcrypt.generateVerificationCode(
    alice[1], bob[1], convId
  );
  const codeAlice = JSON.parse(codeAliceJson);

  const codeBobJson = vollcrypt.generateVerificationCode(
    bob[1], alice[1], convId  // Different order — same result
  );
  const codeBob = JSON.parse(codeBobJson);

  console.log('Code on Alice side:');
  console.log('  Numeric:', codeAlice.numeric.formatted);
  console.log('  Emoji:  ', codeAlice.emoji.formatted);

  console.log('\nCode on Bob side:');
  console.log('  Numeric:', codeBob.numeric.formatted);
  console.log('  Emoji:  ', codeBob.emoji.formatted);

  const legit = vollcrypt.verifyFingerprintsMatch(
    Buffer.from(codeAlice.fingerprint),
    Buffer.from(codeBob.fingerprint),
  );
  console.log('\n✅ Do codes match?', legit); // true

  // --- Scenario 2: MITM attack ---
  const mallory = vollcrypt.generateEd25519Keypair();

  const codeMitmJson = vollcrypt.generateVerificationCode(
    alice[1], mallory[1], convId  // Mallory pretending to be Bob
  );
  const codeMitm = JSON.parse(codeMitmJson);

  const attacked = vollcrypt.verifyFingerprintsMatch(
    Buffer.from(codeAlice.fingerprint),
    Buffer.from(codeMitm.fingerprint),
  );
  console.log('\n🚨 Do codes match in MITM scenario?', attacked); // false
  console.log('   Alice code:', codeAlice.numeric.groups.slice(0, 3).join(' '), '...');
  console.log('   MITM code: ', codeMitm.numeric.groups.slice(0, 3).join(' '), '...');
  console.log('\nDifferent code -> Server changed keys! Not secure.');
}

main().catch(console.error);
