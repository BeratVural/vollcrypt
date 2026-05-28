import { test } from 'node:test';
import assert from 'node:assert';
// @ts-ignore
import * as api from '../index.js';

test('random generation parameters', () => {
  const dek = api.generateDek();
  assert.strictEqual(dek.length, 32);

  const fileId = api.generateFileId();
  assert.strictEqual(fileId.length, 16);

  const salt = api.generateSalt();
  assert.strictEqual(salt.length, 16);

  const gk = api.generateGk();
  assert.strictEqual(gk.length, 32);
});

test('password mode roundtrip', () => {
  const dek = api.generateDek();
  const fileId = api.generateFileId();
  const plaintext = Buffer.from('hello world password encryption test');

  // Encrypt chunk
  const envelope = api.encryptChunk(dek, fileId, 0, plaintext);
  assert.strictEqual(envelope.chunkIndex, 0);

  // Wrap DEK
  const kdf = {
    kind: 'Pbkdf2',
    rounds: 1000,
    salt: api.generateSalt(),
    mCost: undefined,
    tCost: undefined,
    pCost: undefined,
  };
  const wrap = api.wrapDekWithPassword(dek, 'my-secure-password', kdf);
  assert.strictEqual(wrap.kind, 'PasswordPbkdf2');

  // Unwrap DEK
  const unwrappedDek = api.unwrapDekWithPassword(wrap, 'my-secure-password');
  assert.deepStrictEqual(unwrappedDek, dek);

  // Decrypt chunk
  const decrypted = api.decryptChunk(unwrappedDek, fileId, 0, envelope);
  assert.deepStrictEqual(decrypted, plaintext);
});

test('wrong password fails', () => {
  const dek = api.generateDek();
  const kdf = {
    kind: 'Pbkdf2',
    rounds: 1000,
    salt: api.generateSalt(),
    mCost: undefined,
    tCost: undefined,
    pCost: undefined,
  };
  const wrap = api.wrapDekWithPassword(dek, 'correct-password', kdf);

  assert.throws(() => {
    api.unwrapDekWithPassword(wrap, 'wrong-password');
  });
});

test('async password unwrap roundtrip', async () => {
  const dek = api.generateDek();
  const kdf = {
    kind: 'Argon2id',
    rounds: undefined,
    salt: api.generateSalt(),
    mCost: 1024,
    tCost: 2,
    pCost: 1,
  };
  const wrap = api.wrapDekWithPassword(dek, 'my-password', kdf);

  const unwrapped = await api.unwrapDekWithPasswordAsync(wrap, 'my-password');
  assert.deepStrictEqual(unwrapped, dek);
});

test('recipient mode roundtrip', () => {
  const key = api.generateDek();
  const recipientId = api.generateFileId(); // 16 bytes
  const keypair = api.generateRecipientKeypair();

  // Wrap
  const wrap = api.wrapKeyToRecipient(key, recipientId, 1, keypair.publicKey);
  assert.strictEqual(wrap.kind, 'HybridKem');

  // Unwrap
  const unwrapped = api.unwrapKeyWithRecipientKey(wrap, keypair.secretKey);
  assert.deepStrictEqual(unwrapped, key);
});

test('multi-recipient', () => {
  const key = api.generateDek();
  const rep1 = api.generateRecipientKeypair();
  const rep2 = api.generateRecipientKeypair();
  const rep3 = api.generateRecipientKeypair();

  const id1 = api.generateFileId();
  const id2 = api.generateFileId();
  const id3 = api.generateFileId();

  const w1 = api.wrapKeyToRecipient(key, id1, 1, rep1.publicKey);
  const w2 = api.wrapKeyToRecipient(key, id2, 1, rep2.publicKey);
  const w3 = api.wrapKeyToRecipient(key, id3, 1, rep3.publicKey);

  // All recipients should be able to unwrap the same key
  assert.deepStrictEqual(api.unwrapKeyWithRecipientKey(w1, rep1.secretKey), key);
  assert.deepStrictEqual(api.unwrapKeyWithRecipientKey(w2, rep2.secretKey), key);
  assert.deepStrictEqual(api.unwrapKeyWithRecipientKey(w3, rep3.secretKey), key);
});

test('group manifest genesis + addMember + removeMember', () => {
  const groupId = api.generateFileId();
  const initialGk = api.generateDek();
  const founderId = api.generateFileId();
  const founderRecipient = api.generateRecipientKeypair();
  const founderSigning = api.ed25519KeypairGenerate();

  // Genesis
  const manifest = api.GroupManifest.genesis(
    groupId,
    initialGk,
    founderId,
    founderRecipient.publicKey,
    founderSigning.publicKey,
    founderSigning.secretKey,
    Math.floor(Date.now() / 1000)
  );

  manifest.verify();

  assert.strictEqual(manifest.currentGkVersion(), 1);
  const members = manifest.currentMembers();
  assert.strictEqual(members.length, 1);
  assert.deepStrictEqual(members[0], founderId);

  // Add Member
  const newMemberId = api.generateFileId();
  const newRecipient = api.generateRecipientKeypair();
  const newSigning = api.ed25519KeypairGenerate();
  const newMemberKeys = {
    recipient: newRecipient.publicKey,
    signingPk: newSigning.publicKey,
  };

  manifest.addMember(
    newMemberId,
    newMemberKeys,
    initialGk,
    founderSigning.publicKey,
    founderSigning.secretKey,
    Math.floor(Date.now() / 1000)
  );

  manifest.verify();
  assert.strictEqual(manifest.currentMembers().length, 2);

  // Check new member's wrap can resolve the GK
  const wrap = manifest.findMemberWrap(newMemberId);
  const resolvedGk = api.unwrapKeyWithRecipientKey(wrap, newRecipient.secretKey);
  assert.deepStrictEqual(resolvedGk, initialGk);

  // Remove Member
  manifest.removeMember(
    newMemberId,
    founderSigning.publicKey,
    founderSigning.secretKey,
    Math.floor(Date.now() / 1000)
  );

  manifest.verify();
  assert.strictEqual(manifest.currentMembers().length, 1);
  assert.deepStrictEqual(manifest.currentMembers()[0], founderId);
});

test('key rotation and rewrapping', () => {
  const groupId = api.generateFileId();
  const gk1 = api.generateDek();
  const founderId = api.generateFileId();
  const founderRecipient = api.generateRecipientKeypair();
  const founderSigning = api.ed25519KeypairGenerate();

  const manifest = api.GroupManifest.genesis(
    groupId,
    gk1,
    founderId,
    founderRecipient.publicKey,
    founderSigning.publicKey,
    founderSigning.secretKey,
    Math.floor(Date.now() / 1000)
  );

  // Rotate Key
  const gk2 = api.generateDek();
  const newVersion = manifest.rotateGroupKey(
    gk2,
    founderSigning.publicKey,
    founderSigning.secretKey,
    Math.floor(Date.now() / 1000)
  );

  assert.strictEqual(newVersion, 2);
  assert.strictEqual(manifest.currentGkVersion(), 2);

  // verify wrap of member for version 2
  const wrapv2 = manifest.findMemberWrapForVersion(founderId, 2);
  const resolvedGk2 = api.unwrapKeyWithRecipientKey(wrapv2, founderRecipient.secretKey);
  assert.deepStrictEqual(resolvedGk2, gk2);

  // Header rewrap simulation
  const fileId = api.generateFileId();
  const dek = api.generateDek();
  const groupWrap = api.wrapDekForGroup(dek, groupId, 1, gk1);

  // Mock header obj
  const header: api.HeaderObj = {
    version: 2,
    mode: 2, // Group Mode
    cipherId: 0,
    fileId,
    chunkSize: 65536,
    plaintextSize: 1000,
    merkleRoot: api.generateDek(),
    wraps: [groupWrap],
    signedMetadata: undefined,
    signature: undefined,
  };

  const headerBytes = api.HeaderClass.write(header);
  const rewrapResult = api.rewrapDekInHeader(headerBytes, gk1, gk2, 2);

  assert.strictEqual(rewrapResult.updatedCount, 1);

  const parsed = api.HeaderClass.parse(rewrapResult.header);
  assert.strictEqual(parsed.header.wraps[0].gkVersion, 2);

  const decryptedDek = api.unwrapDekWithGroupKey(parsed.header.wraps[0], gk2);
  assert.deepStrictEqual(decryptedDek, dek);
});

test('crypto shred file header', () => {
  const fileId = api.generateFileId();
  const dek = api.generateDek();
  const kdf = {
    kind: 'Pbkdf2',
    rounds: 1000,
    salt: api.generateSalt(),
    mCost: undefined,
    tCost: undefined,
    pCost: undefined,
  };
  const wrap = api.wrapDekWithPassword(dek, 'password', kdf);

  const header: api.HeaderObj = {
    version: 2,
    mode: 0,
    cipherId: 0,
    fileId,
    chunkSize: 65536,
    plaintextSize: 100,
    merkleRoot: api.generateDek(),
    wraps: [wrap],
    signedMetadata: undefined,
    signature: undefined,
  };

  const headerBytes = api.HeaderClass.write(header);
  const shreddedBytes = api.cryptoShredHeader(headerBytes);

  const parsed = api.HeaderClass.parse(shreddedBytes);
  assert.strictEqual(parsed.header.wraps.length, 0);
});

test('signed header plain + verify', () => {
  const fileId = api.generateFileId();
  const signerKeys = api.ed25519KeypairGenerate();
  const keyLogId = api.generateDek();

  const header: api.HeaderObj = {
    version: 2,
    mode: 0,
    cipherId: 0,
    fileId,
    chunkSize: 65536,
    plaintextSize: 100,
    merkleRoot: api.generateDek(),
    wraps: [],
    signedMetadata: undefined,
    signature: undefined,
  };

  const signed = api.signHeaderPlain(
    header,
    signerKeys.publicKey,
    signerKeys.secretKey,
    keyLogId,
    Math.floor(Date.now() / 1000)
  );

  assert.ok(signed.signature);
  assert.strictEqual(signed.signedMetadata?.kind, 'Plain');

  const signerPubkey = api.verifyHeaderSignaturePlain(signed);
  assert.deepStrictEqual(signerPubkey, signerKeys.publicKey);
});

test('signed header sealed + resolve_sender', () => {
  const fileId = api.generateFileId();
  const signerKeys = api.ed25519KeypairGenerate();

  // Setup KeyLog
  const authority = api.ed25519KeypairGenerate();
  const keyLog = api.KeyLog.create(authority.publicKey);

  const userId = api.generateFileId();
  const deviceId = api.generateFileId();

  // Register device first to get the actual keyLogId
  const keyLogId = keyLog.registerDevice(
    userId,
    deviceId,
    signerKeys.publicKey,
    'My MacBook Pro',
    authority.secretKey,
    Math.floor(Date.now() / 1000) - 100
  );

  const header: api.HeaderObj = {
    version: 2,
    mode: 2,
    cipherId: 0,
    fileId,
    chunkSize: 65536,
    plaintextSize: 100,
    merkleRoot: api.generateDek(),
    wraps: [],
    signedMetadata: undefined,
    signature: undefined,
  };

  const groupId = api.generateFileId();
  const gk = api.generateDek();

  // Sign using the actual registration entry hash
  const signed = api.signHeaderSealed(
    header,
    signerKeys.publicKey,
    signerKeys.secretKey,
    keyLogId,
    Math.floor(Date.now() / 1000),
    groupId,
    1,
    gk
  );

  assert.ok(signed.signature);
  assert.strictEqual(signed.signedMetadata?.kind, 'Sealed');

  const signerPubkey = api.verifyHeaderSignatureSealed(signed, gk);
  assert.deepStrictEqual(signerPubkey, signerKeys.publicKey);

  const senderInfo = api.resolveSender(signed, keyLog, gk);
  assert.deepStrictEqual(senderInfo.signerPubkey, signerKeys.publicKey);
  assert.deepStrictEqual(senderInfo.userId, userId);
  assert.deepStrictEqual(senderInfo.deviceId, deviceId);
  assert.strictEqual(senderInfo.deviceWasActive, true);
  assert.strictEqual(senderInfo.humanLabel, 'My MacBook Pro');
});

test('ed25519 sign/verify', () => {
  const keypair = api.ed25519KeypairGenerate();
  const message = Buffer.from('merhaba dunya');
  const signature = api.ed25519Sign(keypair.secretKey, message);
  const isValid = api.ed25519Verify(keypair.publicKey, message, signature);
  assert.strictEqual(isValid, true);
});

test('pipelined file encryption and decryption roundtrip', async () => {
  const fs = await import('node:fs');
  const path = await import('node:path');
  const os = await import('node:os');

  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'vollcrypt-test-'));
  const srcPath = path.join(tempDir, 'source.bin');
  const encPath = path.join(tempDir, 'encrypted.bin');
  const decPath = path.join(tempDir, 'decrypted.bin');

  // Create a source file with some data (1 MB)
  const dataSize = 1024 * 1024;
  const originalData = Buffer.alloc(dataSize);
  for (let i = 0; i < dataSize; i++) {
    originalData[i] = i % 256;
  }
  fs.writeFileSync(srcPath, originalData);

  const dek = api.generateDek();
  const fileId = api.generateFileId();
  const chunkSize = 65536; // 64 KB

  // Wrap DEK
  const kdf = {
    kind: 'Pbkdf2',
    rounds: 1000,
    salt: api.generateSalt(),
    mCost: undefined,
    tCost: undefined,
    pCost: undefined,
  };
  const wrap = api.wrapDekWithPassword(dek, 'pipelined-password', kdf);

  // Encrypt file
  const header = await api.encryptFilePipelinedAsync(
    srcPath,
    encPath,
    dek,
    fileId,
    chunkSize,
    [wrap],
    0, // Mode::Password
    4, // num_workers
    null // sign_info
  );

  assert.strictEqual(header.version, 1);
  assert.deepStrictEqual(header.fileId, fileId);
  assert.strictEqual(header.chunkSize, chunkSize);

  // Decrypt file
  const decHeader = await api.decryptFilePipelinedAsync(
    encPath,
    decPath,
    dek,
    4 // num_workers
  );

  assert.deepStrictEqual(decHeader.fileId, fileId);

  // Compare original vs decrypted data
  const decryptedData = fs.readFileSync(decPath);
  assert.deepStrictEqual(decryptedData, originalData);

  // Cleanup
  fs.rmSync(tempDir, { recursive: true, force: true });
});

test('pipelined file encryption with signing', async () => {
  const fs = await import('node:fs');
  const path = await import('node:path');
  const os = await import('node:os');

  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'vollcrypt-test-sign-'));
  const srcPath = path.join(tempDir, 'source.bin');
  const encPath = path.join(tempDir, 'encrypted.bin');
  const decPath = path.join(tempDir, 'decrypted.bin');

  const originalData = Buffer.from('Testing file signing with pipelined encryption');
  fs.writeFileSync(srcPath, originalData);

  const dek = api.generateDek();
  const fileId = api.generateFileId();
  const chunkSize = 4096;

  // Sign info setup (Plain)
  const signerKeys = api.ed25519KeypairGenerate();
  const keyLogId = api.generateDek();
  const timestamp = Math.floor(Date.now() / 1000);

  const signInfo = {
    kind: 'Plain',
    signerEd25519Pk: signerKeys.publicKey,
    signerEd25519Sk: signerKeys.secretKey,
    keyLogId: keyLogId,
    timestamp: timestamp,
    sealedGroupId: undefined,
    sealedGkVersion: undefined,
    sealedGk: undefined,
  };

  // Encrypt file
  const header = await api.encryptFilePipelinedAsync(
    srcPath,
    encPath,
    dek,
    fileId,
    chunkSize,
    [],
    0, // Mode::Password
    2, // num_workers
    signInfo
  );

  assert.strictEqual(header.version, 2);
  assert.ok(header.signature);
  assert.strictEqual(header.signedMetadata?.kind, 'Plain');

  // Verify header signature
  const signerPubkey = api.verifyHeaderSignaturePlain(header);
  assert.deepStrictEqual(signerPubkey, signerKeys.publicKey);

  // Decrypt file
  await api.decryptFilePipelinedAsync(
    encPath,
    decPath,
    dek,
    2 // num_workers
  );

  const decryptedData = fs.readFileSync(decPath);
  assert.deepStrictEqual(decryptedData, originalData);

  fs.rmSync(tempDir, { recursive: true, force: true });
});
