const { describe, test } = require('node:test');
const assert = require('node:assert');
const vc = require('../index.js');

const GENESIS_HASH = Buffer.alloc(32);

describe('messages native binding smoke tests', () => {
  test('AES-GCM encrypt/decrypt roundtrip binds AAD', () => {
    const key = Buffer.alloc(32, 7);
    const aad = Buffer.from('aad');
    const plaintext = Buffer.from('native binding plaintext');

    const ciphertext = vc.encryptAesGcm(key, plaintext, aad);
    assert.notDeepStrictEqual(ciphertext, plaintext);
    assert.deepStrictEqual(vc.decryptAesGcm(key, ciphertext, aad), plaintext);
    assert.throws(() => vc.decryptAesGcm(key, ciphertext, Buffer.from('wrong aad')));
  });

  test('Ed25519 signatures verify and reject tampering', () => {
    const [sk, pk] = vc.generateEd25519Keypair();
    const message = Buffer.from('signed message');
    const signature = vc.signMessage(sk, message);

    assert.strictEqual(vc.verifySignature(pk, message, signature), true);
    assert.strictEqual(vc.verifySignature(pk, Buffer.from('tampered'), signature), false);
  });

  test('key log queries verify the chain before returning current keys', () => {
    const [sk, pk] = vc.generateEd25519Keypair();
    const userId = Buffer.from('alice');
    const entry = JSON.parse(vc.keyLogCreateEntry(userId, pk, 1000n, GENESIS_HASH, 1, sk));
    const entriesJson = JSON.stringify([entry]);

    assert.strictEqual(vc.keyLogVerifyChain(entriesJson), true);
    assert.deepStrictEqual(vc.keyLogCurrentKey(entriesJson, userId), pk);

    const tampered = [{ ...entry, timestamp: 9999 }];
    assert.throws(() => vc.keyLogCurrentKey(JSON.stringify(tampered), userId));
  });

  test('64-bit counters and timestamps are not truncated at the JS boundary', () => {
    const low = 1n;
    const high = 0x1_0000_0001n;
    const srk = Buffer.alloc(32, 0x35);

    assert.notDeepStrictEqual(
      vc.deriveWindowKey(srk, high),
      vc.deriveWindowKey(srk, low),
    );

    const messageId = Buffer.from('message-id');
    const senderId = Buffer.from('sender-id');
    const ciphertext = Buffer.from('ciphertext');
    assert.notDeepStrictEqual(
      vc.transcriptComputeMessageHash(messageId, senderId, high, ciphertext),
      vc.transcriptComputeMessageHash(messageId, senderId, low, ciphertext),
    );

    const [aliceSecret] = vc.generateRatchetKeypair();
    const [, bobPublic] = vc.generateRatchetKeypair();
    assert.notDeepStrictEqual(
      vc.ratchetSrk(srk, aliceSecret, bobPublic, Buffer.from('chat'), high, true),
      vc.ratchetSrk(srk, aliceSecret, bobPublic, Buffer.from('chat'), low, true),
    );

    const [signingKey, publicKey] = vc.generateEd25519Keypair();
    const userId = Buffer.from('64-bit-user');
    const entry = JSON.parse(
      vc.keyLogCreateEntry(userId, publicKey, high, GENESIS_HASH, 1, signingKey),
    );
    assert.strictEqual(entry.timestamp, Number(high));

    const registry = JSON.parse(
      vc.registryAddDevice(vc.registryEmpty(), 'device-1', 'Phone', high, 'public-key'),
    );
    assert.strictEqual(registry.devices[0].added_at, Number(high));
  });

  test('key log returns null when a verified chain has no key for the user', () => {
    const [sk, pk] = vc.generateEd25519Keypair();
    const alice = Buffer.from('alice');
    const bob = Buffer.from('bob');
    const entry = JSON.parse(
      vc.keyLogCreateEntry(alice, pk, 1000n, GENESIS_HASH, 1, sk),
    );

    assert.strictEqual(vc.keyLogCurrentKey(JSON.stringify([entry]), bob), null);
    assert.strictEqual(
      vc.keyLogKeyAtTimestamp(JSON.stringify([entry]), bob, 1000n),
      null,
    );
  });
  test('sealed sender requires a trusted sender public key', () => {
    const [recipientSk, recipientPk] = vc.generateX25519Keypair();
    const [aliceSk, alicePk] = vc.generateEd25519Keypair();
    const [mallorySk, malloryPk] = vc.generateEd25519Keypair();
    const senderId = Buffer.from('alice');
    const content = Buffer.from('sealed content');
    const entry = JSON.parse(vc.keyLogCreateEntry(senderId, alicePk, 1000n, GENESIS_HASH, 1, aliceSk));
    const entriesJson = JSON.stringify([entry]);

    const sealed = vc.sealMessage(recipientPk, senderId, content, aliceSk);
    const [recoveredSender, recoveredContent] = vc.unsealMessage(sealed, recipientSk, entriesJson, alicePk);
    assert.deepStrictEqual(recoveredSender, senderId);
    assert.deepStrictEqual(recoveredContent, content);

    assert.throws(() => vc.unsealMessage(sealed, recipientSk, entriesJson, malloryPk));
    assert.throws(() => {
      const forgedEntry = JSON.parse(vc.keyLogCreateEntry(senderId, malloryPk, 1000n, GENESIS_HASH, 1, mallorySk));
      const forged = vc.sealMessage(recipientPk, senderId, Buffer.from('forged'), mallorySk);
      vc.unsealMessage(forged, recipientSk, JSON.stringify([forgedEntry]), alicePk);
    });
  });
});