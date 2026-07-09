import { test, describe, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert';
import { generateEd25519Keypair, signMessage } from '../src/security';
import { mongooseDbGuard } from '../src/mongoose';
import {
  dbGuardContextStore,
  getCachedKey,
  setCachedKey,
  resetSecureKeyCacheForTesting,
  configureBreakGlass,
  activateBreakGlass,
  deactivateBreakGlass,
  isBreakGlassActive,
  getBreakGlassKey,
  parseCiphertext,
  encryptValue,
  decryptValue
} from '../src/index';

class MockSchema {
  preHooks: Record<string, Function[]> = {};
  postHooks: Record<string, Function[]> = {};

  pre(hookName: string, fn: Function) {
    if (!this.preHooks[hookName]) this.preHooks[hookName] = [];
    this.preHooks[hookName].push(fn);
  }

  post(hookName: string, fn: Function) {
    if (!this.postHooks[hookName]) this.postHooks[hookName] = [];
    this.postHooks[hookName].push(fn);
  }
}

describe('Vollcrypt Phase 5 Enterprise Security Modules', () => {
  beforeEach(() => {
    resetSecureKeyCacheForTesting();
  });

  afterEach(() => {
    resetSecureKeyCacheForTesting();
  });

  test('Secure TTL Cache wraps DEK and evicts after expiry', async () => {
    const key = Buffer.alloc(32, 42);
    setCachedKey('tenant-1', '1', key, 50); // 50ms TTL

    // Immediately check cache: should exist and match plaintext key
    const cached = getCachedKey('tenant-1', '1');
    assert.ok(cached);
    assert.deepStrictEqual(cached, key);

    // Wait for eviction
    await new Promise((resolve) => setTimeout(resolve, 60));

    // Check again: should be undefined
    const expired = getCachedKey('tenant-1', '1');
    assert.strictEqual(expired, undefined);
  });

  test('Schema Evolution & Crypto-Agility: parses old and new formats', () => {
    const key = Buffer.alloc(32, 99);
    const keys = { '1': key };

    const encrypted = encryptValue('hello-world', key, '1');
    assert.ok(encrypted.startsWith('VOLLVALT:v1:'));

    const decrypted = decryptValue(encrypted, keys);
    assert.strictEqual(decrypted, 'hello-world');

    // Test that dynamically mapping version 2 to algorithm 1 resolves and decrypts correctly
    const { VERSION_ALGORITHMS } = require('../src/index');
    VERSION_ALGORITHMS['2'] = '1';
    
    const rawCipherB64 = encrypted.split(':').pop();
    const legacyEncrypted = `VOLLVALT:v2:${rawCipherB64}`;
    
    const decryptedLegacy = decryptValue(legacyEncrypted, { '2': key });
    assert.strictEqual(decryptedLegacy, 'hello-world');
  });

  test('Break-Glass Protocol: M-of-N threshold signatures bypass KMS', () => {
    // Generate 3 keypairs
    const kp1 = generateEd25519Keypair(); // CEO
    const kp2 = generateEd25519Keypair(); // CTO
    const kp3 = generateEd25519Keypair(); // Legal

    const pk1 = kp1[1].toString('hex');
    const pk2 = kp2[1].toString('hex');
    const pk3 = kp3[1].toString('hex');

    // Configure break glass: threshold 2, public keys [pk1, pk2, pk3]
    configureBreakGlass({
      threshold: 2,
      publicKeys: [pk1, pk2, pk3]
    });

    assert.strictEqual(isBreakGlassActive(), false);

    const timestamp = Date.now();
    const message = `break-glass-activate|${timestamp}`;
    const msgBuf = Buffer.from(message, 'utf8');

    // Sign message with CEO and CTO secret keys
    const sig1 = signMessage(kp1[0], msgBuf).toString('hex');
    const sig2 = signMessage(kp2[0], msgBuf).toString('hex');

    const emergencyKey = Buffer.alloc(32, 7);

    // Activate Break-Glass
    activateBreakGlass(
      [
        { publicKey: pk1, signature: sig1, timestamp },
        { publicKey: pk2, signature: sig2, timestamp }
      ],
      emergencyKey
    );

    assert.strictEqual(isBreakGlassActive(), true);
    assert.deepStrictEqual(getBreakGlassKey(), emergencyKey);

    // Deactivate Break-Glass
    deactivateBreakGlass();
    assert.strictEqual(isBreakGlassActive(), false);
    assert.strictEqual(getBreakGlassKey(), undefined);
  });

  test('Multi-Tenant KMS Routing in Mongoose', async () => {
    const keyA = Buffer.alloc(32, 10);
    const keyB = Buffer.alloc(32, 20);

    const schema = new MockSchema();
    mongooseDbGuard(schema as any, {
      key: Buffer.alloc(32, 0), // dummy default key
      fields: ['secret'],
      multiTenant: {
        tenants: {
          'tenant-a': { key: keyA },
          'tenant-b': { key: keyB }
        }
      }
    });

    const docA = {
      secret: 'data-for-a',
      isModified() { return true; }
    };

    const docB = {
      secret: 'data-for-b',
      isModified() { return true; }
    };

    const saveHook = schema.preHooks['save'][0];

    // Encrypt for Tenant A
    await dbGuardContextStore.run({ tenantId: 'tenant-a' }, async () => {
      await saveHook.call(docA);
    });

    // Encrypt for Tenant B
    await dbGuardContextStore.run({ tenantId: 'tenant-b' }, async () => {
      await saveHook.call(docB);
    });

    // Verify ciphertexts are different and wrapped properly
    assert.ok(docA.secret.startsWith('VOLLVALT:v1:'));
    assert.ok(docB.secret.startsWith('VOLLVALT:v1:'));
    assert.notStrictEqual(docA.secret, docB.secret);

    // Decrypt for Tenant A: should recover Tenant A data
    const docsA = [{ secret: docA.secret }];
    const findHook = schema.postHooks['find'][0];
    await dbGuardContextStore.run({ tenantId: 'tenant-a' }, async () => {
      await findHook.call({}, docsA, () => {});
    });
    assert.strictEqual(docsA[0].secret, 'data-for-a');

    // Decrypt for Tenant B: should recover Tenant B data
    const docsB = [{ secret: docB.secret }];
    await dbGuardContextStore.run({ tenantId: 'tenant-b' }, async () => {
      await findHook.call({}, docsB, () => {});
    });
    assert.strictEqual(docsB[0].secret, 'data-for-b');

    // 4. Verify that running without tenant context throws an error
    await assert.rejects(async () => {
      await saveHook.call(docA);
    }, /tenantId must be provided in multi-tenant mode/);
  });
});
