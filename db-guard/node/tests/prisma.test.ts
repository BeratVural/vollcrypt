import { test, describe } from 'node:test';
import assert from 'node:assert';
import { wrapKey } from '../src/security';
import { encryptValue, decryptValue, prismaDbGuard, resolveKeys, rewriteQueryWhere } from '../src/prisma';

describe('Prisma db-guard fields encrypt/decrypt', () => {
  const keyV1 = Buffer.alloc(32, 1);
  const keyV2 = Buffer.alloc(32, 2);
  const keys = { '1': keyV1, '2': keyV2 };

  test('encrypt and decrypt roundtrip with single key', () => {
    const raw = 'Secret SSN 12345';
    const encrypted = encryptValue(raw, keyV1, '1');
    assert.ok(encrypted.startsWith('VOLLVALT:v1:'));
    assert.notStrictEqual(encrypted, raw);

    const decrypted = decryptValue(encrypted, { '1': keyV1 });
    assert.strictEqual(decrypted, raw);
  });

  test('key rotation/version decryption', () => {
    const raw = 'Key rotation data';
    const encryptedV1 = encryptValue(raw, keyV1, '1');
    const encryptedV2 = encryptValue(raw, keyV2, '2');

    assert.strictEqual(decryptValue(encryptedV1, keys), raw);
    assert.strictEqual(decryptValue(encryptedV2, keys), raw);
  });

  test('JSON serialization for non-string types', () => {
    const payload = { number: 42, flag: true, nested: { value: 'test' } };
    const encrypted = encryptValue(payload, keyV1, '1');
    const decrypted = decryptValue(encrypted, { '1': keyV1 });

    assert.deepStrictEqual(decrypted, payload);
  });

  test('throw error on missing key version', () => {
    const encrypted = encryptValue('hello', keyV1, '1');
    assert.throws(() => {
      decryptValue(encrypted, { '2': keyV2 });
    }, /Decryption key version "1" not found/);
  });

  test('Prisma Extension interceptor mock execution', async () => {
    const key = Buffer.alloc(32, 3);
    const extension = prismaDbGuard({
      key,
      models: {
        User: ['credit_card']
      }
    });

    // Extract the mock client and query handlers
    // Prisma Extensions are functions that accept a client and call client.$extends(...)
    let extendedConfig: any = null;
    const mockClient = {
      $extends(config: any) {
        extendedConfig = config;
        return this;
      }
    };

    // Execute the extension function with our mock client
    (extension as any)(mockClient);

    assert.ok(extendedConfig);
    const queryConfig = extendedConfig.query;
    assert.ok(queryConfig);

    const createHook = queryConfig.$allModels?.create;
    assert.ok(createHook);

    const mockQuery = async (args: any) => {
      // Verifies that the input was encrypted before query execution
      assert.ok(args.data.credit_card.startsWith('VOLLVALT:v1:'));
      assert.notStrictEqual(args.data.credit_card, '1234-5678');
      
      // Return the encrypted field in result to simulate database storage
      return {
        id: 1,
        name: 'Alice',
        credit_card: args.data.credit_card
      };
    };

    const finalResult = await createHook({
      model: 'User',
      operation: 'create',
      args: { data: { name: 'Alice', credit_card: '1234-5678' } },
      query: mockQuery
    });

    // Verifies that the output was decrypted after query execution
    assert.strictEqual(finalResult.credit_card, '1234-5678');
  });

  test('resolveKeys resolves key from KmsProvider with envelope decryption', async () => {
    // We need to pass a valid 32-byte KEK and DEK to satisfy wrapKey/unwrapKey
    const testKek = Buffer.alloc(32, 12);
    const testDek = Buffer.alloc(32, 13);
    const mockWrappedDek = wrapKey(testKek, testDek);
    const wrappedKek = Buffer.from('wrapped-kek-value');

    const providerInstance = {
      async decrypt(ciphertext: Buffer): Promise<Buffer> {
        assert.deepStrictEqual(ciphertext, wrappedKek);
        return testKek;
      }
    };

    const keys = await resolveKeys({
      kms: {
        provider: providerInstance,
        wrappedKey: mockWrappedDek,
        wrappedKek: wrappedKek
      },
      models: {}
    });

    assert.ok(keys['1']);
    assert.deepStrictEqual(keys['1'], testDek);
  });

  test('Prisma query rewriting intercepts query and translates to _bidx', () => {
    const rootSalt = Buffer.alloc(32, 14);
    const fields = ['email'];
    const where = { email: 'test@example.com' };

    rewriteQueryWhere(where, fields, rootSalt, 'User');

    assert.strictEqual(where.email, undefined);
    assert.ok((where as any).email_bidx);
    assert.ok(/^[0-9a-f]{64}$/.test((where as any).email_bidx));
  });

  test('Prisma aggressive zeroization on encryptValue', () => {
    const rawVal = 'sensitive ssn data';
    const key = Buffer.alloc(32, 15);
    
    // Spy on Buffer.prototype.fill
    const originalFill = Buffer.prototype.fill;
    let fillCalled = false;
    let filledWithZero = false;

    Buffer.prototype.fill = function (value: any, ...args: any[]) {
      if (value === 0) {
        fillCalled = true;
        filledWithZero = true;
      }
      return originalFill.apply(this, [value, ...args]);
    };

    try {
      encryptValue(rawVal, key, '1');
      assert.ok(fillCalled);
      assert.ok(filledWithZero);
    } finally {
      Buffer.prototype.fill = originalFill;
    }
  });
});
