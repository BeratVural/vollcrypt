import { test, describe } from 'node:test';
import assert from 'node:assert';
import { createDrizzleGuard } from '../src/drizzle';

describe('Drizzle db-guard custom column adapter', () => {
  const key = Buffer.alloc(32, 7);

  test('creates custom column types with valid properties', () => {
    const guard = createDrizzleGuard({ key });
    
    assert.ok(guard.pgText);
    assert.ok(guard.mysqlText);
    assert.ok(guard.sqliteText);

    const pgCol = guard.pgText('credit_card');
    assert.strictEqual(pgCol.config?.name, 'credit_card');

    const toDriver = (pgCol as any).config?.customTypeParams?.toDriver;
    const fromDriver = (pgCol as any).config?.customTypeParams?.fromDriver;
    assert.ok(toDriver);
    assert.ok(fromDriver);

    const rawVal = 'sensitive info';
    const encrypted = toDriver(rawVal);
    assert.ok(encrypted.startsWith('VOLLVALT:v1:'));

    const decrypted = fromDriver(encrypted);
    assert.strictEqual(decrypted, rawVal);
  });

  test('dual-read fallback for unencrypted values in Drizzle', () => {
    const guard = createDrizzleGuard({ key });
    const pgCol = guard.pgText('address');
    const fromDriver = (pgCol as any).config?.customTypeParams?.fromDriver;

    const rawVal = 'Legacy Address';
    // Raw value should be returned as is (dual-read)
    const decrypted = fromDriver(rawVal);
    assert.strictEqual(decrypted, rawVal);
  });

  test('creates custom blind index column types and hashes values', () => {
    const rootSalt = Buffer.alloc(32, 9);
    const guard = createDrizzleGuard({
      key,
      blindIndexes: {
        rootSalt
      }
    });

    assert.ok(guard.pgBlindIndex);
    assert.ok(guard.mysqlBlindIndex);
    assert.ok(guard.sqliteBlindIndex);

    const pgCol = guard.pgBlindIndex('email_bidx', 'users.email');
    assert.strictEqual(pgCol.config?.name, 'email_bidx');

    const toDriver = (pgCol as any).config?.customTypeParams?.toDriver;
    const fromDriver = (pgCol as any).config?.customTypeParams?.fromDriver;
    assert.ok(toDriver);
    assert.ok(fromDriver);

    const rawEmail = 'test@example.com';
    const hashed1 = toDriver(rawEmail);
    assert.ok(/^[0-9a-f]{64}$/.test(hashed1));

    // Consistency check
    const hashed2 = toDriver(rawEmail);
    assert.strictEqual(hashed1, hashed2);

    // Uniqueness (different value)
    const hashedDiffVal = toDriver('different@example.com');
    assert.notStrictEqual(hashed1, hashedDiffVal);

    // Uniqueness (different column name)
    const ssnCol = guard.pgBlindIndex('ssn_bidx', 'users.ssn');
    const toDriverSsn = (ssnCol as any).config?.customTypeParams?.toDriver;
    const hashedDiffCol = toDriverSsn(rawEmail);
    assert.notStrictEqual(hashed1, hashedDiffCol);
  });
});
