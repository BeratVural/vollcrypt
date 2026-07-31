import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import {
  DB_GUARD_CONTRACT_VERSION,
  DbGuardContractError,
  DbGuardContractV1,
  toDrizzleDbGuardOptions,
  toMongooseDbGuardOptions,
  toPrismaDbGuardOptions,
  toTypeOrmDbGuardOptions,
  validateDbGuardContract
} from '../src/contract';

function contract(): DbGuardContractV1 {
  return {
    contractVersion: DB_GUARD_CONTRACT_VERSION,
    keyring: {
      keys: { '1': Buffer.alloc(32, 1), '2': Buffer.alloc(32, 2) },
      activeVersion: '2'
    },
    resources: { User: ['email', 'card'] },
    blindIndexes: {
      rootSalt: Buffer.alloc(32, 3),
      allowFrequencyLeakage: true,
      resources: { User: ['email'] }
    },
    security: {
      allowUnrestrictedDecrypt: true,
      rateLimiter: { maxDecryptionsPerSecond: 20 }
    }
  };
}

describe('versioned DB Guard adapter contract', () => {
  test('maps one key/resource/security contract to all four Node ORM adapters', () => {
    const input = contract();
    const prisma = toPrismaDbGuardOptions(input);
    const mongoose = toMongooseDbGuardOptions(input, 'User');
    const drizzle = toDrizzleDbGuardOptions(input);
    const typeorm = toTypeOrmDbGuardOptions(input);

    assert.equal(prisma.activeKeyVersion, '2');
    assert.deepEqual(prisma.models, { User: ['email', 'card'] });
    assert.deepEqual(mongoose.fields, ['email', 'card']);
    assert.equal(mongoose.blindIndexes?.modelName, 'User');
    assert.equal(drizzle.activeKeyVersion, '2');
    assert.deepEqual(typeorm.entities, { User: ['email', 'card'] });
    assert.equal(prisma.allowUnrestrictedDecrypt, true);
    assert.equal(mongoose.rateLimiter?.maxDecryptionsPerSecond, 20);
  });

  test('rejects unsupported contract versions with a stable error code', () => {
    const input = contract() as any;
    input.contractVersion = 2;
    assert.throws(
      () => validateDbGuardContract(input),
      (error: unknown) => error instanceof DbGuardContractError
        && error.code === 'UNSUPPORTED_CONTRACT_VERSION'
    );
  });

  test('rejects missing, unsupported, and malformed key versions before adapter setup', () => {
    const missingActive = contract();
    missingActive.keyring.activeVersion = '3';
    assert.throws(
      () => validateDbGuardContract(missingActive),
      (error: unknown) => error instanceof DbGuardContractError
        && error.code === 'INVALID_KEYRING'
    );

    const malformed = contract();
    malformed.keyring.keys = { '1': Buffer.alloc(16) };
    assert.throws(() => validateDbGuardContract(malformed), /must be 32 bytes/);
  });

  test('rejects empty resource scopes and unknown Mongoose resources', () => {
    const empty = contract();
    empty.resources = {};
    assert.throws(
      () => validateDbGuardContract(empty),
      (error: unknown) => error instanceof DbGuardContractError
        && error.code === 'INVALID_RESOURCE_SCOPE'
    );

    assert.throws(
      () => toMongooseDbGuardOptions(contract(), 'Missing'),
      (error: unknown) => error instanceof DbGuardContractError
        && error.code === 'RESOURCE_NOT_FOUND'
    );
  });
});