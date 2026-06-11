import { test, describe, beforeEach } from 'node:test';
import assert from 'node:assert';
import { dbGuardContextStore, configureAuditLogger, decryptWithSecurity, resetFailClosedStatusForTesting, resetAuditLoggerForTesting, AuditLogEntry } from '../src/index';

describe('Vollcrypt Central Security Modules (Phase 4)', () => {
  const key = Buffer.alloc(32, 17);

  beforeEach(() => {
    resetFailClosedStatusForTesting();
    resetAuditLoggerForTesting();
  });

  test('dbGuardContextStore manages request context roles and ids', () => {
    dbGuardContextStore.run({ role: 'ADMIN', userId: 'user_123' }, () => {
      const store = dbGuardContextStore.getStore();
      assert.ok(store);
      assert.strictEqual(store.role, 'ADMIN');
      assert.strictEqual(store.userId, 'user_123');
    });

    assert.strictEqual(dbGuardContextStore.getStore(), undefined);
  });

  test('Crypto-RBAC decryptions: authorized roles, unauthorized masking, and static mask bypass', () => {
    const rbacOptions = {
      cryptoRbac: {
        roles: {
          HR_ADMIN: {
            decrypt: ['User.ssn', 'User.email'],
          },
          SUPPORT: {
            decrypt: [],
            mask: {
              'User.ssn': 'tc_no',
              'User.email': 'email',
              'User.credit_card': 'credit_card',
              'User.salary': '$1000 (static)'
            }
          }
        }
      }
    };

    const mockDecryptRawFn = () => {
      return '12345678901';
    };

    // 1. Authorized role gets plain text
    dbGuardContextStore.run({ role: 'HR_ADMIN' }, () => {
      const decrypted = decryptWithSecurity(
        'VOLLVALT:v1:somebase64',
        mockDecryptRawFn,
        'User',
        'ssn',
        'rec_1',
        rbacOptions
      );
      assert.strictEqual(decrypted, '12345678901');
    });

    // 2. Unauthorized role gets dynamically masked value
    dbGuardContextStore.run({ role: 'SUPPORT' }, () => {
      const decrypted = decryptWithSecurity(
        'VOLLVALT:v1:somebase64',
        mockDecryptRawFn,
        'User',
        'ssn',
        'rec_1',
        rbacOptions
      );
      assert.strictEqual(decrypted, '123XXXXXX01');
    });

    // 3. Static mask returns immediately without executing decryptRawFn
    dbGuardContextStore.run({ role: 'SUPPORT' }, () => {
      let decryptRawFnCalled = false;
      const decrypted = decryptWithSecurity(
        'VOLLVALT:v1:somebase64',
        () => {
          decryptRawFnCalled = true;
          return 'raw';
        },
        'User',
        'salary',
        'rec_1',
        rbacOptions
      );
      assert.strictEqual(decrypted, '$1000 (static)');
      assert.strictEqual(decryptRawFnCalled, false);
    });

    // 4. Unauthorized role with no mask throws error
    dbGuardContextStore.run({ role: 'GUEST' }, () => {
      assert.throws(() => {
        decryptWithSecurity(
          'VOLLVALT:v1:somebase64',
          mockDecryptRawFn,
          'User',
          'ssn',
          'rec_1',
          rbacOptions
        );
      }, /Role "GUEST" is not authorized/);
    });
  });

  test('Decryption Rate Limiter triggers Fail-Closed and zeroizes keys in RAM', () => {
    const localKeys = { '1': Buffer.from('my-sensitive-key-data-32-bytes') };
    const { registerKeysForZeroization } = require('../src/security');
    registerKeysForZeroization(localKeys);

    const options = {
      rateLimiter: {
        maxDecryptionsPerSecond: 3
      }
    };

    const mockDecryptRawFn = () => 'plaintext';

    assert.strictEqual(decryptWithSecurity('VOLLVALT:v1:b64', mockDecryptRawFn, 'User', 'email', '1', options), 'plaintext');
    assert.strictEqual(decryptWithSecurity('VOLLVALT:v1:b64', mockDecryptRawFn, 'User', 'email', '1', options), 'plaintext');
    assert.strictEqual(decryptWithSecurity('VOLLVALT:v1:b64', mockDecryptRawFn, 'User', 'email', '1', options), 'plaintext');

    assert.throws(() => {
      decryptWithSecurity('VOLLVALT:v1:b64', mockDecryptRawFn, 'User', 'email', '1', options);
    }, /Decryption rate limit exceeded. Fail-Closed mode triggered/);

    assert.deepStrictEqual(localKeys['1'], Buffer.alloc(30, 0));
  });

  test('Cryptographic Audit Trail forms immutable SHA-256 chain', () => {
    const logs: AuditLogEntry[] = [];
    configureAuditLogger({
      onAuditLog(entry) {
        logs.push(entry);
      }
    });

    const mockDecryptRawFn = () => 'plaintext';

    decryptWithSecurity('VOLLVALT:v1:b64', mockDecryptRawFn, 'User', 'email', 'rec_1');
    decryptWithSecurity('VOLLVALT:v1:b64', mockDecryptRawFn, 'User', 'ssn', 'rec_2');

    assert.strictEqual(logs.length, 2);

    assert.strictEqual(logs[0].prevHash, '0'.repeat(64));
    assert.ok(logs[0].hash);

    assert.strictEqual(logs[1].prevHash, logs[0].hash);

    const entry = logs[0];
    const payload = `${entry.timestamp}|${entry.userId || ''}|${entry.role || ''}|${entry.model}|${entry.field}|${entry.recordId || ''}|${entry.action}|${entry.prevHash}`;
    const crypto = require('crypto');
    const expectedHash = crypto.createHash('sha256').update(payload).digest('hex');
    assert.strictEqual(entry.hash, expectedHash);
  });

  test('Rate Limiter custom modes: warn and disabled', () => {
    const localKeys = { '1': Buffer.from('my-sensitive-key-data-32-bytes') };
    const { registerKeysForZeroization } = require('../src/security');
    registerKeysForZeroization(localKeys);

    let consoleWarnCalled = false;
    const originalConsoleWarn = console.warn;
    console.warn = () => {
      consoleWarnCalled = true;
    };

    try {
      const options = {
        rateLimiter: {
          maxDecryptionsPerSecond: 2,
          mode: 'warn' as const
        }
      };

      const mockDecryptRawFn = () => 'plaintext';

      assert.strictEqual(decryptWithSecurity('VOLLVALT:v1:b64', mockDecryptRawFn, 'User', 'email', '1', options), 'plaintext');
      assert.strictEqual(decryptWithSecurity('VOLLVALT:v1:b64', mockDecryptRawFn, 'User', 'email', '1', options), 'plaintext');
      assert.strictEqual(decryptWithSecurity('VOLLVALT:v1:b64', mockDecryptRawFn, 'User', 'email', '1', options), 'plaintext');

      assert.ok(consoleWarnCalled);
      assert.notDeepStrictEqual(localKeys['1'], Buffer.alloc(30, 0));
    } finally {
      console.warn = originalConsoleWarn;
    }
  });

  test('Page Size Limit checks: warn, error, bypass', () => {
    const { checkPageSize } = require('../src/index');

    const statusOk = checkPageSize(10, { maxPageSize: 50 });
    assert.strictEqual(statusOk, 'ok');

    let consoleWarnCalled = false;
    const originalConsoleWarn = console.warn;
    console.warn = () => {
      consoleWarnCalled = true;
    };
    try {
      const statusWarn = checkPageSize(100, { maxPageSize: 50, onPageSizeExceeded: 'warn' });
      assert.strictEqual(statusWarn, 'warn');
      assert.ok(consoleWarnCalled);
    } finally {
      console.warn = originalConsoleWarn;
    }

    assert.throws(() => {
      checkPageSize(100, { maxPageSize: 50, onPageSizeExceeded: 'error' });
    }, /Query returned 100 records, which exceeds the max allowed page size/);

    const statusBypass = checkPageSize(100, { maxPageSize: 50, onPageSizeExceeded: 'bypass' });
    assert.strictEqual(statusBypass, 'bypass');
  });
});
