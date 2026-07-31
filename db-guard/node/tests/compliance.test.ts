import { test, describe } from 'node:test';
import assert from 'node:assert';
import { auditConfiguration, generateComplianceHtmlReport } from '../src/compliance';

describe('Compliance Scorecard Generator', () => {
  test('auditConfiguration correctly evaluates empty/basic config', () => {
    const basicConfig = {
      key: Buffer.alloc(32, 1)
    };

    const scorecard = auditConfiguration(basicConfig);

    assert.ok(scorecard.gdprScore < 100); // Should be less because of missing KMS, RBAC
    assert.ok(scorecard.kvkkScore < 100);
    assert.ok(scorecard.pciScore < 100);
    assert.ok(scorecard.failedChecks.length > 0);
    assert.ok(scorecard.passedChecks.length > 0); // RAM zeroization still passes
  });

  test('auditConfiguration reports acknowledged equality-index leakage honestly', () => {
    const fullConfig = {
      kms: {
        provider: {},
        wrappedKey: Buffer.alloc(32, 2),
        wrappedKek: Buffer.alloc(32, 3),
        activeKeyVersion: '1'
      },
      models: {
        User: ['email', 'credit_card']
      },
      blindIndexes: {
        rootSalt: Buffer.alloc(32, 4),
        allowFrequencyLeakage: true,
        models: {
          User: ['email']
        }
      },
      cryptoRbac: {
        roles: {
          ADMIN: {
            decrypt: ['User.email', 'User.credit_card']
          },
          SUPPORT: {
            decrypt: [],
            mask: {
              'User.credit_card': 'credit_card'
            }
          }
        }
      },
      rateLimiter: {
        maxDecryptionsPerSecond: 100,
        mode: 'fail_closed' as const,
        maxPageSize: 100,
        onPageSizeExceeded: 'error' as const
      },
      breakGlassThreshold: 2,
      breakGlassPublicKeys: ['hexkey1', 'hexkey2'],
      postQuantumEnabled: true,
      auditTrailPath: 'audit.log',
      auditIntegrityKey: Buffer.alloc(32, 5)
    };

    const scorecard = auditConfiguration(fullConfig);

    assert.strictEqual(scorecard.gdprScore, 100);
    assert.strictEqual(scorecard.kvkkScore, 75);
    assert.strictEqual(scorecard.pciScore, 100);
    assert.strictEqual(scorecard.failedChecks.length, 0);
    assert.ok(scorecard.passedChecks.some(c => c.includes('BREAK_GLASS_PROTOCOL')));
    assert.ok(scorecard.passedChecks.some(c => c.includes('POST_QUANTUM_KEM')));
  });

  test('auditConfiguration rejects unacknowledged deterministic blind indexes', () => {
    const scorecard = auditConfiguration({
      blindIndexes: {
        rootSalt: Buffer.alloc(32, 7),
        models: { User: ['email'] }
      }
    });

    assert.ok(scorecard.failedChecks.some(c => c.includes('BLIND_INDEX_RISK_NOT_ACKNOWLEDGED')));
  });
  test('generateComplianceHtmlReport produces a beautiful valid HTML document', () => {
    const basicConfig = {
      key: Buffer.alloc(32, 1)
    };

    const html = generateComplianceHtmlReport(basicConfig);

    assert.ok(typeof html === 'string');
    assert.ok(html.includes('<!DOCTYPE html>'));
    assert.ok(html.includes('VOLLCRYPT'));
    assert.ok(html.includes('GDPR Compliance'));
    assert.ok(html.includes('KVKK Compliance'));
    assert.ok(html.includes('PCI-DSS v4.0'));
    assert.ok(html.includes('Print Compliance PDF Report'));
  });
});


test('compliance report does not claim certification when controls fail', () => {
  const scorecard = auditConfiguration({ key: Buffer.alloc(32, 1) });
  assert.match(scorecard.summaryText, /not a GDPR, KVKK, PCI-DSS, FIPS, or CMVP certification/);

  const html = generateComplianceHtmlReport({ key: Buffer.alloc(32, 1) });
  assert.ok(html.includes('FAILED'));
  assert.ok(!html.includes('CMVP FIPS 140-3'));
  assert.ok(!html.includes('Official cryptographic compliance validation'));
});
