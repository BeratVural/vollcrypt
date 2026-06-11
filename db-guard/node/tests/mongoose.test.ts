import { test, describe } from 'node:test';
import assert from 'node:assert';
import { mongooseDbGuard } from '../src/mongoose';

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

describe('Mongoose db-guard plugin', () => {
  const key = Buffer.alloc(32, 5);

  test('registers pre-save, pre-update, and post-read hooks', () => {
    const schema = new MockSchema();
    mongooseDbGuard(schema as any, {
      key,
      fields: ['credit_card', 'ssn']
    });

    assert.ok(schema.preHooks['save']);
    assert.ok(schema.preHooks['updateOne']);
    assert.ok(schema.preHooks['findOneAndUpdate']);
    assert.ok(schema.postHooks['find']);
    assert.ok(schema.postHooks['findOne']);
  });

  test('pre-save hook encrypts modified target fields', () => {
    const schema = new MockSchema();
    mongooseDbGuard(schema as any, {
      key,
      fields: ['credit_card']
    });

    const doc = {
      credit_card: '1111-2222',
      isModified(field: string) {
        return field === 'credit_card';
      }
    };

    const saveHook = schema.preHooks['save'][0];
    let nextCalled = false;
    saveHook.call(doc, () => {
      nextCalled = true;
    });

    assert.ok(nextCalled);
    assert.ok(doc.credit_card.startsWith('VOLLVALT:v1:'));
    assert.notStrictEqual(doc.credit_card, '1111-2222');
  });

  test('pre-query update hook encrypts set updates', () => {
    const schema = new MockSchema();
    mongooseDbGuard(schema as any, {
      key,
      fields: ['credit_card']
    });

    const updatePayload = {
      $set: {
        credit_card: '3333-4444'
      }
    };

    const updateQueryMock = {
      getUpdate() {
        return updatePayload;
      }
    };

    const updateHook = schema.preHooks['updateOne'][0];
    let nextCalled = false;
    updateHook.call(updateQueryMock, () => {
      nextCalled = true;
    });

    assert.ok(nextCalled);
    assert.ok(updatePayload.$set.credit_card.startsWith('VOLLVALT:v1:'));
    assert.notStrictEqual(updatePayload.$set.credit_card, '3333-4444');
  });

  test('post-find hook decrypts documents', () => {
    const schema = new MockSchema();
    mongooseDbGuard(schema as any, {
      key,
      fields: ['credit_card']
    });

    // Encrypt some test data first using save hook
    const tempDoc = {
      credit_card: '2222-3333',
      isModified() { return true; }
    };
    schema.preHooks['save'][0].call(tempDoc, () => {});

    const docs = [
      { credit_card: tempDoc.credit_card },
      { credit_card: tempDoc.credit_card }
    ];

    const findHook = schema.postHooks['find'][0];
    let nextCalled = false;
    findHook.call({}, docs, () => {
      nextCalled = true;
    });

    assert.ok(nextCalled);
    assert.strictEqual(docs[0].credit_card, '2222-3333');
    assert.strictEqual(docs[1].credit_card, '2222-3333');
  });

  test('Mongoose blind indexing and query rewriting', () => {
    const schema = new MockSchema();
    const rootSalt = Buffer.alloc(32, 16);
    mongooseDbGuard(schema as any, {
      key,
      fields: ['credit_card'],
      blindIndexes: {
        rootSalt,
        fields: ['credit_card'],
        modelName: 'User'
      }
    });

    // 1. Pre-save hook computes blind index
    const doc = {
      credit_card: '1111-2222',
      credit_card_bidx: undefined as any,
      isModified(field: string) {
        return field === 'credit_card';
      }
    };

    const saveHook = schema.preHooks['save'][0];
    saveHook.call(doc, () => {});

    assert.ok(doc.credit_card_bidx);
    assert.ok(/^[0-9a-f]{64}$/.test(doc.credit_card_bidx));
    assert.ok(doc.credit_card.startsWith('VOLLVALT:v1:'));

    // 2. Query hooks rewrite query conditions to use _bidx
    const conditionsObj = { credit_card: '1111-2222' };
    const queryMock = {
      getQuery() {
        return conditionsObj;
      }
    };

    const findPreHook = schema.preHooks['find'][0];
    findPreHook.call(queryMock, () => {});

    const rewrittenQuery = queryMock.getQuery();
    assert.strictEqual(rewrittenQuery.credit_card, undefined);
    assert.ok((rewrittenQuery as any).credit_card_bidx);
    assert.ok(/^[0-9a-f]{64}$/.test((rewrittenQuery as any).credit_card_bidx));
  });

  test('pre-query update hook encrypts nested updates and dot-notation updates', () => {
    const schema = new MockSchema();
    mongooseDbGuard(schema as any, {
      key,
      fields: ['profile.credit_card']
    });

    const updatePayload = {
      $set: {
        profile: {
          credit_card: '4444-5555'
        },
        'profile.credit_card': '5555-6666'
      }
    };

    const updateQueryMock = {
      getUpdate() {
        return updatePayload;
      }
    };

    const updateHook = schema.preHooks['updateOne'][0];
    let nextCalled = false;
    updateHook.call(updateQueryMock, () => {
      nextCalled = true;
    });

    assert.ok(nextCalled);
    assert.ok(updatePayload.$set.profile.credit_card.startsWith('VOLLVALT:v1:'));
    assert.notStrictEqual(updatePayload.$set.profile.credit_card, '4444-5555');
    assert.ok(updatePayload.$set['profile.credit_card'].startsWith('VOLLVALT:v1:'));
    assert.notStrictEqual(updatePayload.$set['profile.credit_card'], '5555-6666');
  });
});
