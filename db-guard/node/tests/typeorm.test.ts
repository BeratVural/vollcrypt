import { test, describe } from 'node:test';
import assert from 'node:assert';
import { createTypeOrmSubscriber } from '../src/typeorm';

describe('TypeORM db-guard subscriber', () => {
  const key = Buffer.alloc(32, 9);

  test('registers TypeORM events and encrypts/decrypts models', () => {
    const Subscriber = createTypeOrmSubscriber({
      key,
      entities: {
        User: ['credit_card']
      }
    });

    const subscriberInstance = new Subscriber();

    assert.strictEqual(subscriberInstance.listenTo(), Object);

    const entity = {
      name: 'Bob',
      credit_card: '9999-8888'
    };

    const mockInsertEvent = {
      metadata: { name: 'User' },
      entity
    };

    subscriberInstance.beforeInsert(mockInsertEvent as any);

    assert.ok(entity.credit_card.startsWith('VOLLVALT:v1:'));
    assert.notStrictEqual(entity.credit_card, '9999-8888');

    const mockLoadEvent = {
      metadata: { name: 'User' }
    };

    const loadedEntity = {
      name: 'Bob',
      credit_card: entity.credit_card
    };

    subscriberInstance.afterLoad(loadedEntity, mockLoadEvent as any);

    assert.strictEqual(loadedEntity.credit_card, '9999-8888');
  });

  test('TypeORM dual-read fallback', () => {
    const Subscriber = createTypeOrmSubscriber({
      key,
      entities: {
        User: ['credit_card']
      }
    });
    const subscriberInstance = new Subscriber();

    const mockLoadEvent = {
      metadata: { name: 'User' }
    };

    const loadedEntity = {
      name: 'Legacy User',
      credit_card: 'Unencrypted Card'
    };

    subscriberInstance.afterLoad(loadedEntity, mockLoadEvent as any);

    assert.strictEqual(loadedEntity.credit_card, 'Unencrypted Card');
  });

  test('TypeORM blind indexing generation', () => {
    const rootSalt = Buffer.alloc(32, 10);
    const Subscriber = createTypeOrmSubscriber({
      key,
      entities: {
        User: ['credit_card']
      },
      blindIndexes: {
        rootSalt,
        entities: {
          User: ['credit_card']
        }
      }
    });

    const subscriberInstance = new Subscriber();
    const entity = {
      name: 'Bob',
      credit_card: '9999-8888',
      credit_card_bidx: undefined as any
    };

    const mockInsertEvent = {
      metadata: { name: 'User' },
      entity
    };

    subscriberInstance.beforeInsert(mockInsertEvent as any);

    // Verify it generated the blind index
    assert.ok(entity.credit_card_bidx);
    assert.ok(/^[0-9a-f]{64}$/.test(entity.credit_card_bidx));

    // Verify original field is encrypted
    assert.ok(entity.credit_card.startsWith('VOLLVALT:v1:'));
  });
});
