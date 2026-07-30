import { test, describe } from 'node:test';
import assert from 'node:assert';
import {
  assertSafeIdentifier,
  buildPostgresBatchSelectSql,
  migrateMongoCollection,
  migratePostgresWithClient,
  DEFAULT_MIGRATION_OPTIONS,
} from '../src/cli';

const key = Buffer.alloc(32, 7);

describe('db-guard CLI migration safety', () => {
  test('Postgres batch SQL uses validated identifiers, keyset pagination, and ordering', () => {
    assert.strictEqual(
      buildPostgresBatchSelectSql('users', 'email', 'id', 'up', false),
      'SELECT "id", "email" FROM "users" WHERE "email" IS NOT NULL AND "email" NOT LIKE \'VOLLVALT:%\' ORDER BY "id" ASC LIMIT $1',
    );
    assert.strictEqual(
      buildPostgresBatchSelectSql('users', 'email', 'id', 'down', true),
      'SELECT "id", "email" FROM "users" WHERE "email" LIKE \'VOLLVALT:%\' AND "id" > $1 ORDER BY "id" ASC LIMIT $2',
    );
    assert.throws(() => assertSafeIdentifier('users;drop', 'table'), /simple SQL\/Mongo identifier/);
  });

  test('Postgres migration applies statement and lock timeouts and advances by keyset', async () => {
    const queries: Array<{ sql: string; params?: any[] }> = [];
    const client = {
      async query(sql: string, params?: any[]) {
        queries.push({ sql, params });
        if (sql.startsWith('SELECT COUNT')) return { rows: [{ count: '2' }] };
        if (sql.startsWith('SELECT "id"')) {
          if (sql.includes('"id" > $1')) return { rows: [] };
          return { rows: [{ id: 1, email: 'alice@example.com' }, { id: 2, email: 'bob@example.com' }] };
        }
        return { rows: [] };
      },
    };

    const processed = await migratePostgresWithClient(client, 'users', 'email', 'id', key, '1', 2, {
      direction: 'up',
      statementTimeoutMs: 1234,
      lockTimeoutMs: 55,
      mongoMaxTimeMs: 999,
    });

    assert.strictEqual(processed, 2);
    assert.ok(queries.some(q => q.sql === "SET statement_timeout = '1234ms'"));
    assert.ok(queries.some(q => q.sql === "SET lock_timeout = '55ms'"));
    assert.ok(queries.some(q => q.sql === "SET LOCAL statement_timeout = '1234ms'"));
    assert.ok(queries.some(q => q.sql === "SET LOCAL lock_timeout = '55ms'"));

    const selects = queries.filter(q => q.sql.startsWith('SELECT "id"'));
    assert.strictEqual(selects.length, 2);
    assert.match(selects[0].sql, /ORDER BY "id" ASC LIMIT \$1$/);
    assert.deepStrictEqual(selects[0].params, [2]);
    assert.match(selects[1].sql, /"id" > \$1 ORDER BY "id" ASC LIMIT \$2$/);
    assert.deepStrictEqual(selects[1].params, [2, 2]);
  });

  test('Postgres migration rolls back and rethrows failed batch updates', async () => {
    const queries: string[] = [];
    const client = {
      async query(sql: string) {
        queries.push(sql);
        if (sql.startsWith('SELECT COUNT')) return { rows: [{ count: '1' }] };
        if (sql.startsWith('SELECT "id"')) return { rows: [{ id: 1, email: 'alice@example.com' }] };
        if (sql.startsWith('UPDATE')) throw new Error('update failed');
        return { rows: [] };
      },
    };

    await assert.rejects(
      () => migratePostgresWithClient(client, 'users', 'email', 'id', key, '1', 1, DEFAULT_MIGRATION_OPTIONS),
      /update failed/,
    );
    assert.ok(queries.includes('ROLLBACK'));
  });

  test('Mongo migration uses maxTimeMS, sort, and _id keyset pagination', async () => {
    const countCalls: any[] = [];
    const findFilters: any[] = [];
    const sortCalls: any[] = [];
    const maxTimeCalls: number[] = [];
    const updateCalls: any[] = [];
    let findCount = 0;
    const collection = {
      async countDocuments(filter: any, options: any) {
        countCalls.push({ filter, options });
        return 2;
      },
      find(filter: any) {
        findFilters.push(filter);
        const docs = findCount++ === 0
          ? [{ _id: 1, email: 'alice@example.com' }, { _id: 2, email: 'bob@example.com' }]
          : [];
        return {
          sort(sort: any) { sortCalls.push(sort); return this; },
          limit(limit: number) { assert.strictEqual(limit, 2); return this; },
          maxTimeMS(ms: number) { maxTimeCalls.push(ms); return this; },
          async toArray() { return docs; },
        };
      },
      async updateOne(filter: any, update: any, options: any) {
        updateCalls.push({ filter, update, options });
      },
    };

    const processed = await migrateMongoCollection(collection, 'users', 'email', '_id', key, '1', 2, {
      direction: 'up',
      statementTimeoutMs: 1,
      lockTimeoutMs: 1,
      mongoMaxTimeMs: 777,
    });

    assert.strictEqual(processed, 2);
    assert.deepStrictEqual(countCalls[0].options, { maxTimeMS: 777 });
    assert.deepStrictEqual(sortCalls[0], { _id: 1 });
    assert.deepStrictEqual(maxTimeCalls, [777, 777]);
    assert.deepStrictEqual(findFilters[1], { $and: [findFilters[0], { _id: { $gt: 2 } }] });
    assert.strictEqual(updateCalls.length, 2);
    assert.deepStrictEqual(updateCalls[0].filter, { _id: 1 });
    assert.deepStrictEqual(updateCalls[0].options, { maxTimeMS: 777 });
  });
});