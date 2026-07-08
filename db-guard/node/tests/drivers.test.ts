import { test } from 'node:test';
import * as assert from 'node:assert';
import { wrapSqliteDatabase, wrapOracleConnection } from '../src/drivers.js';
import { encryptValue } from '../src/prisma.js';

const KEY = Buffer.alloc(32, 0x01); // 32-byte test key

test('wrapSqliteDatabase E2E parameters encryption and results decryption', async (t) => {
  const options = {
    key: KEY,
    entities: {
      users: ['email', 'ssn']
    }
  };

  // Mock Statement
  let lastParams: any[] = [];
  const mockStatement = {
    run(...params: any[]) {
      lastParams = params;
      return { changes: 1, lastInsertRowid: 1 };
    },
    get(...params: any[]) {
      lastParams = params;
      const encEmail = encryptValue('test@example.com', KEY, '1');
      return { id: 1, email: encEmail, role: 'user' };
    },
    all(...params: any[]) {
      lastParams = params;
      const encEmail = encryptValue('test@example.com', KEY, '1');
      return [
        { id: 1, email: encEmail, role: 'user' }
      ];
    }
  };

  // Mock Database
  const mockDb = {
    prepare(sql: string) {
      return mockStatement;
    }
  };

  const wrappedDb = wrapSqliteDatabase(mockDb, options);

  // 1. Test parameter encryption on write (INSERT)
  const insertStmt = wrappedDb.prepare('INSERT INTO users (email, ssn) VALUES (?, ?)');
  insertStmt.run('alice@example.com', '123-45-678');

  assert.ok(lastParams[0].startsWith('VOLLVALT:'));
  assert.ok(lastParams[1].startsWith('VOLLVALT:'));

  // 2. Test row decryption on read (SELECT)
  const selectStmt = wrappedDb.prepare('SELECT * FROM users WHERE id = ?');
  const row = selectStmt.get(1);

  assert.strictEqual(row.email, 'test@example.com');
  assert.strictEqual(row.role, 'user');

  // Test read multiple (all)
  const rows = selectStmt.all(1);
  assert.strictEqual(rows[0].email, 'test@example.com');
});

test('wrapOracleConnection bind parameter encryption and result decryption', async (t) => {
  const options = {
    key: KEY,
    entities: {
      employees: ['ssn']
    }
  };

  let lastBinds: any = null;
  const mockConnection = {
    async execute(sql: string, bindParams: any, execOptions: any) {
      lastBinds = bindParams;
      const encSsn = encryptValue('999-99-9999', KEY, '1');
      return {
        rows: [
          { ssn: encSsn, name: 'Bob' }
        ]
      };
    }
  };

  const wrappedConnection = wrapOracleConnection(mockConnection, options);

  // 1. Test execute with object bind parameters
  await wrappedConnection.execute(
    'INSERT INTO employees (ssn, name) VALUES (:ssn, :name)',
    { ssn: '999-99-9999', name: 'Bob' }
  );

  assert.ok(lastBinds.ssn.startsWith('VOLLVALT:'));
  assert.strictEqual(lastBinds.name, 'Bob');

  // 2. Test execute with array bind parameters
  await wrappedConnection.execute(
    'INSERT INTO employees (ssn, name) VALUES (?, ?)',
    ['999-99-9999', 'Bob']
  );

  assert.ok(lastBinds[0].startsWith('VOLLVALT:'));
  assert.strictEqual(lastBinds[1], 'Bob');

  // 3. Test execute query result decryption
  const res = await wrappedConnection.execute('SELECT ssn, name FROM employees WHERE id = 1');
  assert.strictEqual(res.rows[0].ssn, '999-99-9999');
  assert.strictEqual(res.rows[0].name, 'Bob');
});

test('wrapSqliteDatabase support for quoted SQL identifiers', async (t) => {
  const options = {
    key: KEY,
    entities: {
      users: ['email', 'ssn']
    }
  };

  let lastParams: any[] = [];
  const mockStatement = {
    run(...params: any[]) {
      lastParams = params;
      return { changes: 1 };
    }
  };

  const mockDb = {
    prepare(sql: string) {
      return mockStatement;
    }
  };

  const wrappedDb = wrapSqliteDatabase(mockDb, options);

  // 1. Quoted table and column identifiers in INSERT
  const insertStmt1 = wrappedDb.prepare('INSERT INTO "users" ("email", `ssn`) VALUES (?, ?)');
  insertStmt1.run('alice@example.com', '123-45-678');
  assert.ok(lastParams[0].startsWith('VOLLVALT:'));
  assert.ok(lastParams[1].startsWith('VOLLVALT:'));

  // 2. Bracketed identifiers in UPDATE
  const updateStmt = wrappedDb.prepare('UPDATE [users] SET [email] = ?, `ssn` = ? WHERE id = ?');
  updateStmt.run('bob@example.com', '987-65-432', 1);
  assert.ok(lastParams[0].startsWith('VOLLVALT:'));
  assert.ok(lastParams[1].startsWith('VOLLVALT:'));
});
