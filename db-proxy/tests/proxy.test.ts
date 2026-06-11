import { test } from 'node:test';
import * as assert from 'node:assert';
import * as net from 'net';
import pg from 'pg';
import { encryptValue, resetFailClosedStatusForTesting } from '@vollcrypt/db-guard';
import { DbProxyServer, DbProxyOptions } from '../src/proxy.js';
import { serializeDataRow } from '../src/pg-protocol.js';

const KEY = Buffer.alloc(32, 0x01); // Ephemeral test key (32 bytes of 0x01)

/**
 * Helper to serialize RowDescription ('T') packet for mock DB.
 */
function buildRowDescription(columns: string[]): Buffer {
  let totalSize = 0;
  for (const col of columns) {
    totalSize += Buffer.byteLength(col, 'utf8') + 1 + 4 + 2 + 4 + 2 + 4 + 2;
  }
  const msgLen = 4 + 2 + totalSize;
  const buf = Buffer.alloc(1 + msgLen);
  buf.write('T', 0, 'ascii');
  buf.writeInt32BE(msgLen, 1);
  buf.writeInt16BE(columns.length, 5);

  let offset = 7;
  for (const col of columns) {
    const nameLen = buf.write(col, offset, 'utf8');
    offset += nameLen;
    buf.writeUInt8(0, offset); // null terminator
    offset += 1;
    buf.writeInt32BE(0, offset); // table OID
    offset += 4;
    buf.writeInt16BE(0, offset); // attr num
    offset += 2;
    buf.writeInt32BE(25, offset); // type OID (text)
    offset += 4;
    buf.writeInt16BE(-1, offset); // type size
    offset += 2;
    buf.writeInt32BE(-1, offset); // type modifier
    offset += 4;
    buf.writeInt16BE(0, offset); // format code (text)
    offset += 2;
  }
  return buf;
}

/**
 * Creates a mock PostgreSQL TCP Server for testing.
 */
function createMockDbServer(port: number, handler: (query: string) => Buffer[]): net.Server {
  const server = net.createServer((socket) => {
    let buffer = Buffer.alloc(0);

    socket.on('data', (data) => {
      buffer = Buffer.concat([buffer, data]);

      while (true) {
        if (buffer.length === 0) break;

        const firstByte = buffer[0];
        if (firstByte === 0) {
          // Startup / SSLRequest
          if (buffer.length < 4) break;
          const len = buffer.readInt32BE(0);
          if (buffer.length < len) break;

          const msg = buffer.subarray(0, len);
          buffer = buffer.subarray(len);

          if (len === 8 && msg.readInt32BE(4) === 80877103) {
            // SSLRequest
            socket.write(Buffer.from('N', 'ascii'));
          } else {
            // StartupMessage -> AuthOk + ReadyForQuery
            const authOk = Buffer.from([0x52, 0, 0, 0, 8, 0, 0, 0, 0]);
            const readyForQuery = Buffer.from([0x5a, 0, 0, 0, 5, 0x49]);
            socket.write(Buffer.concat([authOk, readyForQuery]));
          }
        } else {
          // Standard query message
          if (buffer.length < 5) break;
          const len = buffer.readInt32BE(1);
          if (buffer.length < 1 + len) break;

          const msg = buffer.subarray(0, 1 + len);
          buffer = buffer.subarray(1 + len);

          const type = String.fromCharCode(firstByte);
          if (type === 'Q') {
            const query = msg.subarray(5, msg.length - 1).toString('utf8');
            const responses = handler(query);
            socket.write(Buffer.concat(responses));
          } else if (type === 'P') {
            // ParseComplete
            socket.write(Buffer.from([0x31, 0, 0, 0, 4]));
          } else if (type === 'B') {
            // BindComplete
            socket.write(Buffer.from([0x32, 0, 0, 0, 4]));
          } else if (type === 'D') {
            // Describe -> RowDescription ('T')
            const responses = handler('fetch-users-prepared');
            socket.write(responses[0]);
          } else if (type === 'E') {
            // Execute -> DataRow ('D') + CommandComplete ('C')
            const responses = handler('fetch-users-prepared');
            socket.write(Buffer.concat([responses[1], responses[2]]));
          } else if (type === 'S') {
            // Sync -> ReadyForQuery ('Z')
            socket.write(Buffer.from([0x5a, 0, 0, 0, 5, 0x49]));
          } else if (type === 'X') {
            socket.end();
          }
        }
      }
    });
  });

  server.listen(port);
  return server;
}

test('Database Protocol Proxy E2E Interception Suite', async (t) => {
  const MOCK_DB_PORT = 15432;
  const PROXY_PORT = 15433;

  // Prepare test ciphertexts
  const encEmail = encryptValue('user@example.com', KEY, '1');
  const encTc = encryptValue('12345678901', KEY, '1');
  const encCc = encryptValue('1111-2222-3333-4444', KEY, '1');

  // Setup the mock DB server
  const mockDb = createMockDbServer(MOCK_DB_PORT, (query) => {
    if (query.includes('plain_data')) {
      const rowDesc = buildRowDescription(['id', 'name', 'unencrypted_cc', 'unencrypted_email', 'unencrypted_tc', 'unencrypted_iban']);
      const dataRow = serializeDataRow([
        Buffer.from('2', 'utf8'),
        Buffer.from('Alice', 'utf8'),
        Buffer.from('4321 5555 6666 7777', 'utf8'),
        Buffer.from('alice@company.com', 'utf8'),
        Buffer.from('98765432101', 'utf8'),
        Buffer.from('TR560006200000012345678901', 'utf8'),
      ]);
      const cmdComplete = Buffer.alloc(18);
      cmdComplete.write('C', 0, 'ascii');
      cmdComplete.writeInt32BE(17, 1);
      cmdComplete.write('SELECT 1\0', 5, 'ascii');
      const readyForQuery = Buffer.from([0x5a, 0, 0, 0, 5, 0x49]);
      return [rowDesc, dataRow, cmdComplete, readyForQuery];
    }

    if (query.includes('concat_data')) {
      const rowDesc = buildRowDescription(['id', 'unencrypted_cc', 'unencrypted_email']);
      const dataRow = serializeDataRow([
        Buffer.from('3', 'utf8'),
        Buffer.from('CC Number: 4321 5555 6666 7777', 'utf8'),
        Buffer.from('Email address: alice@company.com', 'utf8'),
      ]);
      const cmdComplete = Buffer.alloc(18);
      cmdComplete.write('C', 0, 'ascii');
      cmdComplete.writeInt32BE(17, 1);
      cmdComplete.write('SELECT 1\0', 5, 'ascii');
      const readyForQuery = Buffer.from([0x5a, 0, 0, 0, 5, 0x49]);
      return [rowDesc, dataRow, cmdComplete, readyForQuery];
    }

    if (query.includes('DROP TABLE')) {
      const cmdComplete = Buffer.alloc(20);
      cmdComplete.write('C', 0, 'ascii');
      cmdComplete.writeInt32BE(19, 1);
      cmdComplete.write('DROP TABLE\0', 5, 'ascii');
      const readyForQuery = Buffer.from([0x5a, 0, 0, 0, 5, 0x49]);
      return [cmdComplete, readyForQuery];
    }

    // Return row metadata: id, email, tc_no, credit_card
    const rowDesc = buildRowDescription(['id', 'users.email', 'users.tc_no', 'users.credit_card']);
    
    // Return row data containing ciphertexts
    const dataRow = serializeDataRow([
      Buffer.from('1', 'utf8'),
      Buffer.from(encEmail, 'utf8'),
      Buffer.from(encTc, 'utf8'),
      Buffer.from(encCc, 'utf8'),
    ]);

    // CommandComplete ('C') and ReadyForQuery ('Z')
    const cmdComplete = Buffer.alloc(18);
    cmdComplete.write('C', 0, 'ascii');
    cmdComplete.writeInt32BE(17, 1);
    cmdComplete.write('SELECT 1\0', 5, 'ascii');

    const readyForQuery = Buffer.from([0x5a, 0, 0, 0, 5, 0x49]);

    return [rowDesc, dataRow, cmdComplete, readyForQuery];
  });

  // Setup proxy server configuration
  const proxyConfig = {
    users: {
      postgres: { role: 'OWNER', userId: 'usr-admin' },
      analyst_hr: { role: 'HR_ADMIN', userId: 'usr-hr-01' },
      analyst_marketing: { role: 'MARKETING', userId: 'usr-mkt-01' },
      unauthorized_user: { role: 'GUEST', userId: 'usr-guest-01' },
    },
    cryptoRbac: {
      roles: {
        OWNER: {
          decrypt: ['users.email', 'users.tc_no', 'users.credit_card'],
        },
        HR_ADMIN: {
          decrypt: ['users.email', 'users.tc_no'],
          mask: {
            'users.credit_card': 'credit_card',
          },
        },
        MARKETING: {
          decrypt: ['users.email'],
          mask: {
            'users.tc_no': 'tc_no',
            'users.credit_card': 'credit_card',
          },
        },
      },
    },
  };

  const proxyOptions: DbProxyOptions = {
    port: PROXY_PORT,
    dbHost: '127.0.0.1',
    dbPort: MOCK_DB_PORT,
    config: proxyConfig,
    resolvedKeys: { '1': KEY },
  };

  const proxy = new DbProxyServer(proxyOptions);
  await proxy.start();

  await t.test('1. Authorized user (postgres/OWNER) should receive fully decrypted data', async () => {
    const client = new pg.Client({
      host: '127.0.0.1',
      port: PROXY_PORT,
      user: 'postgres',
      database: 'testdb',
    });

    await client.connect();
    const res = await client.query('SELECT * FROM users');
    await client.end();

    assert.strictEqual(res.rows.length, 1);
    assert.strictEqual(res.rows[0].id, '1');
    assert.strictEqual(res.rows[0]['users.email'], 'user@example.com');
    assert.strictEqual(res.rows[0]['users.tc_no'], '12345678901');
    assert.strictEqual(res.rows[0]['users.credit_card'], '1111-2222-3333-4444');
  });

  await t.test('2. HR user (analyst_hr/HR_ADMIN) should see email & tc_no decrypted, but credit_card masked', async () => {
    const client = new pg.Client({
      host: '127.0.0.1',
      port: PROXY_PORT,
      user: 'analyst_hr',
      database: 'testdb',
    });

    await client.connect();
    const res = await client.query('SELECT * FROM users');
    await client.end();

    assert.strictEqual(res.rows.length, 1);
    assert.strictEqual(res.rows[0]['users.email'], 'user@example.com');
    assert.strictEqual(res.rows[0]['users.tc_no'], '12345678901');
    assert.strictEqual(res.rows[0]['users.credit_card'], '1111-XXXX-XXXX-4444'); // Masked using 'credit_card' rule
  });

  await t.test('3. Marketing user (analyst_marketing/MARKETING) should see email decrypted, but tc_no & credit_card masked', async () => {
    const client = new pg.Client({
      host: '127.0.0.1',
      port: PROXY_PORT,
      user: 'analyst_marketing',
      database: 'testdb',
    });

    await client.connect();
    const res = await client.query('SELECT * FROM users');
    await client.end();

    assert.strictEqual(res.rows.length, 1);
    assert.strictEqual(res.rows[0]['users.email'], 'user@example.com');
    assert.strictEqual(res.rows[0]['users.tc_no'], '123XXXXXX01'); // Masked using 'tc_no' rule
    assert.strictEqual(res.rows[0]['users.credit_card'], '1111-XXXX-XXXX-4444');
  });

  await t.test('4. Guest user (unauthorized_user/GUEST) without masking rule should trigger PostgreSQL cryptographic access violation error', async () => {
    const client = new pg.Client({
      host: '127.0.0.1',
      port: PROXY_PORT,
      user: 'unauthorized_user',
      database: 'testdb',
    });

    await client.connect();
    try {
      await client.query('SELECT * FROM users');
      assert.fail('Query should have thrown access violation error');
    } catch (err) {
      assert.match(
        (err as Error).message,
        /Vollcrypt Cryptographic Access Violation: Vollcrypt Security: Role "GUEST" is not authorized to decrypt field "users.email"/
      );
    } finally {
      await client.end();
    }
  });

  await t.test('5. Rate limits triggering fail-closed should block subsequent decryptions', async () => {
    resetFailClosedStatusForTesting();

    // Create a client with a strict low rate limit of 1 decryption
    const strictProxyOptions: DbProxyOptions = {
      port: PROXY_PORT + 10,
      dbHost: '127.0.0.1',
      dbPort: MOCK_DB_PORT,
      config: {
        users: { postgres: { role: 'OWNER', userId: 'usr-admin' } },
        cryptoRbac: {
          roles: {
            OWNER: {
              decrypt: ['users.email', 'users.tc_no', 'users.credit_card'],
            },
          },
        },
        rateLimiter: {
          maxDecryptionsPerSecond: 1, // trigger rate limit immediately
          mode: 'fail_closed',
        }
      },
      resolvedKeys: { '1': KEY },
    };

    const strictProxy = new DbProxyServer(strictProxyOptions);
    await strictProxy.start();

    const client = new pg.Client({
      host: '127.0.0.1',
      port: PROXY_PORT + 10,
      user: 'postgres',
      database: 'testdb',
    });

    await client.connect();

    try {
      // Query will attempt 3 decryptions (email, tc_no, credit_card), which exceeds rate limit of 1
      await client.query('SELECT * FROM users');
      assert.fail('Query should have thrown rate limit exception');
    } catch (err) {
      assert.match(
        (err as Error).message,
        /Decryption rate limit exceeded. Fail-Closed mode triggered/
      );
    } finally {
      await client.end();
      await strictProxy.stop();
      resetFailClosedStatusForTesting();
    }
  });

  await t.test('6. WAF should block SQL injection attempts', async () => {
    const client = new pg.Client({
      host: '127.0.0.1',
      port: PROXY_PORT,
      user: 'postgres',
      database: 'testdb',
    });

    await client.connect();
    try {
      await client.query("SELECT * FROM users WHERE username = 'admin' OR '1'='1'");
      assert.fail('WAF should have blocked SQL Injection');
    } catch (err) {
      assert.match(
        (err as Error).message,
        /Vollcrypt WAF Blocked: SQL Injection signature detected/
      );
    } finally {
      await client.end();
    }
  });

  await t.test('7. WAF should block DDL commands for non-OWNER roles', async () => {
    const client = new pg.Client({
      host: '127.0.0.1',
      port: PROXY_PORT,
      user: 'analyst_hr',
      database: 'testdb',
    });

    await client.connect();
    try {
      await client.query('DROP TABLE logs');
      assert.fail('WAF should have blocked DROP TABLE for HR_ADMIN');
    } catch (err) {
      assert.match(
        (err as Error).message,
        /Vollcrypt WAF Blocked: Unauthorized command: role "HR_ADMIN" is not permitted to execute DDL queries/
      );
    } finally {
      await client.end();
    }
  });

  await t.test('8. WAF should allow DDL commands for OWNER role', async () => {
    const client = new pg.Client({
      host: '127.0.0.1',
      port: PROXY_PORT,
      user: 'postgres',
      database: 'testdb',
    });

    await client.connect();
    const res = await client.query('DROP TABLE logs');
    await client.end();

    assert.ok(res);
  });

  await t.test('9. DLP should dynamically scan and mask unencrypted PII strings in query responses', async () => {
    const client = new pg.Client({
      host: '127.0.0.1',
      port: PROXY_PORT,
      user: 'postgres',
      database: 'testdb',
    });

    await client.connect();
    const res = await client.query('SELECT * FROM plain_data');
    await client.end();

    assert.strictEqual(res.rows.length, 1);
    assert.strictEqual(res.rows[0].id, '2');
    assert.strictEqual(res.rows[0].name, 'Alice');
    
    // Verifying credit card auto-masking
    assert.strictEqual(res.rows[0].unencrypted_cc, '4321-XXXX-XXXX-7777');
    
    // Verifying email auto-masking
    assert.strictEqual(res.rows[0].unencrypted_email, 'ali***@company.com');
    
    // Verifying national ID auto-masking
    assert.strictEqual(res.rows[0].unencrypted_tc, '987XXXXXX01');
    
    // Verifying IBAN auto-masking
    assert.strictEqual(res.rows[0].unencrypted_iban, 'TR56XXXXXXXXXXXXXXXXXX8901');
  });

  await t.test('10. WAF should block DDL commands attempted via comment delimiters or newlines', async () => {
    const client = new pg.Client({
      host: '127.0.0.1',
      port: PROXY_PORT,
      user: 'analyst_hr',
      database: 'testdb',
    });

    await client.connect();

    // Test bypass attempt via comment delimiters (DROP/**/TABLE)
    try {
      await client.query('DROP/**/TABLE logs');
      assert.fail('WAF should have blocked comment-delimited DROP TABLE');
    } catch (err) {
      assert.match(
        (err as Error).message,
        /Vollcrypt WAF Blocked: Unauthorized command: role "HR_ADMIN" is not permitted to execute DDL queries/
      );
    }

    // Test bypass attempt via newline delimiter (DROP\nTABLE)
    try {
      await client.query('DROP\nTABLE logs');
      assert.fail('WAF should have blocked newline-delimited DROP TABLE');
    } catch (err) {
      assert.match(
        (err as Error).message,
        /Vollcrypt WAF Blocked: Unauthorized command: role "HR_ADMIN" is not permitted to execute DDL queries/
      );
    }

    await client.end();
  });

  await t.test('11. DLP should dynamically scan and mask concatenated PII fields to block extraction bypasses', async () => {
    const client = new pg.Client({
      host: '127.0.0.1',
      port: PROXY_PORT,
      user: 'postgres',
      database: 'testdb',
    });

    await client.connect();
    const res = await client.query('SELECT * FROM concat_data');
    await client.end();

    assert.strictEqual(res.rows.length, 1);
    assert.strictEqual(res.rows[0].id, '3');
    // Verify CC was matched and masked inside the concatenated string
    assert.strictEqual(res.rows[0].unencrypted_cc, 'CC Number: 4321-XXXX-XXXX-7777');
    // Verify Email was matched and masked inside the concatenated string
    assert.strictEqual(res.rows[0].unencrypted_email, 'Email address: ali***@company.com');
  });

  await t.test('12. Prepared statement column mapping state should remain in-sync across multiple executions (Extended Protocol)', async () => {
    const client = new pg.Client({
      host: '127.0.0.1',
      port: PROXY_PORT,
      user: 'analyst_marketing', // Unauthorized for credit card (should be masked)
      database: 'testdb',
    });

    await client.connect();

    // Prepare a statement S1 (this will trigger Parse + Describe, caching row description columns)
    const prepQuery = {
      name: 'fetch-users-prepared',
      text: 'SELECT id, users.email, users.tc_no, users.credit_card FROM users'
    };

    // First execution
    const res1 = await client.query(prepQuery);
    assert.strictEqual(res1.rows[0]['users.credit_card'], '1111-XXXX-XXXX-4444');

    // Second execution on same session
    // The database does NOT send a new RowDescription packet because the statement is already described.
    // The proxy must use its statement cache to maintain schema sync.
    const res2 = await client.query(prepQuery);
    assert.strictEqual(res2.rows[0]['users.credit_card'], '1111-XXXX-XXXX-4444');

    await client.end();
  });

  // Clean up servers
  await proxy.stop();
  mockDb.close();
});
