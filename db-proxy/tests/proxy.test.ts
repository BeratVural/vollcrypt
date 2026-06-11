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

  // Clean up servers
  await proxy.stop();
  mockDb.close();
});
