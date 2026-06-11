import { test } from 'node:test';
import * as assert from 'node:assert';
import * as net from 'net';
import * as fs from 'fs';
import pg from 'pg';
import { encryptValue, resetFailClosedStatusForTesting } from '@vollcrypt/db-guard';
import { DbProxyServer, DbProxyOptions, serializeErrorResponse } from '../src/proxy.js';
import { serializeDataRow, serializeParameterStatus, parseParameterStatus } from '../src/pg-protocol.js';

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
            // StartupMessage -> AuthOk + ParameterStatus + ReadyForQuery
            const authOk = Buffer.from([0x52, 0, 0, 0, 8, 0, 0, 0, 0]);
            const serverVer = serializeParameterStatus('server_version', '12.4');
            const readyForQuery = Buffer.from([0x5a, 0, 0, 0, 5, 0x49]);
            socket.write(Buffer.concat([authOk, serverVer, readyForQuery]));
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

    if (query.includes('exfiltrate_data')) {
      const rowDesc = buildRowDescription(['id', 'name']);
      const r1 = serializeDataRow([Buffer.from('1', 'utf8'), Buffer.from('Row 1', 'utf8')]);
      const r2 = serializeDataRow([Buffer.from('2', 'utf8'), Buffer.from('Row 2', 'utf8')]);
      const r3 = serializeDataRow([Buffer.from('3', 'utf8'), Buffer.from('Row 3', 'utf8')]);
      const cmdComplete = Buffer.alloc(18);
      cmdComplete.write('C', 0, 'ascii');
      cmdComplete.writeInt32BE(17, 1);
      cmdComplete.write('SELECT 1\0', 5, 'ascii');
      const readyForQuery = Buffer.from([0x5a, 0, 0, 0, 5, 0x49]);
      return [rowDesc, r1, r2, r3, cmdComplete, readyForQuery];
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

    if (query.includes('XXXX-XXXX-XXXX-') && query.includes('AS credit_card')) {
      const rowDesc = buildRowDescription(['credit_card']);
      const dataRow = serializeDataRow([Buffer.from('XXXX-XXXX-XXXX-4444', 'utf8')]);
      const cmdComplete = Buffer.alloc(18);
      cmdComplete.write('C', 0, 'ascii');
      cmdComplete.writeInt32BE(17, 1);
      cmdComplete.write('SELECT 1\0', 5, 'ascii');
      const readyForQuery = Buffer.from([0x5a, 0, 0, 0, 5, 0x49]);
      return [rowDesc, dataRow, cmdComplete, readyForQuery];
    }

    if (query.includes("WHERE tenant_id = 'org_marketing'")) {
      const rowDesc = buildRowDescription(['invoice_id', 'tenant_id']);
      const dataRow = serializeDataRow([
        Buffer.from('inv_01', 'utf8'),
        Buffer.from('org_marketing', 'utf8'),
      ]);
      const cmdComplete = Buffer.alloc(18);
      cmdComplete.write('C', 0, 'ascii');
      cmdComplete.writeInt32BE(17, 1);
      cmdComplete.write('SELECT 1\0', 5, 'ascii');
      const readyForQuery = Buffer.from([0x5a, 0, 0, 0, 5, 0x49]);
      return [rowDesc, dataRow, cmdComplete, readyForQuery];
    }

    if (query.includes('avg_salary')) {
      const rowDesc = buildRowDescription(['avg_salary']);
      const dataRow = serializeDataRow([Buffer.from('5000.00', 'utf8')]);
      const cmdComplete = Buffer.alloc(18);
      cmdComplete.write('C', 0, 'ascii');
      cmdComplete.writeInt32BE(17, 1);
      cmdComplete.write('SELECT 1\0', 5, 'ascii');
      const readyForQuery = Buffer.from([0x5a, 0, 0, 0, 5, 0x49]);
      return [rowDesc, dataRow, cmdComplete, readyForQuery];
    }

    if (query.includes('high_egress_data')) {
      const rowDesc = buildRowDescription(['id']);
      const rows: Buffer[] = [];
      for (let i = 0; i < 105; i++) {
        rows.push(serializeDataRow([Buffer.from(String(i), 'utf8')]));
      }
      const cmdComplete = Buffer.alloc(18);
      cmdComplete.write('C', 0, 'ascii');
      cmdComplete.writeInt32BE(17, 1);
      cmdComplete.write('SELECT 1\0', 5, 'ascii');
      const readyForQuery = Buffer.from([0x5a, 0, 0, 0, 5, 0x49]);
      return [rowDesc, ...rows, cmdComplete, readyForQuery];
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
      tenant_user: { role: 'MARKETING', userId: 'usr-mkt-tenant', tenantId: 'org_marketing' },
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

  await t.test('13. Database version cloaking (ParameterStatus server_version masking)', async () => {
    const client = new pg.Client({
      host: '127.0.0.1',
      port: PROXY_PORT,
      user: 'postgres',
      database: 'testdb',
    });

    let versionReceived: string | undefined;
    const connectPromise = client.connect();
    
    if ((client as any).connection) {
      (client as any).connection.on('parameterStatus', (msg: any) => {
        if (msg.parameterName === 'server_version') {
          versionReceived = msg.parameterValue;
        }
      });
    }

    await connectPromise;
    assert.strictEqual(versionReceived, '16.0'); // Masked from 12.4
    await client.end();
  });

  await t.test('14. Query Fingerprinting Allowlisting (Learning and Blocking modes)', async () => {
    const allowlistFile = 'tests/allowlist-temp.json';
    if (fs.existsSync(allowlistFile)) {
      fs.unlinkSync(allowlistFile);
    }

    const learningOptions: DbProxyOptions = {
      port: PROXY_PORT + 20,
      dbHost: '127.0.0.1',
      dbPort: MOCK_DB_PORT,
      config: {
        users: { postgres: { role: 'OWNER', userId: 'usr-admin' } },
        firewall: {
          fingerprinting: {
            enabled: true,
            mode: 'learning',
            allowlistPath: allowlistFile,
          }
        }
      },
      resolvedKeys: { '1': KEY },
    };

    const learningProxy = new DbProxyServer(learningOptions);
    await learningProxy.start();

    // 1. Connect and run a query under learning mode
    const client1 = new pg.Client({
      host: '127.0.0.1',
      port: PROXY_PORT + 20,
      user: 'postgres',
      database: 'testdb',
    });
    await client1.connect();
    await client1.query('SELECT * FROM plain_data');
    await client1.end();
    await learningProxy.stop();

    // Verify allowlist file was written
    assert.ok(fs.existsSync(allowlistFile));
    const content = fs.readFileSync(allowlistFile, 'utf8');
    assert.match(content, /SELECT \* FROM plain_data/);

    // 2. Start blocking mode proxy
    const blockingOptions: DbProxyOptions = {
      port: PROXY_PORT + 21,
      dbHost: '127.0.0.1',
      dbPort: MOCK_DB_PORT,
      config: {
        users: { postgres: { role: 'OWNER', userId: 'usr-admin' } },
        firewall: {
          fingerprinting: {
            enabled: true,
            mode: 'blocking',
            allowlistPath: allowlistFile,
          }
        }
      },
      resolvedKeys: { '1': KEY },
    };

    const blockingProxy = new DbProxyServer(blockingOptions);
    await blockingProxy.start();

    const client2 = new pg.Client({
      host: '127.0.0.1',
      port: PROXY_PORT + 21,
      user: 'postgres',
      database: 'testdb',
    });
    await client2.connect();

    // Query matching fingerprint should succeed
    const res = await client2.query('SELECT * FROM plain_data');
    assert.ok(res);

    // Query not matching fingerprint should be blocked
    try {
      await client2.query('SELECT id, name FROM plain_data');
      assert.fail('Should have blocked unallowlisted query shape');
    } catch (err) {
      assert.match((err as Error).message, /Blocked by allowlist: query shape/);
    } finally {
      await client2.end();
      await blockingProxy.stop();
      if (fs.existsSync(allowlistFile)) {
        fs.unlinkSync(allowlistFile);
      }
    }
  });

  await t.test('15. Semantic SQLi threat scoring and tautology blocking', async () => {
    const client = new pg.Client({
      host: '127.0.0.1',
      port: PROXY_PORT,
      user: 'postgres',
      database: 'testdb',
    });

    await client.connect();

    // Stacked catalog access query (triggers stacked query + system catalog access = 9 score)
    try {
      await client.query("SELECT 1; SELECT * FROM pg_catalog.pg_tables");
      assert.fail('Should have blocked stacked system catalog query');
    } catch (err) {
      assert.match((err as Error).message, /Semantic SQLi threat detected: query score is 9/);
    }

    // timing delays query
    try {
      await client.query("SELECT pg_sleep(5)");
      assert.fail('Should have blocked sleep statement');
    } catch (err) {
      assert.match((err as Error).message, /Semantic SQLi threat detected: query score is 8/);
    }

    await client.end();
  });

  await t.test('16. Temporal role-based query restrictions', async () => {
    const tempProxyOptions: DbProxyOptions = {
      port: PROXY_PORT + 22,
      dbHost: '127.0.0.1',
      dbPort: MOCK_DB_PORT,
      config: {
        users: {
          analyst_marketing: { role: 'MARKETING', userId: 'usr-mkt-01' },
          postgres: { role: 'OWNER', userId: 'usr-admin' },
        },
        firewall: {
          temporalConstraints: {
            MARKETING: {
              startHour: 9,
              endHour: 18,
              allowedDays: [], // Empty allowed days blocks query every day
            }
          }
        }
      },
      resolvedKeys: { '1': KEY },
    };

    const tempProxy = new DbProxyServer(tempProxyOptions);
    await tempProxy.start();

    // Connecting with constrained role (MARKETING) should fail
    const client1 = new pg.Client({
      host: '127.0.0.1',
      port: PROXY_PORT + 22,
      user: 'analyst_marketing',
      database: 'testdb',
    });
    await client1.connect();
    try {
      await client1.query('SELECT * FROM users');
      assert.fail('Temporal constraint should have blocked the query');
    } catch (err) {
      assert.match((err as Error).message, /Temporal access restriction/);
    } finally {
      await client1.end();
    }

    // Connecting with OWNER role (no constraints) should succeed
    const client2 = new pg.Client({
      host: '127.0.0.1',
      port: PROXY_PORT + 22,
      user: 'postgres',
      database: 'testdb',
    });
    await client2.connect();
    const res = await client2.query('SELECT * FROM users');
    assert.ok(res);
    await client2.end();
    await tempProxy.stop();
  });

  await t.test('17. Connection-scoped rate limiting (QPS limits)', async () => {
    const rateProxyOptions: DbProxyOptions = {
      port: PROXY_PORT + 23,
      dbHost: '127.0.0.1',
      dbPort: MOCK_DB_PORT,
      config: {
        users: { postgres: { role: 'OWNER', userId: 'usr-admin' } },
        firewall: {
          rateLimits: {
            maxQueriesPerSecond: 2,
          }
        }
      },
      resolvedKeys: { '1': KEY },
    };

    const rateProxy = new DbProxyServer(rateProxyOptions);
    await rateProxy.start();

    const client = new pg.Client({
      host: '127.0.0.1',
      port: PROXY_PORT + 23,
      user: 'postgres',
      database: 'testdb',
    });
    await client.connect();

    // Send 3 queries in rapid succession
    await client.query('SELECT 1');
    await client.query('SELECT 2');
    try {
      await client.query('SELECT 3');
      assert.fail('Third query should have exceeded QPS limits');
    } catch (err) {
      assert.match((err as Error).message, /Connection query rate limit exceeded/);
    } finally {
      await client.end();
      await rateProxy.stop();
    }
  });

  await t.test('18. Data egress mass exfiltration row limit', async () => {
    const egressProxyOptions: DbProxyOptions = {
      port: PROXY_PORT + 24,
      dbHost: '127.0.0.1',
      dbPort: MOCK_DB_PORT,
      config: {
        users: { postgres: { role: 'OWNER', userId: 'usr-admin' } },
        firewall: {
          maxRowsPerQuery: 2,
        }
      },
      resolvedKeys: { '1': KEY },
    };

    const egressProxy = new DbProxyServer(egressProxyOptions);
    await egressProxy.start();

    const client = new pg.Client({
      host: '127.0.0.1',
      port: PROXY_PORT + 24,
      user: 'postgres',
      database: 'testdb',
    });
    await client.connect();

    try {
      // Query "exfiltrate_data" returns 3 rows, but maxRowsPerQuery is 2
      await client.query('SELECT * FROM exfiltrate_data');
      assert.fail('Should have aborted due to mass exfiltration row limits');
    } catch (err) {
      assert.match((err as Error).message, /Mass exfiltration limit exceeded/);
    } finally {
      await client.end();
      await egressProxy.stop();
    }
  });

  await t.test('19. SSO Token Authenticator & Password Interception', async () => {
    const SSO_DB_PORT = MOCK_DB_PORT + 50;
    const SSO_PROXY_PORT = PROXY_PORT + 50;
    const REAL_PASSWORD = 'super_secret_db_pass';

    // Start mock DB requesting password authentication
    const ssoDb = createMockAuthDbServer(SSO_DB_PORT, REAL_PASSWORD);

    const ssoProxyOptions: DbProxyOptions = {
      port: SSO_PROXY_PORT,
      dbHost: '127.0.0.1',
      dbPort: SSO_DB_PORT,
      dbPassword: REAL_PASSWORD,
      config: {
        users: {
          'ayse@company.com': { role: 'OWNER', userId: 'usr-sso-ayse' }
        }
      },
      resolvedKeys: { '1': KEY }
    };

    const ssoProxy = new DbProxyServer(ssoProxyOptions);
    await ssoProxy.start();

    // Register active SSO session passcode
    const tempPasscode = 'VPass_8b9a2c4d';
    ssoProxy.registerSsoSession('ayse@company.com', tempPasscode, ['OWNER']);

    // Attempt client connection using SSO passcode as password
    const client = new pg.Client({
      host: '127.0.0.1',
      port: SSO_PROXY_PORT,
      user: 'ayse@company.com',
      password: tempPasscode,
      database: 'testdb',
    });

    await client.connect();
    const res = await client.query('SELECT 1');
    assert.strictEqual(res.rows[0].val, 'SSO OK');
    await client.end();

    // Verify invalid passcode is rejected
    const badClient = new pg.Client({
      host: '127.0.0.1',
      port: SSO_PROXY_PORT,
      user: 'ayse@company.com',
      password: 'invalid_passcode',
      database: 'testdb',
    });

    try {
      await badClient.connect();
      assert.fail('Should have rejected invalid SSO passcode');
    } catch (err) {
      assert.match((err as Error).message, /Authentication failed/);
    }

    await ssoProxy.stop();
    ssoDb.close();
  });

  await t.test('20. Dynamic JIT Access Control Policy Checks', async () => {
    // analyst_marketing normally has credit card masked
    const client = new pg.Client({
      host: '127.0.0.1',
      port: PROXY_PORT,
      user: 'analyst_marketing',
      database: 'testdb',
    });

    await client.connect();

    // 1. Initial query: credit card should be masked
    const res1 = await client.query('SELECT * FROM users');
    assert.strictEqual(res1.rows[0]['users.credit_card'], '1111-XXXX-XXXX-4444');

    // 2. Register dynamic JIT grant elevating to OWNER role (active for 500ms)
    proxy.registerJitGrant('usr-mkt-01', 'OWNER', 500);

    // 3. Immediate query: credit card should be fully decrypted
    const res2 = await client.query('SELECT * FROM users');
    assert.strictEqual(res2.rows[0]['users.credit_card'], '1111-2222-3333-4444');

    // 4. Wait 600ms for JIT grant to expire
    await new Promise(resolve => setTimeout(resolve, 600));

    // 5. Query after expiry: should fallback to masked rules
    const res3 = await client.query('SELECT * FROM users');
    assert.strictEqual(res3.rows[0]['users.credit_card'], '1111-XXXX-XXXX-4444');

    await client.end();
  });

  await t.test('21. High-Performance Selective Scanning (Direct Stream Bypass)', async () => {
    const client = new pg.Client({
      host: '127.0.0.1',
      port: PROXY_PORT,
      user: 'postgres',
      database: 'testdb',
    });

    await client.connect();

    // Query plain_data which contains no sensitive columns.
    // It should trigger direct stream bypass and return Alice
    const res = await client.query('SELECT * FROM plain_data');
    assert.strictEqual(res.rows[0].name, 'Alice');

    await client.end();
  });

  await t.test('22. SQL Query Rewriting and Masking (Dynamic Masking Expression Injection)', async () => {
    const client = new pg.Client({
      host: '127.0.0.1',
      port: PROXY_PORT,
      user: 'analyst_marketing',
      database: 'testdb',
    });

    await client.connect();
    const res = await client.query('SELECT credit_card FROM users');
    assert.strictEqual(res.rows[0].credit_card, 'XXXX-XXXX-XXXX-4444');
    await client.end();
  });

  await t.test('23. Automatic Row-Level Security (RLS) Tenant Injection', async () => {
    const client = new pg.Client({
      host: '127.0.0.1',
      port: PROXY_PORT,
      user: 'tenant_user',
      database: 'testdb',
    });

    await client.connect();
    const res = await client.query('SELECT * FROM invoices');
    assert.strictEqual(res.rows[0].invoice_id, 'inv_01');
    assert.strictEqual(res.rows[0].tenant_id, 'org_marketing');
    await client.end();
  });

  await t.test('24. Differential Privacy (Laplace Noise Aggregate Injection)', async () => {
    const client = new pg.Client({
      host: '127.0.0.1',
      port: PROXY_PORT,
      user: 'postgres',
      database: 'testdb',
    });

    await client.connect();
    const res = await client.query('SELECT avg_salary FROM salary_stats');
    const val = parseFloat(res.rows[0].avg_salary);
    assert.ok(!isNaN(val));
    assert.notStrictEqual(val, 5000.00);
    assert.ok(Math.abs(val - 5000.00) < 10.0);
    await client.end();
  });

  await t.test('25. Behavioral Anomaly Throttling and SIEM Logging', async () => {
    const client = new pg.Client({
      host: '127.0.0.1',
      port: PROXY_PORT,
      user: 'postgres',
      database: 'testdb',
    });

    // Clean up or delete existing SIEM log file so we can isolate this test
    if (fs.existsSync('logs/siem.cef')) {
      fs.unlinkSync('logs/siem.cef');
    }

    await client.connect();
    const start = Date.now();
    const res = await client.query('SELECT * FROM high_egress_data');
    const duration = Date.now() - start;

    assert.strictEqual(res.rows.length, 105);
    // Since total egress rows is 105 (>100), we expect throttling (50ms delay for rows > 100)
    // 5 rows * 50ms = 250ms delay. So duration should be at least 200ms.
    assert.ok(duration >= 200, `Throttling did not introduce expected delay (duration: ${duration}ms)`);

    // Verify SIEM CEF log was created and contains expected information
    assert.ok(fs.existsSync('logs/siem.cef'));
    const cefContent = fs.readFileSync('logs/siem.cef', 'utf8');
    assert.match(cefContent, /ANOMALY_DETECTED/);
    assert.match(cefContent, /High row egress volume anomaly detected/);
    await client.end();
  });

  await t.test('26. Timing Attack Mitigation (Query and WAF Constant-Time Padding)', async () => {
    const timeProxyOptions: DbProxyOptions = {
      port: PROXY_PORT + 30,
      dbHost: '127.0.0.1',
      dbPort: MOCK_DB_PORT,
      config: {
        users: { postgres: { role: 'OWNER', userId: 'usr-admin' } }
      },
      resolvedKeys: { '1': KEY },
      minResponseTimeMs: 40,
    };

    const timeProxy = new DbProxyServer(timeProxyOptions);
    await timeProxy.start();

    const client = new pg.Client({
      host: '127.0.0.1',
      port: PROXY_PORT + 30,
      user: 'postgres',
      database: 'testdb',
    });

    await client.connect();

    // 1. Check query execution timing
    const t0 = Date.now();
    await client.query('SELECT 1');
    const d0 = Date.now() - t0;
    assert.ok(d0 >= 35, `Query round-trip was too fast (duration: ${d0}ms)`);

    // 2. Check WAF block timing
    const t1 = Date.now();
    try {
      await client.query("SELECT * FROM users WHERE username = 'admin' OR '1'='1'");
      assert.fail('Should have blocked SQLi');
    } catch (err) {
      const d1 = Date.now() - t1;
      assert.ok(d1 >= 35, `WAF block was too fast (duration: ${d1}ms)`);
      assert.match((err as Error).message, /Vollcrypt WAF Blocked/);
    }

    await client.end();
    await timeProxy.stop();
  });

  await t.test('27. Enclave Remote Attestation SQL Interception', async () => {
    const client = new pg.Client({
      host: '127.0.0.1',
      port: PROXY_PORT,
      user: 'postgres',
      database: 'testdb',
    });

    await client.connect();
    const res = await client.query('SELECT VOLLCRYPT_ATTESTATION_REPORT();');
    await client.end();

    assert.strictEqual(res.rows.length, 1);
    const reportStr = res.rows[0].attestation_report;
    assert.ok(reportStr);
    
    const report = JSON.parse(reportStr);
    assert.strictEqual(report.attestation_type, 'Intel SGX Quote');
    assert.ok(report.mrenclave);
    assert.ok(report.mrsigner);
    assert.ok(report.quote_signature);
  });

  await t.test('28. P2P Clustering and IP Ban Synchronization', async () => {
    const node1Options: DbProxyOptions = {
      port: PROXY_PORT + 40,
      dbHost: '127.0.0.1',
      dbPort: MOCK_DB_PORT,
      config: {
        users: { postgres: { role: 'OWNER', userId: 'usr-admin' } },
        firewall: {
          ipBanning: { enabled: true }
        }
      },
      resolvedKeys: { '1': KEY },
      gossipPort: 16001,
      peers: ['127.0.0.1:16001', '127.0.0.1:16002'],
      minResponseTimeMs: 0,
    };

    const node2Options: DbProxyOptions = {
      port: PROXY_PORT + 41,
      dbHost: '127.0.0.1',
      dbPort: MOCK_DB_PORT,
      config: {
        users: { postgres: { role: 'OWNER', userId: 'usr-admin' } },
        firewall: {
          ipBanning: { enabled: true }
        }
      },
      resolvedKeys: { '1': KEY },
      gossipPort: 16002,
      peers: ['127.0.0.1:16001', '127.0.0.1:16002'],
      minResponseTimeMs: 0,
    };

    const node1 = new DbProxyServer(node1Options);
    const node2 = new DbProxyServer(node2Options);

    await node1.start();
    await node2.start();

    // Give cluster a moment to sync P2P sockets
    await new Promise(resolve => setTimeout(resolve, 300));

    // 1. Connect client to Node 1 and trigger WAF violation (SQLi)
    const client1 = new pg.Client({
      host: '127.0.0.1',
      port: PROXY_PORT + 40,
      user: 'postgres',
      database: 'testdb',
    });

    await client1.connect();
    try {
      await client1.query("SELECT * FROM users WHERE username = 'admin' OR '1'='1'");
    } catch (err) {
      // Expected block
    }
    await client1.end();

    // Wait a brief moment for the cluster BAN_IP gossip message to propagate
    await new Promise(resolve => setTimeout(resolve, 300));

    // 2. Try to connect to Node 2. It should immediately drop the connection!
    const client2 = new pg.Client({
      host: '127.0.0.1',
      port: PROXY_PORT + 41,
      user: 'postgres',
      database: 'testdb',
      connectionTimeoutMillis: 1000,
    });

    try {
      await client2.connect();
      assert.fail('Node 2 should have immediately dropped the connection from the banned IP');
    } catch (err) {
      assert.ok(err);
    } finally {
      await node1.stop();
      await node2.stop();
    }
  });

  await t.test('29. CLI Hybrid Parser and Interactive Menu Configuration', async () => {
    const { handleHybridStartup } = await import('../src/index.js');

    const defaults = {
      minResponseTimeMs: 15,
      noAttestation: false,
      noDlp: false,
      noWaf: false,
      noIpBanning: false,
      fipsMode: false,
      jitApprovalRequired: false,
      anomalyEngine: false,
    };

    const originalTTY = process.stdin.isTTY;
    const originalWrite = process.stdout.write;
    const originalSetRawMode = process.stdin.setRawMode;

    try {
      // Silence stdout
      process.stdout.write = () => true;

      // Mock TTY as false (non-interactive fallback)
      Object.defineProperty(process.stdin, 'isTTY', {
        value: false,
        configurable: true
      });

      const resNonTty = await handleHybridStartup(defaults);
      assert.deepStrictEqual(resNonTty, defaults);

      // Mock TTY as true (interactive)
      Object.defineProperty(process.stdin, 'isTTY', {
        value: true,
        configurable: true
      });
      process.stdin.setRawMode = (() => process.stdin) as any;

      // Case 2: TTY true, emit ENTER immediately to start with defaults
      const pEnter = handleHybridStartup(defaults);
      process.stdin.emit('keypress', '', { name: 'enter' });
      const resEnter = await pEnter;
      assert.deepStrictEqual(resEnter, defaults);

      // Case 3: TTY true, press SPACE to enter menu, toggle Enclave Remote Attestation [OFF], then confirm with ENTER
      const pSpace = handleHybridStartup(defaults);
      process.stdin.emit('keypress', '', { name: 'space' });
      // In showInteractiveMenu:
      // index 0: Timing Attack Mitigation
      // index 1: Enclave Remote Attestation
      // Let's press down arrow to go to Enclave Remote Attestation, then space to toggle, then enter
      process.stdin.emit('keypress', '', { name: 'down' });
      process.stdin.emit('keypress', '', { name: 'space' });
      process.stdin.emit('keypress', '', { name: 'enter' });

      const resSpace = await pSpace;
      assert.strictEqual(resSpace.noAttestation, true);
      assert.strictEqual(resSpace.noDlp, false); // untouched

      // Case 4: Toggle FIPS mode (index 5)
      const pFips = handleHybridStartup(defaults);
      process.stdin.emit('keypress', '', { name: 'space' });
      // Go down 5 times to FIPS Compliance
      process.stdin.emit('keypress', '', { name: 'down' });
      process.stdin.emit('keypress', '', { name: 'down' });
      process.stdin.emit('keypress', '', { name: 'down' });
      process.stdin.emit('keypress', '', { name: 'down' });
      process.stdin.emit('keypress', '', { name: 'down' });
      process.stdin.emit('keypress', '', { name: 'space' });
      process.stdin.emit('keypress', '', { name: 'enter' });

      const resFips = await pFips;
      assert.strictEqual(resFips.fipsMode, true);
    } finally {
      process.stdout.write = originalWrite;
      process.stdin.setRawMode = originalSetRawMode;
      Object.defineProperty(process.stdin, 'isTTY', {
        value: originalTTY,
        configurable: true
      });
    }
  });

  await t.test('30. Multi-Database Protocol Proxy WAF Interception (MySQL and MongoDB)', async () => {
    // 1. MySQL WAF block test
    const mysqlOptions: DbProxyOptions = {
      port: PROXY_PORT + 50,
      dbHost: '127.0.0.1',
      dbPort: MOCK_DB_PORT,
      resolvedKeys: { '1': KEY },
      dbType: 'mysql',
      minResponseTimeMs: 0,
    };
    const mysqlProxy = new DbProxyServer(mysqlOptions);
    await mysqlProxy.start();

    // Connect mock MySQL socket client
    const mysqlClient = net.connect({ port: PROXY_PORT + 50 });
    await new Promise((resolve) => mysqlClient.on('connect', resolve));

    // Send mock COM_QUERY packet (packet len 42, sequence 0, command 0x03)
    const sqlQuery = "SELECT * FROM users WHERE username = 'admin' OR '1'='1'";
    const queryBuf = Buffer.from(sqlQuery, 'utf8');
    const mysqlReq = Buffer.alloc(5 + queryBuf.length);
    mysqlReq.writeUIntLE(queryBuf.length + 1, 0, 3); // Payload len
    mysqlReq[3] = 0; // Seq ID
    mysqlReq[4] = 0x03; // COM_QUERY
    queryBuf.copy(mysqlReq, 5);

    const mysqlResponsePromise = new Promise<Buffer>((resolve) => mysqlClient.once('data', resolve));
    mysqlClient.write(mysqlReq);

    const mysqlRes = await mysqlResponsePromise;
    mysqlClient.end();
    await mysqlProxy.stop();

    // Verify response is MySQL Error Packet (0xff)
    assert.strictEqual(mysqlRes[4], 0xff);
    assert.ok(mysqlRes.toString('utf8').includes('SQL Injection'));

    // 2. MongoDB WAF block test
    const mongoOptions: DbProxyOptions = {
      port: PROXY_PORT + 51,
      dbHost: '127.0.0.1',
      dbPort: MOCK_DB_PORT,
      resolvedKeys: { '1': KEY },
      dbType: 'mongodb',
      minResponseTimeMs: 0,
    };
    const mongoProxy = new DbProxyServer(mongoOptions);
    await mongoProxy.start();

    const mongoClient = net.connect({ port: PROXY_PORT + 51 });
    await new Promise((resolve) => mongoClient.on('connect', resolve));

    // Construct mock OP_MSG containing a dangerous dropDatabase command
    const mongoCommand = "dropDatabase";
    const mongoCmdBuf = Buffer.from(mongoCommand, 'utf8');
    const mongoReq = Buffer.alloc(16 + mongoCmdBuf.length);
    mongoReq.writeInt32LE(mongoReq.length, 0); // messageLength
    mongoReq.writeInt32LE(1, 4); // requestId
    mongoReq.writeInt32LE(0, 8); // responseTo
    mongoReq.writeInt32LE(2013, 12); // OP_MSG
    mongoCmdBuf.copy(mongoReq, 16);

    const mongoResponsePromise = new Promise<Buffer>((resolve) => mongoClient.once('data', resolve));
    mongoClient.write(mongoReq);

    const mongoRes = await mongoResponsePromise;
    mongoClient.end();
    await mongoProxy.stop();

    // Verify response has OP_MSG opcode (2013) and includes BSON error text
    const resOpCode = mongoRes.readInt32LE(12);
    assert.strictEqual(resOpCode, 2013);
    assert.ok(mongoRes.toString('utf8').includes('dropDatabase'));
  });

  await t.test('31. MPC Split-Key Decryption Key Reconstruction', async () => {
    // Create 3 shares of a 32-byte key
    const share1 = Buffer.alloc(32, 0x0f);
    const share2 = Buffer.alloc(32, 0xf0);
    const share3 = Buffer.alloc(32, 0xaa); // 0x0f ^ 0xf0 ^ 0xaa = 0x55

    const mpcOptions: DbProxyOptions = {
      port: PROXY_PORT + 52,
      dbHost: '127.0.0.1',
      dbPort: MOCK_DB_PORT,
      resolvedKeys: {},
      mpcShares: [share1, share2, share3],
      minResponseTimeMs: 0,
    };
    const mpcProxy = new DbProxyServer(mpcOptions);
    await mpcProxy.start();

    // Reconstructed key in resolvedKeys['1'] should be 32 bytes of 0x55
    const reconstructedKey = (mpcProxy as any).options.resolvedKeys['1'];
    assert.ok(reconstructedKey);
    assert.strictEqual(reconstructedKey[0], 0x55);
    await mpcProxy.stop();
  });

  await t.test('32. AI-Driven Semantic Anomaly Threat Scoring and Blocking', async () => {
    const anomalyOptions: DbProxyOptions = {
      port: PROXY_PORT + 53,
      dbHost: '127.0.0.1',
      dbPort: MOCK_DB_PORT,
      resolvedKeys: { '1': KEY },
      config: {
        users: { postgres: { role: 'LAWYER', userId: 'usr-lawyer' } },
        firewall: {
          anomalyEngine: { enabled: true }
        }
      },
      minResponseTimeMs: 0,
    };
    const anomalyProxy = new DbProxyServer(anomalyOptions);
    await anomalyProxy.start();

    const client = new pg.Client({
      host: '127.0.0.1',
      port: PROXY_PORT + 53,
      user: 'postgres',
      database: 'testdb',
    });

    await client.connect();

    // Normal query similar to baseline profile
    const normalRes = await client.query('SELECT * FROM users WHERE id = 1');
    assert.ok(normalRes);

    // Highly anomalous query: 'DROP TABLE log_audits CASCADE'
    try {
      await client.query('DROP TABLE log_audits CASCADE');
      assert.fail('Anomalous query should be blocked by AI anomaly engine');
    } catch (err: any) {
      assert.ok(err.message.includes('AI Anomaly'));
    } finally {
      await client.end();
      await anomalyProxy.stop();
    }
  });

  await t.test('33. JIT Asynchronous Access Approval Webhook Simulation', async () => {
    const jitOptions: DbProxyOptions = {
      port: PROXY_PORT + 54,
      dbHost: '127.0.0.1',
      dbPort: MOCK_DB_PORT,
      resolvedKeys: { '1': KEY },
      config: {
        users: { postgres: { role: 'LAWYER', userId: 'usr-lawyer' } },
        firewall: {
          jitApprovalRequired: true
        }
      },
      minResponseTimeMs: 0,
    };
    const jitProxy = new DbProxyServer(jitOptions);
    await jitProxy.start();

    const client = new pg.Client({
      host: '127.0.0.1',
      port: PROXY_PORT + 54,
      user: 'postgres',
      database: 'testdb',
    });

    await client.connect();

    // Query should trigger JIT webhook simulation, pause connection, get approved, and execute successfully
    const res = await client.query('SELECT 1');
    assert.ok(res);

    await client.end();
    await jitProxy.stop();
  });

  await t.test('34. FIPS 140-3 Compliance Boundary Mode Log Verification', async () => {
    const fipsOptions: DbProxyOptions = {
      port: PROXY_PORT + 55,
      dbHost: '127.0.0.1',
      dbPort: MOCK_DB_PORT,
      resolvedKeys: { '1': KEY },
      fipsMode: true,
      minResponseTimeMs: 0,
    };
    const fipsProxy = new DbProxyServer(fipsOptions);
    await fipsProxy.start();
    await fipsProxy.stop();

    // Check that CEF SIEM log has FIPS_INIT message
    const logContent = fs.readFileSync('logs/siem.cef', 'utf8');
    assert.ok(logContent.includes('FIPS_INIT'));
  });

  // Clean up servers
  await proxy.stop();
  mockDb.close();
});

// Helper for Mock Auth DB Server
function createMockAuthDbServer(port: number, passwordExpected: string): net.Server {
  const server = net.createServer((socket) => {
    let buffer = Buffer.alloc(0);
    let authenticated = false;

    socket.on('data', (data) => {
      buffer = Buffer.concat([buffer, data]);

      while (true) {
        if (buffer.length === 0) break;
        const firstByte = buffer[0];

        if (!authenticated) {
          if (firstByte === 0) {
            const len = buffer.readInt32BE(0);
            if (buffer.length < len) break;
            buffer = buffer.subarray(len);

            // Send CleartextPassword authentication request ('R' with code 3)
            const authReq = Buffer.from([0x52, 0, 0, 0, 8, 0, 0, 0, 3]);
            socket.write(authReq);
          } else if (firstByte === 112) { // 'p' PasswordMessage
            const len = buffer.readInt32BE(1);
            if (buffer.length < 1 + len) break;
            const msg = buffer.subarray(0, 1 + len);
            buffer = buffer.subarray(1 + len);

            const password = msg.toString('utf8', 5, msg.length - 1);
            if (password === passwordExpected) {
              authenticated = true;
              const authOk = Buffer.from([0x52, 0, 0, 0, 8, 0, 0, 0, 0]);
              const serverVer = serializeParameterStatus('server_version', '12.4');
              const readyForQuery = Buffer.from([0x5a, 0, 0, 0, 5, 0x49]);
              socket.write(Buffer.concat([authOk, serverVer, readyForQuery]));
            } else {
              const err = serializeErrorResponse('Authentication failed: wrong password');
              socket.write(err);
              socket.end();
            }
          } else {
            break;
          }
        } else {
          if (buffer.length < 5) break;
          const len = buffer.readInt32BE(1);
          if (buffer.length < 1 + len) break;
          const msg = buffer.subarray(0, 1 + len);
          buffer = buffer.subarray(1 + len);

          const type = String.fromCharCode(firstByte);
          if (type === 'Q') {
            const rowDesc = buildRowDescription(['id', 'val']);
            const dataRow = serializeDataRow([Buffer.from('1', 'utf8'), Buffer.from('SSO OK', 'utf8')]);
            const cmdComplete = Buffer.alloc(18);
            cmdComplete.write('C', 0, 'ascii');
            cmdComplete.writeInt32BE(17, 1);
            cmdComplete.write('SELECT 1\0', 5, 'ascii');
            const readyForQuery = Buffer.from([0x5a, 0, 0, 0, 5, 0x49]);
            socket.write(Buffer.concat([rowDesc, dataRow, cmdComplete, readyForQuery]));
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
