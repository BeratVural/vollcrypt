import * as net from 'net';
import { validateQuery, ensureTenantScopedQuery, extractProjectionColumns, extractTableName } from '../waf.js';
import { resolveUserContext, type ProxyConfig } from '../auth.js';
import { createInitialUserContext, decryptDriverValue, resolveProjectedField, type DriverConnectionOptions } from './common.js';

/** Serializes an Oracle TNS refusal packet. */
export function serializeOracleError(message: string): Buffer {
  const msgBuf = Buffer.from(message, 'ascii');
  const payload = Buffer.alloc(2 + msgBuf.length);
  payload[0] = 0x01; // refuse version
  payload[1] = 0x02; // user refuse code
  msgBuf.copy(payload, 2);

  const header = Buffer.alloc(8);
  header.writeUInt16BE(8 + payload.length, 0); // length
  header[4] = 0x04; // TNS Refuse Packet Type

  return Buffer.concat([header, payload]);
}

/** Decrypts encrypted values in an Oracle TNS data response. */
export function decryptOracleResponse(
  packet: Buffer,
  keys: Record<string, Buffer>,
  role: string = 'GUEST',
  userId: string = 'guest-user',
  tenantId?: string,
  config?: ProxyConfig,
  modelName: string = 'default',
  columns: string[] = []
): Buffer {
  if (packet.length < 8) return packet;
  const tnsType = packet[4];
  if (tnsType !== 0x06) return packet; // Only data packets contain rows

  const header = packet.subarray(0, 8);
  const payload = packet.subarray(8);

  const decryptPayload = (buf: Buffer, cellIdx: number = 0): Buffer => {
    const payloadStr = buf.toString('ascii');
    const matchIndex = payloadStr.indexOf('VOLLVALT:');
    if (matchIndex === -1) return buf;

    // Find ciphertext boundary
    const ctextPart = payloadStr.substring(matchIndex);
    const boundaryMatch = ctextPart.match(/[^A-Za-z0-9+/=:]/);
    const ctext = boundaryMatch ? ctextPart.substring(0, boundaryMatch.index) : ctextPart;

    try {
        const { field, model } = resolveProjectedField(columns[cellIdx], modelName, 'column');
        const ptext = decryptDriverValue(
          ctext,
          model,
          field,
          { keys, role, userId, tenantId, config }
        );
      const ptextBuf = Buffer.from(ptext, 'ascii');
      const ctextBuf = Buffer.from(ctext, 'ascii');

      const indexInBytes = buf.indexOf(ctextBuf);
      if (indexInBytes !== -1) {
        const before = buf.subarray(0, indexInBytes);
        const after = buf.subarray(indexInBytes + ctextBuf.length);

        // Try updating the length prefix preceding the string
        if (indexInBytes >= 1) {
          const singleByteLen = buf[indexInBytes - 1];
          if (singleByteLen === ctextBuf.length) {
            before[indexInBytes - 1] = ptextBuf.length;
          } else if (indexInBytes >= 2) {
            const doubleByteLen = buf.readUInt16BE(indexInBytes - 2);
            if (doubleByteLen === ctextBuf.length) {
              before.writeUInt16BE(ptextBuf.length, indexInBytes - 2);
            } else {
              const doubleByteLenLE = buf.readUInt16LE(indexInBytes - 2);
              if (doubleByteLenLE === ctextBuf.length) {
                before.writeUInt16LE(ptextBuf.length, indexInBytes - 2);
              }
            }
          }
        }

        const processedAfter = decryptPayload(after, cellIdx + 1);
        return Buffer.concat([before, ptextBuf, processedAfter]);
      }
    } catch (err: any) {
      throw err;
    }
    return buf;
  };

  const newPayload = decryptPayload(payload);
  if (newPayload === payload) return packet;

  const newPacket = Buffer.concat([header, newPayload]);
  // Update TNS header packet length (Big-Endian)
  if (newPacket.length >= 2) {
    newPacket.writeUInt16BE(newPacket.length, 0);
  }
  return newPacket;
}

/** Proxies one Oracle connection with identity, WAF, and decryption. */
export function handleOracleConnection(
  clientSocket: net.Socket,
  options: DriverConnectionOptions
) {
  let connected = false;
  const queue: Buffer[] = [];
  let currentUser = createInitialUserContext(options.role);
  let identityResolved = false;
  let currentTable = 'default';
  let currentColumns: string[] = [];

  const backendSocket = net.connect({
    host: options.dbHost,
    port: options.dbPort,
  }, () => {
    connected = true;
    for (const buf of queue) {
      if (backendSocket.writable) {
        backendSocket.write(buf);
      }
    }
    queue.length = 0;
  });

  backendSocket.on('data', (data) => {
    let processedData: Buffer<ArrayBufferLike> = data;
    try {
      processedData = decryptOracleResponse(
        data,
        options.resolvedKeys,
        currentUser.role,
        currentUser.userId,
        currentUser.tenantId,
        options.config,
        currentTable,
        currentColumns
      );
    } catch (err: any) {
      options.logSiem('ORACLE_DECRYPT_ERROR', 8, `Oracle decryption error: ${err.message}`);
      const errPacket = serializeOracleError(err.message);
      clientSocket.write(errPacket);
      return;
    }

    if (clientSocket.writable) {
      clientSocket.write(processedData);
    }
  });

  clientSocket.on('data', (data) => {
    if (data.length > 8) {
      const type = data[4];

      // Parse usernames only from the initial TNS Connect packet.
      const packetStr = type === 0x01 && !identityResolved ? data.toString('ascii') : '';
      const userMatch = packetStr.match(/\(\s*USER\s*=\s*([^)]+)\)/i) || packetStr.match(/AUTH_USERNAME\s*=\s*([A-Za-z0-9_]+)/i);
      if (type === 0x01 && !identityResolved && userMatch && userMatch[1]) {
        const username = userMatch[1].trim();
        currentUser = resolveUserContext(username, options.config);
        identityResolved = true;
      }

      if (type === 0x06) { // TNS Data Packet
        // Look for SQL query text in the packet payload
        const payloadStr = data.toString('ascii', 8);
        // Clean out binary garbage or non-printable chars from raw query search
        const queryClean = payloadStr.replace(/[^ -~]/g, ' ');
        
        // Match standard SQL keywords to identify query payload
        if (queryClean.match(/\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\b/i)) {
          // Extract query statement
          const sqlMatch = queryClean.match(/\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\b[\s\S]+/i);
          if (sqlMatch) {
            const query = sqlMatch[0].trim();
            try {
              if (!options.noWaf) {
                validateQuery(query, currentUser.role);
              }
              ensureTenantScopedQuery(query, currentUser.tenantId);
            } catch (err: any) {
              options.logSiem('WAF_ORACLE_BLOCK', 9, `Oracle WAF violation blocked: ${err.message}`);
              const errPacket = serializeOracleError(err.message);
              clientSocket.write(errPacket);
              return;
            }
            currentTable = 'default';
            currentColumns = [];
            try {
              currentTable = extractTableName(query);
              currentColumns = extractProjectionColumns(query);
            } catch (e) {
              currentTable = 'default';
              currentColumns = [];
              // ignore parsing error
            }
          }
        }
      }
    }

    if (connected) {
      if (backendSocket.writable) {
        backendSocket.write(data);
      }
    } else {
      queue.push(data);
    }
  });

  clientSocket.on('error', () => {
    backendSocket.destroy();
  });
  backendSocket.on('error', () => {
    clientSocket.destroy();
  });
  clientSocket.on('close', () => {
    backendSocket.destroy();
  });
  backendSocket.on('close', () => {
    clientSocket.destroy();
  });
}

