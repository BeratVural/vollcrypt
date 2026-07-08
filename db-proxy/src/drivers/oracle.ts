import * as net from 'net';
import { validateQuery, extractProjectionColumns, extractTableName } from '../waf.js';
import { decryptValue, decryptWithSecurity, dbGuardContextStore } from '@vollcrypt/db-guard';
import { getRbacConfig, resolveUserContext } from '../auth.js';

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

export function decryptOracleResponse(
  packet: Buffer,
  keys: Record<string, Buffer>,
  role: string = 'GUEST',
  userId: string = 'guest-user',
  tenantId?: string,
  config?: any,
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
      let fieldName = columns[cellIdx] || 'column';
      let model = modelName;
      if (fieldName.includes('.')) {
        const parts = fieldName.split('.');
        fieldName = parts[parts.length - 1];
        model = parts[0] === 'u' || parts[0] === 't' ? modelName : parts[0];
      }

      const ptext = dbGuardContextStore.run(
        {
          role,
          userId,
          tenantId,
          maxDecryptionsPerSecond: config?.rateLimiter?.maxDecryptionsPerSecond,
          rateLimiterMode: config?.rateLimiter?.mode,
        },
        () => decryptWithSecurity(
          ctext,
          (cipherText) => decryptValue(cipherText, keys),
          model,
          fieldName,
          undefined,
          {
            cryptoRbac: getRbacConfig(config),
            rateLimiter: config?.rateLimiter,
          }
        )
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

export function handleOracleConnection(
  clientSocket: net.Socket,
  options: {
    dbHost: string;
    dbPort: number;
    noWaf?: boolean;
    role: string;
    clientIp: string;
    resolvedKeys: Record<string, Buffer>;
    config?: any;
    logSiem: (event: string, severity: number, message: string) => void;
  }
) {
  let connected = false;
  const queue: Buffer[] = [];
  let currentRole = options.role;
  let currentUserId = options.role === 'OWNER' ? 'usr-admin' : 'guest-user';
  let currentTenantId: string | undefined;
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
    let processedData: any = data;
    try {
      processedData = decryptOracleResponse(
        data,
        options.resolvedKeys,
        currentRole,
        currentUserId,
        currentTenantId,
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

      // Parse Oracle TNS Connect / Data packets for usernames
      // We look for patterns like (USER=username) or AUTH_USERNAME=username
      const packetStr = data.toString('ascii');
      const userMatch = packetStr.match(/\(\s*USER\s*=\s*([^)]+)\)/i) || packetStr.match(/AUTH_USERNAME\s*=\s*([A-Za-z0-9_]+)/i);
      if (userMatch && userMatch[1]) {
        const username = userMatch[1].trim();
        const userContext = resolveUserContext(username, options.config);
        currentUserId = userContext.userId;
        currentRole = userContext.role;
        currentTenantId = userContext.tenantId;
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
            if (!options.noWaf) {
              try {
                validateQuery(query, currentRole);
              } catch (err: any) {
                options.logSiem('WAF_ORACLE_BLOCK', 9, `Oracle WAF violation blocked: ${err.message}`);
                const errPacket = serializeOracleError(err.message);
                clientSocket.write(errPacket);
                return;
              }
            }
            try {
              currentTable = extractTableName(query);
              currentColumns = extractProjectionColumns(query);
            } catch (e) {
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
  clientSocket.on('close', () => {
    clientSocket.destroy();
  });
}

