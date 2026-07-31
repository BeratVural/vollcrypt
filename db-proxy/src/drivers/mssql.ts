import * as net from 'net';
import { validateQuery, ensureTenantScopedQuery, extractProjectionColumns, extractTableName } from '../waf.js';
import { decryptValue, decryptWithSecurity, dbGuardContextStore } from '@vollcrypt/db-guard';
import { getRbacConfig, resolveUserContext } from '../auth.js';

export function serializeMssqlError(message: string, code: number = 50000): Buffer {
  const msgBuf = Buffer.from(message, 'utf16le');
  const srvName = Buffer.from('VOLLCRYPT\0', 'utf16le');
  const procName = Buffer.from('PROXY\0', 'utf16le');

  const tokenLength = 11 + msgBuf.length + 1 + srvName.length + 1 + procName.length + 2;
  const token = Buffer.alloc(tokenLength);
  token[0] = 0xaa; // Error Token ID
  token.writeUInt16LE(tokenLength - 3, 1);
  token.writeInt32LE(code, 3); // Error Number
  token[7] = 1; // State
  token[8] = 16; // Severity
  token.writeUInt16LE(msgBuf.length / 2, 9); // Message Length in characters
  msgBuf.copy(token, 11);

  let cursor = 11 + msgBuf.length;
  token[cursor] = srvName.length / 2;
  cursor++;
  srvName.copy(token, cursor);
  cursor += srvName.length;

  token[cursor] = procName.length / 2;
  cursor++;
  procName.copy(token, cursor);
  cursor += procName.length;

  token.writeUInt16LE(1, cursor); // Line number

  // TDS Packet Header (8 bytes)
  const header = Buffer.alloc(8);
  header[0] = 0x04; // Tabular result packet type
  header[1] = 0x01; // EOM status
  header.writeUInt16BE(8 + token.length, 2);

  return Buffer.concat([header, token]);
}

/**
 * Intercepts and decrypts VOLLVALT: values inside TDS 7.4 response streams.
 */
export function decryptMssqlResponse(
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

  const header = packet.subarray(0, 8);
  const payload = packet.subarray(8);

  const decryptPayload = (buf: Buffer, cellIdx: number = 0): Buffer => {
    const payloadStr = buf.toString('utf16le');
    const matchIndex = payloadStr.indexOf('VOLLVALT:');
    if (matchIndex === -1) return buf;

    // Locate ciphertext boundaries
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
      const ptextBuf = Buffer.from(ptext, 'utf16le');
      const ctextBuf = Buffer.from(ctext, 'utf16le');

      const indexInBytes = buf.indexOf(ctextBuf);
      if (indexInBytes !== -1) {
        const before = buf.subarray(0, indexInBytes);
        const after = buf.subarray(indexInBytes + ctextBuf.length);

        // Adjust column length prefix (which resides immediately before the string in TDS)
        if (indexInBytes >= 2) {
          const oldLen = buf.readUInt16LE(indexInBytes - 2);
          if (oldLen === ctextBuf.length) {
            before.writeUInt16LE(ptextBuf.length, indexInBytes - 2);
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
  // Update TDS header message length field (bytes 2 and 3)
  if (newPacket.length >= 4) {
    newPacket.writeUInt16BE(newPacket.length, 2);
  }
  return newPacket;
}

/** Parses ibUserName/cchUserName from an MS-TDS LOGIN7 packet. */
export function parseLogin7Username(packet: Buffer): string | null {
  const tdsHeaderLength = 8;
  const login7UserOffsetField = tdsHeaderLength + 40;
  const login7UserLengthField = tdsHeaderLength + 42;
  if (packet.length < login7UserLengthField + 2 || packet[0] !== 0x10) return null;

  const packetLength = packet.readUInt16BE(2);
  if (packetLength < login7UserLengthField + 2 || packetLength > packet.length) return null;

  const login7Length = packet.readUInt32LE(tdsHeaderLength);
  if (login7Length < 44 || login7Length + tdsHeaderLength > packetLength) return null;

  const userOffset = packet.readUInt16LE(login7UserOffsetField);
  const userLength = packet.readUInt16LE(login7UserLengthField);
  if (userLength === 0) return null;
  if (userLength > 128) return null;

  const start = tdsHeaderLength + userOffset;
  const end = start + userLength * 2;
  if (start < login7UserLengthField + 2 || end > tdsHeaderLength + login7Length) return null;
  return packet.toString('utf16le', start, end);
}

export function handleMssqlConnection(
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
      processedData = decryptMssqlResponse(
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
      options.logSiem('MSSQL_DECRYPT_ERROR', 8, `MSSQL decryption error: ${err.message}`);
      const errPacket = serializeMssqlError(err.message);
      clientSocket.write(errPacket);
      return;
    }

    if (clientSocket.writable) {
      clientSocket.write(processedData);
    }
  });

  clientSocket.on('data', (data) => {
    if (data.length > 8) {
      const type = data[0];

      // LOGIN7 offsets are relative to the LOGIN7 body, after the 8-byte TDS packet header.
      if (type === 0x10) {
        const username = parseLogin7Username(data);
        if (username !== null) {
          const userContext = resolveUserContext(username, options.config);
          currentUserId = userContext.userId;
          currentRole = userContext.role;
          currentTenantId = userContext.tenantId;
        }
      }

      if (type === 0x01 || type === 0x03) { // SQL Batch or RPC
        const query = data.toString('utf16le', 8);
        try {
          if (!options.noWaf) {
            validateQuery(query, currentRole);
          }
          ensureTenantScopedQuery(query, currentTenantId);
        } catch (err: any) {
            options.logSiem('WAF_MSSQL_BLOCK', 9, `MSSQL WAF violation blocked: ${err.message}`);
            const errPacket = serializeMssqlError(err.message, 50000);
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

