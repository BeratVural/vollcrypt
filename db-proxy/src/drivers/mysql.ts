import * as net from 'net';
import { validateQuery, extractProjectionColumns, extractTableName } from '../waf.js';
import { decryptValue, decryptWithSecurity, dbGuardContextStore } from '@vollcrypt/db-guard';
import { getRbacConfig, resolveUserContext } from '../auth.js';

export function serializeMysqlError(message: string, code: number = 1142, sqlState: string = '42000'): Buffer {
  const msgBuf = Buffer.from(message, 'utf8');
  const body = Buffer.alloc(9 + msgBuf.length);
  body[0] = 0xff; // Error Packet Indicator
  body.writeUInt16LE(code, 1);
  body[3] = 0x23; // '#' SQL State marker
  body.write(sqlState, 4, 5, 'ascii');
  msgBuf.copy(body, 9);

  const header = Buffer.alloc(4);
  header.writeUIntLE(body.length, 0, 3);
  header[3] = 1; // Sequence ID

  return Buffer.concat([header, body]);
}

export function parseLengthEncodedString(
  buf: Buffer,
  offset: number
): { value: string | null; nextOffset: number } {
  if (offset >= buf.length) {
    return { value: null, nextOffset: offset };
  }
  const first = buf[offset];
  if (first === 0xfb) {
    return { value: null, nextOffset: offset + 1 };
  }
  let len = 0;
  let nextOffset = offset + 1;
  if (first < 0xfb) {
    len = first;
  } else if (first === 0xfc) {
    len = buf.readUInt16LE(offset + 1);
    nextOffset = offset + 3;
  } else if (first === 0xfd) {
    len = buf.readUIntLE(offset + 1, 3);
    nextOffset = offset + 4;
  } else if (first === 0xfe) {
    len = buf.readUIntLE(offset + 1, 8);
    nextOffset = offset + 9;
  }

  if (nextOffset + len > buf.length) {
    return { value: null, nextOffset: buf.length };
  }
  const value = buf.toString('utf8', nextOffset, nextOffset + len);
  return { value, nextOffset: nextOffset + len };
}

export function serializeLengthEncodedString(value: string | null): Buffer {
  if (value === null) {
    return Buffer.from([0xfb]);
  }
  const strBuf = Buffer.from(value, 'utf8');
  const len = strBuf.length;
  let lenBuf: Buffer;
  if (len < 251) {
    lenBuf = Buffer.from([len]);
  } else if (len <= 0xffff) {
    lenBuf = Buffer.alloc(3);
    lenBuf[0] = 0xfc;
    lenBuf.writeUInt16LE(len, 1);
  } else if (len <= 0xffffff) {
    lenBuf = Buffer.alloc(4);
    lenBuf[0] = 0xfd;
    lenBuf.writeUIntLE(len, 1, 3);
  } else {
    lenBuf = Buffer.alloc(9);
    lenBuf[0] = 0xfe;
    lenBuf.writeUIntLE(len, 1, 8);
  }
  return Buffer.concat([lenBuf, strBuf]);
}

export function decryptMysqlRow(
  packet: Buffer,
  keys: Record<string, Buffer>,
  role: string = 'GUEST',
  userId: string = 'guest-user',
  tenantId?: string,
  config?: any,
  modelName: string = 'default',
  columns: string[] = []
): Buffer {
  if (packet.length < 5) return packet;
  const payloadLen = packet.readUIntLE(0, 3);
  const seqId = packet[3];

  const firstByte = packet[4];
  // Ignore OK, ERR, or EOF packets
  if (firstByte === 0x00 || firstByte === 0xfe || firstByte === 0xff) {
    return packet;
  }

  const cells: (string | null)[] = [];
  let cursor = 4;
  const end = 4 + payloadLen;

  while (cursor < end) {
    const { value, nextOffset } = parseLengthEncodedString(packet, cursor);
    cells.push(value);
    if (nextOffset === cursor) break;
    cursor = nextOffset;
  }

  let modified = false;
  let idx = 0;
  const decryptedCells = cells.map((cell) => {
    if (cell && cell.startsWith('VOLLVALT:')) {
      modified = true;
      try {
        let fieldName = columns[idx] || `col_${idx}`;
        let model = modelName;
        if (fieldName.includes('.')) {
          const parts = fieldName.split('.');
          fieldName = parts[parts.length - 1];
          model = parts[0] === 'u' || parts[0] === 't' ? modelName : parts[0];
        }

        const val = dbGuardContextStore.run(
          {
            role,
            userId,
            tenantId,
            maxDecryptionsPerSecond: config?.rateLimiter?.maxDecryptionsPerSecond,
            rateLimiterMode: config?.rateLimiter?.mode,
          },
          () => decryptWithSecurity(
            cell,
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
        idx++;
        return val;
      } catch (err: any) {
        throw err;
      }
    }
    idx++;
    return cell;
  });

  if (!modified) return packet;

  const cellBuffers = decryptedCells.map((cell) => serializeLengthEncodedString(cell));
  const newPayload = Buffer.concat(cellBuffers);

  const header = Buffer.alloc(4);
  header.writeUIntLE(newPayload.length, 0, 3);
  header[3] = seqId;

  return Buffer.concat([header, newPayload]);
}

export function handleMysqlConnection(
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
    // Attempt decryption on MySQL response rows
    let processedData: any = data;
    try {
      processedData = decryptMysqlRow(
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
      options.logSiem('MYSQL_DECRYPT_ERROR', 8, `MySQL decryption error: ${err.message}`);
      const errPacket = serializeMysqlError(err.message, 1142, '42000');
      clientSocket.write(errPacket);
      return;
    }

    if (clientSocket.writable) {
      clientSocket.write(processedData);
    }
  });

  clientSocket.on('data', (data) => {
    if (data.length > 5) {
      const packetLen = data.readUIntLE(0, 3);
      const seqId = data[3];
      const command = data[4];

      // HandshakeResponse41 parsing (usually seqId === 1 or 2 depending on SSL status)
      // Check for login response handshake packet
      if (seqId === 1 && packetLen > 32) {
        // HandshakeResponse41 format offset 4: client capabilities (4 bytes), max packet size (4 bytes), charset (1 byte), reserved (23 bytes)
        // Username starts at offset 36 (4 header + 32 handshake offset)
        // Null terminated string.
        let usernameEnd = 36;
        while (usernameEnd < data.length && data[usernameEnd] !== 0x00) {
          usernameEnd++;
        }
        if (usernameEnd > 36 && usernameEnd < data.length) {
          const username = data.toString('utf8', 36, usernameEnd);
          const userContext = resolveUserContext(username, options.config);
          currentUserId = userContext.userId;
          currentRole = userContext.role;
          currentTenantId = userContext.tenantId;
        }
      }

      if (command === 0x03 || command === 0x16) { // COM_QUERY or COM_STMT_PREPARE
        const query = data.toString('utf8', 5, 4 + packetLen);
        if (!options.noWaf) {
          try {
            validateQuery(query, currentRole);
          } catch (err: any) {
            options.logSiem('WAF_MYSQL_BLOCK', 9, `MySQL WAF violation blocked: ${err.message}`);
            const errPacket = serializeMysqlError(err.message, 1142, '42000');
            clientSocket.write(errPacket);
            return; // Halt and prevent forwarding to the backend DB
          }
        }
        try {
          currentTable = extractTableName(query);
          currentColumns = extractProjectionColumns(query);
        } catch (e) {
          // ignore parsing error, fallback to default
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

