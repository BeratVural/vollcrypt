import * as net from 'net';
import { validateQuery } from '../waf.js';
import { decryptValue } from '@vollcrypt/db-guard';

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
export function decryptMssqlResponse(packet: Buffer, keys: Record<string, Buffer>): Buffer {
  const payloadStr = packet.toString('utf16le');
  const matchIndex = payloadStr.indexOf('VOLLVALT:');
  if (matchIndex === -1) return packet;

  // Locate ciphertext boundaries
  const ctextPart = payloadStr.substring(matchIndex);
  const nullOrSpaceIndex = ctextPart.match(/[\s\0]/);
  const ctext = nullOrSpaceIndex ? ctextPart.substring(0, nullOrSpaceIndex.index) : ctextPart;

  try {
    const ptext = decryptValue(ctext, keys);
    const ptextBuf = Buffer.from(ptext, 'utf16le');
    const ctextBuf = Buffer.from(ctext, 'utf16le');

    const indexInBytes = packet.indexOf(ctextBuf);
    if (indexInBytes !== -1) {
      const before = packet.subarray(0, indexInBytes);
      const after = packet.subarray(indexInBytes + ctextBuf.length);

      // Adjust column length prefix (which resides immediately before the string in TDS)
      if (indexInBytes >= 2) {
        const oldLen = packet.readUInt16LE(indexInBytes - 2);
        if (oldLen === ctextBuf.length) {
          before.writeUInt16LE(ptextBuf.length, indexInBytes - 2);
        }
      }

      const newPayload = Buffer.concat([before, ptextBuf, after]);
      
      // Update TDS header message length field
      if (newPayload.length >= 8) {
        newPayload.writeUInt16BE(newPayload.length, 2);
      }
      return newPayload;
    }
  } catch {
    // Fallback on failure
  }
  return packet;
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
    logSiem: (event: string, severity: number, message: string) => void;
  }
) {
  let connected = false;
  const queue: Buffer[] = [];

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
      processedData = decryptMssqlResponse(data, options.resolvedKeys);
    } catch {
      // Fallback
    }

    if (clientSocket.writable) {
      clientSocket.write(processedData);
    }
  });

  clientSocket.on('data', (data) => {
    if (data.length > 8 && !options.noWaf) {
      const type = data[0];
      if (type === 0x01 || type === 0x03) { // SQL Batch or RPC
        const query = data.toString('utf16le', 8);
        try {
          validateQuery(query, options.role);
        } catch (err: any) {
          options.logSiem('WAF_MSSQL_BLOCK', 9, `MSSQL WAF violation blocked: ${err.message}`);
          const errPacket = serializeMssqlError(err.message, 50000);
          clientSocket.write(errPacket);
          return;
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
