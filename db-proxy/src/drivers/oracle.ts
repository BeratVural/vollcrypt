import * as net from 'net';
import { validateQuery } from '../waf.js';
import { decryptValue } from '@vollcrypt/db-guard';

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

export function decryptOracleResponse(packet: Buffer, keys: Record<string, Buffer>): Buffer {
  if (packet.length < 8) return packet;
  const tnsType = packet[4];
  if (tnsType !== 0x06) return packet; // Only data packets contain rows

  const payloadStr = packet.toString('ascii');
  const matchIndex = payloadStr.indexOf('VOLLVALT:');
  if (matchIndex === -1) return packet;

  // Find ciphertext boundary
  const ctextPart = payloadStr.substring(matchIndex);
  const boundaryMatch = ctextPart.match(/[^A-Za-z0-9+/=:]/);
  const ctext = boundaryMatch ? ctextPart.substring(0, boundaryMatch.index) : ctextPart;

  try {
    const ptext = decryptValue(ctext, keys);
    const ptextBuf = Buffer.from(ptext, 'ascii');
    const ctextBuf = Buffer.from(ctext, 'ascii');

    const indexInBytes = packet.indexOf(ctextBuf);
    if (indexInBytes !== -1) {
      const before = packet.subarray(0, indexInBytes);
      const after = packet.subarray(indexInBytes + ctextBuf.length);

      // Try updating the length prefix preceding the string
      if (indexInBytes >= 1) {
        const singleByteLen = packet[indexInBytes - 1];
        if (singleByteLen === ctextBuf.length) {
          before[indexInBytes - 1] = ptextBuf.length;
        } else if (indexInBytes >= 2) {
          const doubleByteLen = packet.readUInt16BE(indexInBytes - 2);
          if (doubleByteLen === ctextBuf.length) {
            before.writeUInt16BE(ptextBuf.length, indexInBytes - 2);
          } else {
            const doubleByteLenLE = packet.readUInt16LE(indexInBytes - 2);
            if (doubleByteLenLE === ctextBuf.length) {
              before.writeUInt16LE(ptextBuf.length, indexInBytes - 2);
            }
          }
        }
      }

      const newPayload = Buffer.concat([before, ptextBuf, after]);
      
      // Update TNS header packet length (Big-Endian)
      if (newPayload.length >= 2) {
        newPayload.writeUInt16BE(newPayload.length, 0);
      }
      return newPayload;
    }
  } catch {
    // Fallback
  }
  return packet;
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
      processedData = decryptOracleResponse(data, options.resolvedKeys);
    } catch {
      // Fallback
    }

    if (clientSocket.writable) {
      clientSocket.write(processedData);
    }
  });

  clientSocket.on('data', (data) => {
    if (data.length > 8 && !options.noWaf) {
      const type = data[4];
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
              validateQuery(query, options.role);
            } catch (err: any) {
              options.logSiem('WAF_ORACLE_BLOCK', 9, `Oracle WAF violation blocked: ${err.message}`);
              const errPacket = serializeOracleError(err.message);
              clientSocket.write(errPacket);
              return;
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
