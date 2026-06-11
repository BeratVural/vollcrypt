import * as net from 'net';
import { validateQuery } from '../waf.js';

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

export function handleMysqlConnection(
  clientSocket: net.Socket,
  options: {
    dbHost: string;
    dbPort: number;
    noWaf?: boolean;
    role: string;
    clientIp: string;
    logSiem: (event: string, severity: number, message: string) => void;
  }
) {
  const backendSocket = net.connect({
    host: options.dbHost,
    port: options.dbPort,
  });

  clientSocket.pipe(backendSocket);

  backendSocket.on('data', (data) => {
    if (clientSocket.writable) {
      clientSocket.write(data);
    }
  });

  clientSocket.on('data', (data) => {
    if (data.length > 5) {
      const packetLen = data.readUIntLE(0, 3);
      const command = data[4];

      if (command === 0x03 && !options.noWaf) { // COM_QUERY
        const query = data.toString('utf8', 5, 4 + packetLen);
        try {
          validateQuery(query, options.role);
        } catch (err: any) {
          options.logSiem('WAF_MYSQL_BLOCK', 9, `MySQL WAF violation blocked: ${err.message}`);
          const errPacket = serializeMysqlError(err.message, 1142, '42000');
          clientSocket.write(errPacket);
        }
      }
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
