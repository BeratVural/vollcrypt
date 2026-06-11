import * as net from 'net';
import { validateQuery } from '../waf.js';

export function serializeMongoError(message: string, code: number = 13): Buffer {
  const okName = Buffer.from('ok\0', 'ascii');
  const okVal = Buffer.alloc(8);
  okVal.writeDoubleLE(0.0, 0);

  const msgName = Buffer.from('errmsg\0', 'ascii');
  const msgVal = Buffer.from(message + '\0', 'utf8');
  const msgLen = Buffer.alloc(4);
  msgLen.writeInt32LE(msgVal.length, 0);

  const codeName = Buffer.from('code\0', 'ascii');
  const codeVal = Buffer.alloc(4);
  codeVal.writeInt32LE(code, 0);

  const body = Buffer.concat([
    Buffer.from([0x01]), okName, okVal,
    Buffer.from([0x02]), msgName, msgLen, msgVal,
    Buffer.from([0x10]), codeName, codeVal,
    Buffer.from([0x00]) // Document terminator
  ]);

  const docSize = Buffer.alloc(4);
  docSize.writeInt32LE(body.length + 4, 0);

  const bsonDoc = Buffer.concat([docSize, body]);

  const header = Buffer.alloc(21);
  header.writeInt32LE(16 + 4 + 1 + bsonDoc.length, 0); // messageLength
  header.writeInt32LE(Math.floor(Math.random() * 100000), 4); // requestId
  header.writeInt32LE(0, 8); // responseTo
  header.writeInt32LE(2013, 12); // opCode OP_MSG
  header.writeInt32LE(0, 16); // flags
  header[20] = 0x00; // section type 0

  return Buffer.concat([header, bsonDoc]);
}

export function handleMongoConnection(
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
    if (data.length > 16 && !options.noWaf) {
      const opCode = data.readInt32LE(12);
      if (opCode === 2013 || opCode === 2004) { // OP_MSG or OP_QUERY
        const payloadStr = data.toString('utf8');
        try {
          if (payloadStr.includes('dropDatabase') || payloadStr.includes('$where')) {
            throw new Error('Dangerous command dropDatabase or $where is not allowed');
          }
          validateQuery(payloadStr, options.role);
        } catch (err: any) {
          options.logSiem('WAF_MONGO_BLOCK', 9, `MongoDB WAF violation blocked: ${err.message}`);
          const errPacket = serializeMongoError(err.message, 13);
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
