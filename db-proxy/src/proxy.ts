import * as net from 'net';
import { Buffer } from 'buffer';
import {
  PostgresStreamParser,
  parseStartupMessage,
  parseRowDescription,
  parseDataRow,
  serializeDataRow,
} from './pg-protocol.js';
import {
  resolveUserContext,
  getRbacConfig,
  ProxyConfig,
  ProxyUserContext,
} from './auth.js';
import {
  dbGuardContextStore,
  decryptValue,
  decryptWithSecurity,
} from '@vollcrypt/db-guard';

export interface DbProxyOptions {
  port: number;
  dbHost: string;
  dbPort: number;
  config?: ProxyConfig;
  resolvedKeys: Record<string, Buffer>;
}

/**
 * Serializes a PostgreSQL protocol ErrorResponse ('E') message.
 */
export function serializeErrorResponse(message: string, code: string = '42501'): Buffer {
  const fields = [
    { type: 'S', value: 'ERROR' },
    { type: 'C', value: code },
    { type: 'M', value: message },
  ];

  let totalSize = 0;
  for (const f of fields) {
    totalSize += 1 + Buffer.byteLength(f.value, 'utf8') + 1;
  }
  totalSize += 1; // final null byte

  const msgLen = 4 + totalSize;
  const buf = Buffer.alloc(1 + msgLen);
  buf.write('E', 0, 'ascii');
  buf.writeInt32BE(msgLen, 1);

  let offset = 5;
  for (const f of fields) {
    buf.write(f.type, offset, 'ascii');
    offset += 1;
    const len = buf.write(f.value, offset, 'utf8');
    offset += len;
    buf.writeUInt8(0, offset);
    offset += 1;
  }
  buf.writeUInt8(0, offset);

  return buf;
}

export class DbProxyServer {
  private server: net.Server | null = null;
  private activeConnections = new Set<net.Socket>();

  constructor(private options: DbProxyOptions) {}

  public start(): Promise<void> {
    return new Promise((resolve, reject) => {
      this.server = net.createServer((clientSocket) => {
        this.handleConnection(clientSocket);
      });

      this.server.on('error', (err) => {
        reject(err);
      });

      this.server.listen(this.options.port, () => {
        resolve();
      });
    });
  }

  public stop(): Promise<void> {
    return new Promise((resolve) => {
      for (const socket of this.activeConnections) {
        socket.destroy();
      }
      this.activeConnections.clear();

      if (this.server) {
        this.server.close(() => {
          resolve();
        });
      } else {
        resolve();
      }
    });
  }

  private handleConnection(clientSocket: net.Socket) {
    this.activeConnections.add(clientSocket);

    const backendSocket = net.connect({
      host: this.options.dbHost,
      port: this.options.dbPort,
    });

    const clientParser = new PostgresStreamParser();
    const backendParser = new PostgresStreamParser();

    let userContext: ProxyUserContext | null = null;
    let currentColumns: string[] = [];
    let isSslNegotiated = false;

    // Handle client to backend stream
    clientSocket.on('data', (data) => {
      try {
        const messages = clientParser.append(data);
        for (const msg of messages) {
          if (!userContext) {
            // Check if it is an SSLRequest (8 bytes, second 4 bytes code: 80877103)
            if (msg.length === 8 && msg.readInt32BE(4) === 80877103) {
              isSslNegotiated = true;
              // Respond with 'N' to refuse SSL, forcing client to fallback to plaintext
              clientSocket.write(Buffer.from('N', 'ascii'));
              continue;
            }

            // Otherwise, it must be the StartupMessage
            const params = parseStartupMessage(msg);
            const username = params.user || 'guest';
            userContext = resolveUserContext(username, this.options.config);

            backendSocket.write(msg);
          } else {
            backendSocket.write(msg);
          }
        }
      } catch (err) {
        const errMsg = (err as Error).message;
        clientSocket.write(serializeErrorResponse(`Vollcrypt Proxy: ${errMsg}`));
        clientSocket.destroy();
      }
    });

    // Handle backend to client stream
    backendSocket.on('data', (data) => {
      try {
        const messages = backendParser.append(data);
        for (const msg of messages) {
          const type = msg[0];

          if (type === 84) { // 'T' -> RowDescription
            currentColumns = parseRowDescription(msg);
            clientSocket.write(msg);
          } else if (type === 68) { // 'D' -> DataRow
            const values = parseDataRow(msg);
            const modifiedValues: (Buffer | null)[] = [];
            let encryptionError: Error | null = null;

            for (let i = 0; i < values.length; i++) {
              const val = values[i];
              if (val === null) {
                modifiedValues.push(null);
                continue;
              }

              const strVal = val.toString('utf8');
              if (strVal.startsWith('VOLLVALT:')) {
                const columnName = currentColumns[i] || `col_${i}`;
                try {
                  // Decrypt using security controls inside user context store
                  const decrypted = dbGuardContextStore.run(
                    {
                      role: userContext?.role || 'GUEST',
                      userId: userContext?.userId || 'guest-user',
                    },
                    () => {
                      let modelName = 'default';
                      let fieldName = columnName;
                      if (columnName.includes('.')) {
                        const parts = columnName.split('.');
                        modelName = parts[0];
                        fieldName = parts[1];
                      }

                      return decryptWithSecurity(
                        strVal,
                        (cipherText) => decryptValue(cipherText, this.options.resolvedKeys),
                        modelName,
                        fieldName,
                        undefined,
                        {
                          cryptoRbac: getRbacConfig(this.options.config),
                          rateLimiter: (this.options.config as any)?.rateLimiter,
                        }
                      );
                    }
                  );

                  const decryptedStr = typeof decrypted === 'string' ? decrypted : JSON.stringify(decrypted);
                  modifiedValues.push(Buffer.from(decryptedStr, 'utf8'));
                } catch (err) {
                  encryptionError = err as Error;
                  break;
                }
              } else {
                modifiedValues.push(val);
              }
            }

            if (encryptionError) {
              clientSocket.write(serializeErrorResponse(`Vollcrypt Cryptographic Access Violation: ${encryptionError.message}`));
              // End the packet flow for this stream
              break;
            } else {
              const newMsg = serializeDataRow(modifiedValues);
              clientSocket.write(newMsg);
            }
          } else {
            clientSocket.write(msg);
          }
        }
      } catch (err) {
        const errMsg = (err as Error).message;
        clientSocket.write(serializeErrorResponse(`Vollcrypt Proxy: ${errMsg}`));
        clientSocket.destroy();
      }
    });

    clientSocket.on('close', () => {
      this.activeConnections.delete(clientSocket);
      backendSocket.destroy();
    });

    backendSocket.on('close', () => {
      clientSocket.destroy();
    });

    clientSocket.on('error', () => {
      backendSocket.destroy();
    });

    backendSocket.on('error', () => {
      clientSocket.destroy();
    });
  }
}
