import * as net from 'net';
import { Buffer } from 'buffer';
import * as fs from 'fs';
import {
  PostgresStreamParser,
  parseStartupMessage,
  parseRowDescription,
  parseDataRow,
  serializeDataRow,
  parseParameterStatus,
  serializeParameterStatus,
  serializePasswordMessage,
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
import { validateQuery, generateFingerprint, evaluateThreatScore } from './waf.js';
import { scanAndMaskCell } from './dlp.js';

export interface DbProxyOptions {
  port: number;
  dbHost: string;
  dbPort: number;
  config?: ProxyConfig;
  resolvedKeys: Record<string, Buffer>;
  dbPassword?: string;
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
  private allowlistedFingerprints = new Set<string>();

  private activeSsoSessions = new Map<string, { username: string; expiresAt: number; roles: string[] }>();
  private activeJitGrants = new Map<string, { role: string; expiresAt: number }>();

  public registerSsoSession(username: string, passcode: string, roles: string[], ttlMs: number = 900000) {
    this.activeSsoSessions.set(passcode, {
      username,
      expiresAt: Date.now() + ttlMs,
      roles,
    });
  }

  public registerJitGrant(userId: string, role: string, durationMs: number) {
    this.activeJitGrants.set(userId, {
      role,
      expiresAt: Date.now() + durationMs,
    });
  }

  constructor(private options: DbProxyOptions) {
    this.loadAllowlist();
  }

  private loadAllowlist() {
    const config = this.options.config?.firewall?.fingerprinting;
    if (config?.enabled && config.allowlistPath) {
      if (fs.existsSync(config.allowlistPath)) {
        try {
          const content = fs.readFileSync(config.allowlistPath, 'utf8');
          const list = JSON.parse(content);
          if (Array.isArray(list)) {
            this.allowlistedFingerprints = new Set(list);
          }
        } catch (err) {
          console.error('Failed to parse WAF allowlist file:', err);
        }
      }
    }
  }

  private saveAllowlist() {
    const config = this.options.config?.firewall?.fingerprinting;
    if (config?.enabled && config.allowlistPath) {
      try {
        const list = Array.from(this.allowlistedFingerprints);
        fs.writeFileSync(config.allowlistPath, JSON.stringify(list, null, 2), 'utf8');
      } catch (err) {
        console.error('Failed to save WAF allowlist file:', err);
      }
    }
  }

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
    let originalUsername = '';
    const dbGuardContext: any = {
      role: 'GUEST',
      userId: 'guest-user',
      maxDecryptionsPerSecond: this.options.config?.rateLimiter?.maxDecryptionsPerSecond,
      rateLimiterMode: this.options.config?.rateLimiter?.mode,
    };
    let currentColumns: string[] = [];
    let isSslNegotiated = false;
    let rowCount = 0;
    let bypassScanning = false;
    const queryTimestamps: number[] = [];

    // Prepared statement and portal schema caches to prevent Extended Protocol bypasses
    const statements = new Map<string, { query: string; columns?: string[] }>();
    const portals = new Map<string, { statementName: string; columns?: string[] }>();
    let lastDescribeRequest: { type: string; name: string } | null = null;

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
            originalUsername = username;
            userContext = resolveUserContext(username, this.options.config);
            dbGuardContext.role = userContext.role;
            dbGuardContext.userId = userContext.userId;

            backendSocket.write(msg);
          } else {
            // WAF Validation and Prepared Statement tracking
            const type = msg[0];
            let queryStr: string | null = null;

            if (type === 112) { // 'p' (PasswordMessage)
              const password = msg.toString('utf8', 5, msg.length - 1);
              const ssoSession = this.activeSsoSessions.get(password);
              if (ssoSession && ssoSession.expiresAt > Date.now()) {
                userContext = {
                  userId: `usr-sso-${ssoSession.username}`,
                  role: ssoSession.roles[0] || 'GUEST',
                };
                dbGuardContext.role = userContext.role;
                dbGuardContext.userId = userContext.userId;

                const realDbPassword = this.options.dbPassword || 'postgres';
                const newMsg = serializePasswordMessage(realDbPassword);
                backendSocket.write(newMsg);
                continue;
              } else {
                backendSocket.write(msg);
                continue;
              }
            }

            if (type === 81) { // 'Q' (Simple Query)
              queryStr = msg.subarray(5, msg.length - 1).toString('utf8');
              currentColumns = []; // Reset simple query schema state
              rowCount = 0;
              bypassScanning = false;
            } else if (type === 80) { // 'P' (Parse prepared statement)
              const destNameNull = msg.indexOf(0, 5);
              if (destNameNull !== -1) {
                const statementName = msg.toString('utf8', 5, destNameNull);
                const queryStart = destNameNull + 1;
                const queryNull = msg.indexOf(0, queryStart);
                if (queryNull !== -1) {
                  queryStr = msg.toString('utf8', queryStart, queryNull);
                  statements.set(statementName, { query: queryStr });
                }
              }
            } else if (type === 66) { // 'B' (Bind portal)
              const portalNull = msg.indexOf(0, 5);
              if (portalNull !== -1) {
                const portalName = msg.toString('utf8', 5, portalNull);
                const stmtStart = portalNull + 1;
                const stmtNull = msg.indexOf(0, stmtStart);
                if (stmtNull !== -1) {
                  const statementName = msg.toString('utf8', stmtStart, stmtNull);
                  const stmt = statements.get(statementName);
                  portals.set(portalName, {
                    statementName,
                    columns: stmt?.columns,
                  });
                }
              }
            } else if (type === 68) { // 'D' (Describe)
              if (msg.length >= 7) {
                const descType = String.fromCharCode(msg[5]);
                const nameNull = msg.indexOf(0, 6);
                if (nameNull !== -1) {
                  const name = msg.toString('utf8', 6, nameNull);
                  lastDescribeRequest = { type: descType, name };
                }
              }
            } else if (type === 69) { // 'E' (Execute)
              rowCount = 0;
              bypassScanning = false;
              const portalNull = msg.indexOf(0, 5);
              if (portalNull !== -1) {
                const portalName = msg.toString('utf8', 5, portalNull);
                const portal = portals.get(portalName);
                if (portal && portal.columns) {
                  currentColumns = portal.columns;
                }
              }
            }

            if (queryStr) {
              try {
                // 0. Dynamic JIT evaluation
                const activeJit = this.activeJitGrants.get(dbGuardContext.userId);
                if (activeJit) {
                  if (activeJit.expiresAt > Date.now()) {
                    dbGuardContext.role = activeJit.role;
                  } else {
                    const originalContext = resolveUserContext(originalUsername, this.options.config);
                    dbGuardContext.role = originalContext.role;
                  }
                }

                // 1. Rate limiting per connection
                const nowMs = Date.now();
                while (queryTimestamps.length > 0 && nowMs - queryTimestamps[0] > 1000) {
                  queryTimestamps.shift();
                }
                const maxQps = this.options.config?.firewall?.rateLimits?.maxQueriesPerSecond;
                if (maxQps && queryTimestamps.length >= maxQps) {
                  throw new Error(`Connection query rate limit exceeded (Limit: ${maxQps}/sec)`);
                }
                queryTimestamps.push(nowMs);

                // 2. Temporal constraints per role
                const constraints = this.options.config?.firewall?.temporalConstraints?.[dbGuardContext.role];
                if (constraints) {
                  const now = new Date();
                  const currentHour = now.getHours();
                  const currentDay = now.getDay();
                  if (!constraints.allowedDays.includes(currentDay) || currentHour < constraints.startHour || currentHour >= constraints.endHour) {
                    throw new Error(`Temporal access restriction. Role "${dbGuardContext.role}" is not permitted to query database at this time.`);
                  }
                }

                // 3. WAF signature & DDL checks
                validateQuery(queryStr, dbGuardContext.role);

                // 4. Semantic threat score analysis
                const threatScore = evaluateThreatScore(queryStr);
                const scoreLimit = 8; // threshold of 8 triggers block
                if (threatScore >= scoreLimit) {
                  throw new Error(`Semantic SQLi threat detected: query score is ${threatScore} (Limit: ${scoreLimit})`);
                }

                // 5. Query Fingerprinting & Allowlisting
                const fpConfig = this.options.config?.firewall?.fingerprinting;
                if (fpConfig?.enabled) {
                  const fingerprint = generateFingerprint(queryStr);
                  if (fpConfig.mode === 'learning') {
                    if (!this.allowlistedFingerprints.has(fingerprint)) {
                      this.allowlistedFingerprints.add(fingerprint);
                      this.saveAllowlist();
                    }
                  } else if (fpConfig.mode === 'blocking') {
                    if (!this.allowlistedFingerprints.has(fingerprint)) {
                      throw new Error(`Blocked by allowlist: query shape "${fingerprint}" is not recognized`);
                    }
                  }
                }

              } catch (err) {
                const violationMsg = (err as Error).message;
                // Write standard PostgreSQL protocol error frame back to the client
                clientSocket.write(serializeErrorResponse(`Vollcrypt WAF Blocked: ${violationMsg}`));
                // Send ReadyForQuery ('Z') so client CLI / DBeaver doesn't hang
                const readyForQuery = Buffer.from([0x5a, 0, 0, 0, 5, 0x49]);
                clientSocket.write(readyForQuery);
                continue;
              }
            }

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
            
            const sensitiveKeywords = ['credit_card', 'email', 'tc_no', 'phone', 'iban', 'cc', 'ssn', 'salary', 'password', 'secret'];
            const hasSensitive = currentColumns.some(col => {
              const colLower = col.toLowerCase();
              return sensitiveKeywords.some(kw => colLower.includes(kw));
            });
            bypassScanning = !hasSensitive;

            // Map the parsed description to the active prepared statement or portal
            if (lastDescribeRequest) {
              if (lastDescribeRequest.type === 'S') {
                const stmt = statements.get(lastDescribeRequest.name);
                if (stmt) {
                  stmt.columns = currentColumns;
                }
              } else if (lastDescribeRequest.type === 'P') {
                const portal = portals.get(lastDescribeRequest.name);
                if (portal) {
                  portal.columns = currentColumns;
                }
              }
            }
            clientSocket.write(msg);
          } else if (type === 68) { // 'D' -> DataRow
            rowCount++;
            const maxRows = this.options.config?.firewall?.maxRowsPerQuery || 5000;
            if (rowCount > maxRows) {
              clientSocket.write(serializeErrorResponse(`Vollcrypt WAF Blocked: Mass exfiltration limit exceeded (Limit: ${maxRows})`));
              clientSocket.destroy();
              backendSocket.destroy();
              break;
            }

            if (bypassScanning) {
              if (!msg.includes('VOLLVALT:')) {
                clientSocket.write(msg);
                continue;
              }
            }

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
                    dbGuardContext,
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
                // DLP Auto-PII scanning on unencrypted text cells
                const maskedVal = scanAndMaskCell(strVal);
                if (maskedVal !== strVal) {
                  modifiedValues.push(Buffer.from(maskedVal, 'utf8'));
                } else {
                  modifiedValues.push(val);
                }
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
          } else if (type === 83) { // 'S' -> ParameterStatus
            const status = parseParameterStatus(msg);
            if (status && status.name === 'server_version') {
              const maskedVersion = this.options.config?.firewall?.versionMask || '16.0';
              const newMsg = serializeParameterStatus('server_version', maskedVersion);
              clientSocket.write(newMsg);
            } else {
              clientSocket.write(msg);
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
