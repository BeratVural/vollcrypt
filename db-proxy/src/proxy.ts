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
  serializeQueryMessage,
  serializeParseMessage,
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
import { validateQuery, generateFingerprint, evaluateThreatScore, rewriteQuery, generateLaplaceNoise, getMockAttestationReport } from './waf.js';
import { scanAndMaskCell } from './dlp.js';

export interface DbProxyOptions {
  port: number;
  dbHost: string;
  dbPort: number;
  config?: ProxyConfig;
  resolvedKeys: Record<string, Buffer>;
  dbPassword?: string;
  gossipPort?: number;
  peers?: string[];
  minResponseTimeMs?: number;
  noAttestation?: boolean;
  noDlp?: boolean;
  noWaf?: boolean;
  noIpBanning?: boolean;
  dbType?: 'postgres' | 'mysql' | 'mongodb' | 'mssql' | 'oracle';
  fipsMode?: boolean;
  mpcShares?: Buffer[];
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

/**
 * Helper to serialize RowDescription ('T') packet.
 */
export function buildRowDescription(columns: string[]): Buffer {
  let totalSize = 0;
  for (const col of columns) {
    totalSize += Buffer.byteLength(col, 'utf8') + 1 + 4 + 2 + 4 + 2 + 4 + 2;
  }
  const msgLen = 4 + 2 + totalSize;
  const buf = Buffer.alloc(1 + msgLen);
  buf.write('T', 0, 'ascii');
  buf.writeInt32BE(msgLen, 1);
  buf.writeInt16BE(columns.length, 5);

  let offset = 7;
  for (const col of columns) {
    const nameLen = buf.write(col, offset, 'utf8');
    offset += nameLen;
    buf.writeUInt8(0, offset); // null terminator
    offset += 1;
    buf.writeInt32BE(0, offset); // table OID
    offset += 4;
    buf.writeInt16BE(0, offset); // attr num
    offset += 2;
    buf.writeInt32BE(25, offset); // type OID (text)
    offset += 4;
    buf.writeInt16BE(-1, offset); // type size
    offset += 2;
    buf.writeInt32BE(-1, offset); // type modifier
    offset += 4;
    buf.writeInt16BE(0, offset); // format code (text)
    offset += 2;
  }
  return buf;
}

export interface ClusterMessage {
  type: 'HEARTBEAT' | 'BAN_IP' | 'ALLOWLIST_FP' | 'DECRYPTION_USAGE';
  senderId: string;
  data: any;
}

export class ClusterManager {
  private server: net.Server | null = null;
  private peerSockets = new Map<string, net.Socket>();
  
  constructor(
    private nodeId: string,
    private gossipPort: number,
    private peers: string[],
    private onMessage: (msg: ClusterMessage) => void
  ) {}

  public async start(): Promise<void> {
    if (!this.gossipPort) return;

    this.server = net.createServer((socket) => {
      let buffer = Buffer.alloc(0);
      socket.on('data', (data) => {
        buffer = Buffer.concat([buffer, data]);
        while (true) {
          const newlineIdx = buffer.indexOf('\n');
          if (newlineIdx === -1) break;
          const line = buffer.subarray(0, newlineIdx).toString('utf8');
          buffer = buffer.subarray(newlineIdx + 1);
          try {
            const msg: ClusterMessage = JSON.parse(line);
            this.onMessage(msg);
          } catch (err) {
            // ignore malformed messages
          }
        }
      });
      socket.on('error', () => {});
    });

    return new Promise((resolve, reject) => {
      this.server!.listen(this.gossipPort, () => {
        this.startHeartbeatLoop();
        resolve();
      });
      this.server!.on('error', (err) => reject(err));
    });
  }

  private startHeartbeatLoop() {
    const interval = setInterval(() => {
      if (!this.server || !this.server.listening) {
        clearInterval(interval);
        return;
      }
      this.broadcast({
        type: 'HEARTBEAT',
        senderId: this.nodeId,
        data: { active: true }
      });
    }, 1000);
  }

  public broadcast(msg: ClusterMessage) {
    const payload = JSON.stringify(msg) + '\n';
    for (const peer of this.peers) {
      const [host, portStr] = peer.split(':');
      const port = parseInt(portStr);
      if (port === this.gossipPort) continue;

      let client = this.peerSockets.get(peer);
      if (!client || client.destroyed) {
        client = net.connect({ host, port }, () => {
          client!.write(payload);
        });
        client.on('error', () => {});
        this.peerSockets.set(peer, client);
      } else {
        try {
          client.write(payload);
        } catch (err) {
          // peer disconnected, will reconnect next time
        }
      }
    }
  }

  public stop() {
    if (this.server) {
      this.server.close();
    }
    for (const socket of this.peerSockets.values()) {
      socket.destroy();
    }
    this.peerSockets.clear();
  }
}

export class DbProxyServer {
  private server: net.Server | null = null;
  private activeConnections = new Set<net.Socket>();
  private allowlistedFingerprints = new Set<string>();

  private activeSsoSessions = new Map<string, { username: string; expiresAt: number; roles: string[] }>();
  private activeJitGrants = new Map<string, { role: string; expiresAt: number }>();
  private bannedIps = new Set<string>();
  private clusterManager: ClusterManager | null = null;
  private nodeId = Math.random().toString(36).substring(7);

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

  public logSiemEvent(event: string, severity: number, username: string, clientIp: string, message: string) {
    const timestamp = new Date().toISOString();
    const cefStr = `CEF:0|Vollcrypt|DB-Proxy|1.0|${event}|${event}|${severity}|src=${clientIp} usrName=${username} msg=${message}\n`;
    try {
      if (!fs.existsSync('logs')) {
        fs.mkdirSync('logs');
      }
      fs.appendFileSync('logs/siem.cef', cefStr, 'utf8');
    } catch (err) {
      console.error('Failed to write SIEM CEF log:', err);
    }
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

  private handleClusterMessage(msg: ClusterMessage) {
    if (msg.type === 'BAN_IP') {
      const ip = msg.data.ip;
      if (ip && !this.bannedIps.has(ip)) {
        this.bannedIps.add(ip);
        this.logSiemEvent('CLUSTER_SYNC', 5, 'cluster', '127.0.0.1', `Synchronized banned IP address from peer: ${ip}`);
        for (const socket of this.activeConnections) {
          if (socket.remoteAddress === ip) {
            socket.destroy();
          }
        }
      }
    } else if (msg.type === 'ALLOWLIST_FP') {
      const fp = msg.data.fingerprint;
      if (fp && !this.allowlistedFingerprints.has(fp)) {
        this.allowlistedFingerprints.add(fp);
        this.saveAllowlist();
      }
    }
  }

  public async start(): Promise<void> {
    if (this.options.gossipPort && this.options.peers) {
      this.clusterManager = new ClusterManager(
        this.nodeId,
        this.options.gossipPort,
        this.options.peers,
        (msg) => this.handleClusterMessage(msg)
      );
      await this.clusterManager.start();
    }

    if (this.options.fipsMode) {
      const crypto = await import('crypto');
      let isFips = false;
      try {
        isFips = (crypto as any).getFips?.() || false;
      } catch {
        isFips = false;
      }
      this.logSiemEvent('FIPS_INIT', 1, 'system', '127.0.0.1', `FIPS 140-3 boundary compliance enabled. FIPS status: ${isFips}`);
    }

    if (this.options.mpcShares && this.options.mpcShares.length >= 2) {
      const { reconstructKeyMpc } = await import('./mpc.js');
      const reconstructedKey = reconstructKeyMpc(this.options.mpcShares);
      this.options.resolvedKeys['1'] = reconstructedKey;
      this.logSiemEvent('MPC_KEY_INIT', 1, 'system', '127.0.0.1', 'Decryption key successfully reconstructed using MPC threshold shares.');
    }

    return new Promise((resolve, reject) => {
      this.server = net.createServer((clientSocket) => {
        const clientIp = clientSocket.remoteAddress;
        if (clientIp && this.bannedIps.has(clientIp) && !this.options.noIpBanning) {
          clientSocket.destroy();
          return;
        }

        const dbType = this.options.dbType || 'postgres';
        if (dbType === 'mysql') {
          import('./drivers/mysql.js').then(({ handleMysqlConnection }) => {
            handleMysqlConnection(clientSocket, {
              dbHost: this.options.dbHost,
              dbPort: this.options.dbPort,
              noWaf: this.options.noWaf,
              role: 'GUEST',
              clientIp: clientIp || '127.0.0.1',
              resolvedKeys: this.options.resolvedKeys,
              logSiem: (evt, sev, msg) => this.logSiemEvent(evt, sev, 'mysql_user', clientIp || '127.0.0.1', msg),
            });
          });
          return;
        }

        if (dbType === 'mongodb') {
          import('./drivers/mongo.js').then(({ handleMongoConnection }) => {
            handleMongoConnection(clientSocket, {
              dbHost: this.options.dbHost,
              dbPort: this.options.dbPort,
              noWaf: this.options.noWaf,
              role: 'GUEST',
              clientIp: clientIp || '127.0.0.1',
              resolvedKeys: this.options.resolvedKeys,
              logSiem: (evt, sev, msg) => this.logSiemEvent(evt, sev, 'mongo_user', clientIp || '127.0.0.1', msg),
            });
          });
          return;
        }

        if (dbType === 'mssql') {
          import('./drivers/mssql.js').then(({ handleMssqlConnection }) => {
            handleMssqlConnection(clientSocket, {
              dbHost: this.options.dbHost,
              dbPort: this.options.dbPort,
              noWaf: this.options.noWaf,
              role: 'GUEST',
              clientIp: clientIp || '127.0.0.1',
              resolvedKeys: this.options.resolvedKeys,
              logSiem: (evt, sev, msg) => this.logSiemEvent(evt, sev, 'mssql_user', clientIp || '127.0.0.1', msg),
            });
          });
          return;
        }

        if (dbType === 'oracle') {
          import('./drivers/oracle.js').then(({ handleOracleConnection }) => {
            handleOracleConnection(clientSocket, {
              dbHost: this.options.dbHost,
              dbPort: this.options.dbPort,
              noWaf: this.options.noWaf,
              role: 'GUEST',
              clientIp: clientIp || '127.0.0.1',
              resolvedKeys: this.options.resolvedKeys,
              logSiem: (evt, sev, msg) => this.logSiemEvent(evt, sev, 'oracle_user', clientIp || '127.0.0.1', msg),
            });
          });
          return;
        }

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

      if (this.clusterManager) {
        this.clusterManager.stop();
        this.clusterManager = null;
      }

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
    const clientIp = clientSocket.remoteAddress || '127.0.0.1';

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
    const egressHistory: { count: number; timestamp: number }[] = [];
    let queryStartTime = 0;

    // Prepared statement and portal schema caches to prevent Extended Protocol bypasses
    const statements = new Map<string, { query: string; columns?: string[] }>();
    const portals = new Map<string, { statementName: string; columns?: string[] }>();
    let lastDescribeRequest: { type: string; name: string } | null = null;

    // Handle client to backend stream
    clientSocket.on('data', async (data) => {
      try {
        const messages = clientParser.append(data);
        for (const msg of messages) {
          let forwardedMsg = msg;

          if (!userContext) {
            // Check if it is an SSLRequest (8 bytes, second 4 bytes code: 80877103)
            if (forwardedMsg.length === 8 && forwardedMsg.readInt32BE(4) === 80877103) {
              isSslNegotiated = true;
              // Respond with 'N' to refuse SSL, forcing client to fallback to plaintext
              clientSocket.write(Buffer.from('N', 'ascii'));
              continue;
            }

            // Otherwise, it must be the StartupMessage
            const params = parseStartupMessage(forwardedMsg);
            const username = params.user || 'guest';
            originalUsername = username;
            userContext = resolveUserContext(username, this.options.config);
            dbGuardContext.role = userContext.role;
            dbGuardContext.userId = userContext.userId;

            backendSocket.write(forwardedMsg);
          } else {
            // WAF Validation and Prepared Statement tracking
            const type = forwardedMsg[0];
            let queryStr: string | null = null;

            if (type === 112) { // 'p' (PasswordMessage)
              const password = forwardedMsg.toString('utf8', 5, forwardedMsg.length - 1);
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
                backendSocket.write(forwardedMsg);
                continue;
              }
            }

            if (type === 81) { // 'Q' (Simple Query)
              queryStartTime = Date.now();
              queryStr = forwardedMsg.subarray(5, forwardedMsg.length - 1).toString('utf8');

              // Intercept Remote Attestation query
              const normalizedQuery = queryStr.trim().toUpperCase().replace(/;/g, '');
              if (normalizedQuery === 'SELECT VOLLCRYPT_ATTESTATION_REPORT()' && !this.options.noAttestation) {
                const report = getMockAttestationReport();
                const jsonStr = JSON.stringify(report);
                const rowDesc = buildRowDescription(['attestation_report']);
                const dataRow = serializeDataRow([Buffer.from(jsonStr, 'utf8')]);
                const cmdComplete = Buffer.alloc(18);
                cmdComplete.write('C', 0, 'ascii');
                cmdComplete.writeInt32BE(17, 1);
                cmdComplete.write('SELECT 1\0', 5, 'ascii');
                const readyForQuery = Buffer.from([0x5a, 0, 0, 0, 5, 0x49]);

                const minTime = this.options.minResponseTimeMs ?? 15;
                const elapsed = Date.now() - queryStartTime;
                if (elapsed < minTime) {
                  await new Promise(resolve => setTimeout(resolve, minTime - elapsed));
                }

                clientSocket.write(Buffer.concat([rowDesc, dataRow, cmdComplete, readyForQuery]));
                continue;
              }

              currentColumns = []; // Reset simple query schema state
              rowCount = 0;
              bypassScanning = false;
            } else if (type === 80) { // 'P' (Parse prepared statement)
              queryStartTime = Date.now();
              const destNameNull = forwardedMsg.indexOf(0, 5);
              if (destNameNull !== -1) {
                const statementName = forwardedMsg.toString('utf8', 5, destNameNull);
                const queryStart = destNameNull + 1;
                const queryNull = forwardedMsg.indexOf(0, queryStart);
                if (queryNull !== -1) {
                  queryStr = forwardedMsg.toString('utf8', queryStart, queryNull);
                  statements.set(statementName, { query: queryStr });
                }
              }
            } else if (type === 66) { // 'B' (Bind portal)
              const portalNull = forwardedMsg.indexOf(0, 5);
              if (portalNull !== -1) {
                const portalName = forwardedMsg.toString('utf8', 5, portalNull);
                const stmtStart = portalNull + 1;
                const stmtNull = forwardedMsg.indexOf(0, stmtStart);
                if (stmtNull !== -1) {
                  const statementName = forwardedMsg.toString('utf8', stmtStart, stmtNull);
                  const stmt = statements.get(statementName);
                  portals.set(portalName, {
                    statementName,
                    columns: stmt?.columns,
                  });
                }
              }
            } else if (type === 68) { // 'D' (Describe)
              if (forwardedMsg.length >= 7) {
                const descType = String.fromCharCode(forwardedMsg[5]);
                const nameNull = forwardedMsg.indexOf(0, 6);
                if (nameNull !== -1) {
                  const name = forwardedMsg.toString('utf8', 6, nameNull);
                  lastDescribeRequest = { type: descType, name };
                }
              }
            } else if (type === 69) { // 'E' (Execute)
              rowCount = 0;
              bypassScanning = false;
              const portalNull = forwardedMsg.indexOf(0, 5);
              if (portalNull !== -1) {
                const portalName = forwardedMsg.toString('utf8', 5, portalNull);
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

                // JIT Temporary Access Approval Webhook Simulation
                if (this.options.config?.firewall?.jitApprovalRequired && dbGuardContext.role !== 'OWNER') {
                  const hasActiveGrant = activeJit && activeJit.expiresAt > Date.now();
                  if (!hasActiveGrant) {
                    this.logSiemEvent('JIT_REQUESTED', 6, dbGuardContext.userId, clientIp || '127.0.0.1', `JIT request triggered for query: ${queryStr}`);
                    
                    // Trigger simulated background approval webhook after 50ms
                    setTimeout(() => {
                      this.registerJitGrant(dbGuardContext.userId, 'OWNER', 3600000);
                      this.logSiemEvent('JIT_APPROVED', 6, 'system', '127.0.0.1', `JIT request automatically approved for user ${dbGuardContext.userId}`);
                    }, 50);

                    // Halt execution asynchronously to await the approval callback
                    await new Promise((r) => setTimeout(r, 100));

                    const updatedJit = this.activeJitGrants.get(dbGuardContext.userId);
                    if (updatedJit && updatedJit.expiresAt > Date.now()) {
                      dbGuardContext.role = updatedJit.role;
                    } else {
                      throw new Error('JIT approval request timed out or was denied');
                    }
                  }
                }

                // AI-Driven Anomaly Threat Scoring
                if (this.options.config?.firewall?.anomalyEngine?.enabled) {
                  const { QueryAnomalyScorer } = await import('./anomaly.js');
                  const scorer = new QueryAnomalyScorer();
                  // Pre-learn normal baseline profiles
                  scorer.learnBaseline(dbGuardContext.userId, [
                    'SELECT * FROM users WHERE id = 1',
                    'SELECT id, username FROM users',
                    'SELECT email FROM users WHERE role = ?',
                  ]);
                  const score = scorer.getAnomalyScore(dbGuardContext.userId, queryStr);
                  if (score > 0.7) {
                    this.logSiemEvent('ANOMALY_THREAT_DETECTION', 8, dbGuardContext.userId, clientIp || '127.0.0.1', `Semantic anomaly detected with threat score ${score.toFixed(2)}: ${queryStr}`);
                    throw new Error(`Query blocked by AI Anomaly Threat Detection (Score: ${score.toFixed(2)})`);
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
                if (!this.options.noWaf) {
                  validateQuery(queryStr, dbGuardContext.role);

                  // 4. Semantic threat score analysis
                  const threatScore = evaluateThreatScore(queryStr);
                  const scoreLimit = 8; // threshold of 8 triggers block
                  if (threatScore >= scoreLimit) {
                    throw new Error(`Semantic SQLi threat detected: query score is ${threatScore} (Limit: ${scoreLimit})`);
                  }
                }

                // 5. Query Fingerprinting & Allowlisting
                const fpConfig = this.options.config?.firewall?.fingerprinting;
                if (fpConfig?.enabled) {
                  const fingerprint = generateFingerprint(queryStr);
                  if (fpConfig.mode === 'learning') {
                    if (!this.allowlistedFingerprints.has(fingerprint)) {
                      this.allowlistedFingerprints.add(fingerprint);
                      this.saveAllowlist();
                      if (this.clusterManager) {
                        this.clusterManager.broadcast({
                          type: 'ALLOWLIST_FP',
                          senderId: this.nodeId,
                          data: { fingerprint }
                        });
                      }
                    }
                  } else if (fpConfig.mode === 'blocking') {
                    if (!this.allowlistedFingerprints.has(fingerprint)) {
                      throw new Error(`Blocked by allowlist: query shape "${fingerprint}" is not recognized`);
                    }
                  }
                }

                // 6. Dynamic SQL Query Rewriting (Masking & RLS Tenant Isolation)
                const rewritten = rewriteQuery(queryStr, dbGuardContext.role, userContext?.tenantId, this.options.config);
                if (rewritten !== queryStr) {
                  if (type === 81) { // Simple Query 'Q'
                    forwardedMsg = serializeQueryMessage(rewritten);
                  } else if (type === 80) { // Parse 'P'
                    const destNameNull = forwardedMsg.indexOf(0, 5);
                    const statementName = destNameNull !== -1 ? forwardedMsg.toString('utf8', 5, destNameNull) : '';
                    const queryNull = destNameNull !== -1 ? forwardedMsg.indexOf(0, destNameNull + 1) : -1;
                    if (queryNull !== -1) {
                      forwardedMsg = serializeParseMessage(statementName, rewritten, forwardedMsg, queryNull);
                    }
                  }
                  queryStr = rewritten;
                }

              } catch (err) {
                const violationMsg = (err as Error).message;
                this.logSiemEvent('WAF_BLOCK', 8, originalUsername || 'guest', clientSocket.remoteAddress || '127.0.0.1', violationMsg);

                // Add to local ban list and broadcast to cluster if enabled
                const ipBanEnabled = (this.options.config as any)?.firewall?.ipBanning?.enabled;
                if (ipBanEnabled) {
                  const clientIp = clientSocket.remoteAddress || '127.0.0.1';
                  this.bannedIps.add(clientIp);
                  if (this.clusterManager) {
                    this.clusterManager.broadcast({
                      type: 'BAN_IP',
                      senderId: this.nodeId,
                      data: { ip: clientIp }
                    });
                  }
                }

                // Timing Attack Mitigation
                const minTime = this.options.minResponseTimeMs ?? 15;
                const elapsed = Date.now() - queryStartTime;
                if (elapsed < minTime) {
                  await new Promise(resolve => setTimeout(resolve, minTime - elapsed));
                }

                // Write standard PostgreSQL protocol error frame back to the client
                clientSocket.write(serializeErrorResponse(`Vollcrypt WAF Blocked: ${violationMsg}`));
                // Send ReadyForQuery ('Z') so client CLI / DBeaver doesn't hang
                const readyForQuery = Buffer.from([0x5a, 0, 0, 0, 5, 0x49]);
                clientSocket.write(readyForQuery);
                continue;
              }
            }

            backendSocket.write(forwardedMsg);
          }
        }
      } catch (err) {
        const errMsg = (err as Error).message;
        clientSocket.write(serializeErrorResponse(`Vollcrypt Proxy: ${errMsg}`));
        clientSocket.destroy();
      }
    });

    // Handle backend to client stream
    backendSocket.on('data', async (data) => {
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

            // Anomaly row rate limit check
            const now = Date.now();
            while (egressHistory.length > 0 && now - egressHistory[0].timestamp > 10000) {
              egressHistory.shift();
            }
            const totalEgress = egressHistory.reduce((sum, h) => sum + h.count, 0) + rowCount;
            if (totalEgress > 100) {
              this.logSiemEvent('ANOMALY_DETECTED', 7, originalUsername || 'guest', clientSocket.remoteAddress || '127.0.0.1', `High row egress volume anomaly detected (Total: ${totalEgress} rows in last 10s)`);
              // Throttling: introduce delay
              await new Promise(resolve => setTimeout(resolve, 50));
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
                const columnName = currentColumns[i] || `col_${i}`;
                const isAggregate = columnName.toLowerCase().startsWith('avg') || columnName.toLowerCase().startsWith('sum') || columnName.toLowerCase().startsWith('count');
                if (isAggregate) {
                  const floatVal = parseFloat(strVal);
                  if (!isNaN(floatVal)) {
                    const noise = generateLaplaceNoise(0.5);
                    const noisyVal = (floatVal + noise).toFixed(2);
                    modifiedValues.push(Buffer.from(noisyVal, 'utf8'));
                    continue;
                  }
                }

                // DLP Auto-PII scanning on unencrypted text cells
                if (!this.options.noDlp) {
                  const maskedVal = scanAndMaskCell(strVal);
                  if (maskedVal !== strVal) {
                    modifiedValues.push(Buffer.from(maskedVal, 'utf8'));
                  } else {
                    modifiedValues.push(val);
                  }
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
          } else if (type === 67 || type === 90) { // 'C' -> CommandComplete or 'Z' -> ReadyForQuery
            if (rowCount > 0) {
              egressHistory.push({ count: rowCount, timestamp: Date.now() });
            }
            if (type === 90) { // 'Z' -> ReadyForQuery
              const minTime = this.options.minResponseTimeMs ?? 15;
              const elapsed = Date.now() - queryStartTime;
              if (queryStartTime > 0 && elapsed < minTime) {
                await new Promise(resolve => setTimeout(resolve, minTime - elapsed));
              }
              queryStartTime = 0; // reset
            }
            clientSocket.write(msg);
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
