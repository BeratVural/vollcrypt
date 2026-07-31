import * as net from 'net';
import { Buffer } from 'buffer';
import * as fs from 'fs';
import * as crypto from 'crypto';
import * as tls from 'tls';
import selfsigned from 'selfsigned';
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
  parseCloseMessage,
  PgColumn,
  PgCloseMessage,
} from './pg-protocol.js';
import {
  resolveUserContext,
  getRbacConfig,
  ProxyConfig,
  ProxyUserContext,
  validateProxyDriverSecurityConfig,
} from './auth.js';
import {
  dbGuardContextStore,
  decryptValue,
  decryptWithSecurity,
  maskValue,
} from '@vollcrypt/db-guard';
import { validateQuery, generateFingerprint, evaluateThreatScore, rewriteQuery, generateLaplaceNoise, identifyAggregates } from './waf.js';
import { scanAndMaskCell } from './dlp.js';
import { reconstructKeyFromXorShares } from './mpc.js';
import { QueryAnomalyScorer } from './anomaly.js';

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
  noDlp?: boolean;
  noWaf?: boolean;
  noIpBanning?: boolean;
  dbType?: 'postgres' | 'mysql' | 'mongodb' | 'mssql' | 'oracle';
  fipsMode?: boolean;
  xorKeySplitShares?: Buffer[];
  xorKeySplitExpectedShares?: number;
  allowSingleProcessXorKeySplit?: true;
  tls?: {
    keyPath?: string;
    certPath?: string;
    allowEphemeralSelfSigned?: boolean;
  };
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

export class FipsStartupError extends Error {
  readonly code = 'ERR_FIPS_RUNTIME_INACTIVE';

  constructor() {
    super('FIPS mode was requested, but the active Node.js/OpenSSL runtime is not in FIPS mode');
    this.name = 'FipsStartupError';
  }
}

export function canonicalizeJson(value: unknown): string {
  const seen = new WeakSet<object>();

  const encode = (current: unknown): string => {
    if (
      current === null ||
      typeof current === 'string' ||
      typeof current === 'boolean' ||
      (typeof current === 'number' && Number.isFinite(current))
    ) {
      const encoded = JSON.stringify(current);
      if (encoded === undefined) throw new Error('Value cannot be represented as canonical JSON');
      return encoded;
    }

    if (Array.isArray(current)) {
      if (seen.has(current)) throw new Error('Canonical JSON does not support cyclic values');
      seen.add(current);
      const encoded = '[' + current.map((item) => encode(item)).join(',') + ']';
      seen.delete(current);
      return encoded;
    }

    if (typeof current === 'object') {
      const object = current as Record<string, unknown>;
      const prototype = Object.getPrototypeOf(object);
      if (prototype !== Object.prototype && prototype !== null) {
        throw new Error('Canonical JSON only supports plain objects');
      }
      if (seen.has(object)) throw new Error('Canonical JSON does not support cyclic values');
      seen.add(object);
      const entries = Object.keys(object).sort().map((key) => {
        if (object[key] === undefined) {
          throw new Error('Canonical JSON does not support undefined object values');
        }
        return JSON.stringify(key) + ':' + encode(object[key]);
      });
      seen.delete(object);
      return '{' + entries.join(',') + '}';
    }

    throw new Error('Value cannot be represented as canonical JSON');
  };

  return encode(value);
}

export interface ClusterMessage {
  type: 'HEARTBEAT' | 'BAN_IP' | 'ALLOWLIST_FP' | 'DECRYPTION_USAGE';
  senderId: string;
  data: any;
  timestamp?: number;
  signature?: string;
}

export class ClusterManager {
  private server: net.Server | null = null;
  private peerSockets = new Map<string, net.Socket>();
  private acceptedSignatures = new Map<string, number>();
  
  constructor(
    private nodeId: string,
    private gossipPort: number,
    private peers: string[],
    private gossipSecret: string,
    private onMessage: (msg: ClusterMessage) => void
  ) {}

  private signMessage(msg: Omit<ClusterMessage, 'signature'>): string {
    const payload = canonicalizeJson({
      type: msg.type,
      senderId: msg.senderId,
      data: msg.data,
      timestamp: msg.timestamp
    });
    return crypto.createHmac('sha256', this.gossipSecret).update(payload).digest('hex');
  }

  private verifyMessage(msg: ClusterMessage): boolean {
    if (
      typeof msg.signature !== 'string' ||
      !/^[0-9a-f]{64}$/i.test(msg.signature) ||
      !Number.isSafeInteger(msg.timestamp) ||
      typeof msg.senderId !== 'string'
    ) {
      return false;
    }

    const now = Date.now();
    if (Math.abs(now - msg.timestamp!) > 5000) return false;

    const unsignedMsg = {
      type: msg.type,
      senderId: msg.senderId,
      data: msg.data,
      timestamp: msg.timestamp
    };

    try {
      const expectedBuf = Buffer.from(this.signMessage(unsignedMsg), 'hex');
      const actualBuf = Buffer.from(msg.signature, 'hex');
      if (
        expectedBuf.length !== actualBuf.length ||
        !crypto.timingSafeEqual(expectedBuf, actualBuf)
      ) {
        return false;
      }

      for (const [key, expiresAt] of this.acceptedSignatures) {
        if (expiresAt <= now) this.acceptedSignatures.delete(key);
      }
      const replayKey = msg.senderId + ':' + msg.signature;
      if (this.acceptedSignatures.has(replayKey)) return false;
      this.acceptedSignatures.set(replayKey, now + 5000);
      return true;
    } catch {
      return false;
    }
  }

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
            if (this.verifyMessage(msg)) {
              this.onMessage(msg);
            }
          } catch (err) {
            // ignore malformed or unauthenticated messages
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
    if (!msg.timestamp) {
      msg.timestamp = Date.now();
    }
    if (!msg.signature) {
      msg.signature = this.signMessage(msg);
    }
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

function redactLogMessage(str: string): string {
  return str
    .replace(/--\s*JIT_TOKEN:\s*[^\s;]+/gi, '-- JIT_TOKEN:[REDACTED]')
    .replace(/VOLLVALT:[A-Za-z0-9+/=_\-:.]+/g, 'VOLLVALT:[REDACTED]')
    .replace(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi, '[REDACTED_EMAIL]')
    .replace(/'[^']*'/g, "'[REDACTED]'")
    .replace(/\b\d{12,19}\b/g, '[REDACTED_NUMBER]');
}

function sanitizeCef(str: string): string {
  return str.replace(/[\r\n]/g, ' ').replace(/\|/g, '\\|').replace(/\\/g, '\\\\');
}

interface PostgresConnectionRuntime {
  clientSocket: net.Socket;
  backendSocket: net.Socket;
  clientParser: PostgresStreamParser;
  backendParser: PostgresStreamParser;
  userContext: ProxyUserContext | null;
  originalUsername: string;
  dbGuardContext: {
    role: string;
    userId: string;
    tenantId?: string;
    maxDecryptionsPerSecond?: number;
    rateLimiterMode?: 'fail_closed' | 'warn' | 'disabled';
  };
  currentColumns: PgColumn[];
  currentAggregates: boolean[];
  isSslNegotiated: boolean;
  rowCount: number;
  bypassScanning: boolean;
  queryTimestamps: number[];
  egressHistory: { count: number; timestamp: number }[];
  queryStartTime: number;
  statements: Map<string, { query: string; columns?: PgColumn[]; aggregates?: boolean[] }>;
  portals: Map<string, { statementName: string; columns?: PgColumn[]; aggregates?: boolean[] }>;
  lastDescribeRequest: { type: string; name: string } | null;
  activeClientSocket: net.Socket | tls.TLSSocket;
  clientIp: string;
}
export class DbProxyServer {
  private server: net.Server | null = null;
  private activeConnections = new Set<net.Socket>();
  private socketTenantIds = new Map<net.Socket, string>();
  private allowlistedFingerprints = new Set<string>();

  private activeSsoSessions = new Map<string, { username: string; expiresAt: number; roles: string[] }>();
  private activeJitGrants = new Map<string, { role: string; expiresAt: number }>();
  private bannedIps = new Set<string>();
  private clusterManager: ClusterManager | null = null;
  private nodeId = Math.random().toString(36).substring(7);
  private gossipSecret: string = '';
  private jitSecret: string = '';
  private anomalyScorer = new QueryAnomalyScorer();

  private isClusterModeConfigured(): boolean {
    return this.options.gossipPort !== undefined || this.options.peers !== undefined;
  }

  public registerSsoSession(username: string, passcode: string, roles: string[], ttlMs: number = 900000) {
    if (this.isClusterModeConfigured()) {
      throw new Error('Cluster mode cannot use process-local SSO sessions; configure a distributed authorization service');
    }
    this.activeSsoSessions.set(passcode, {
      username,
      expiresAt: Date.now() + ttlMs,
      roles,
    });
  }

  public registerJitGrant(userId: string, role: string, durationMs: number) {
    if (this.isClusterModeConfigured()) {
      throw new Error('Cluster mode cannot use process-local JIT grants; configure a distributed authorization service');
    }
    this.activeJitGrants.set(userId, {
      role,
      expiresAt: Date.now() + durationMs,
    });
  }

  public logSiemEvent(event: string, severity: number, username: string, clientIp: string, message: string) {
    const timestamp = new Date().toISOString();
    const cleanIp = sanitizeCef(clientIp);
    const cleanUser = sanitizeCef(username);
    const cleanMsg = sanitizeCef(redactLogMessage(message));
    const cleanEvent = sanitizeCef(event);
    const cefStr = `CEF:0|Vollcrypt|DB-Proxy|1.0|${cleanEvent}|${cleanEvent}|${severity}|src=${cleanIp} usrName=${cleanUser} msg=${cleanMsg}\n`;
    try {
      if (!fs.existsSync('logs')) {
        fs.mkdirSync('logs');
      }
      fs.appendFileSync('logs/siem.cef', cefStr, 'utf8');
    } catch (err) {
      console.error('Failed to write SIEM CEF log:', err);
    }
  }

  public triggerFailClosed(tenantId?: string) {
    if (tenantId) {
      this.logSiemEvent('FAIL_CLOSED_TRIGGERED', 10, 'system', '127.0.0.1', `Tenant-scoped fail-closed triggered for tenant ${tenantId}. Closing only matching active connections.`);
      for (const socket of Array.from(this.activeConnections)) {
        if (this.socketTenantIds.get(socket) === tenantId) {
          socket.destroy();
          this.activeConnections.delete(socket);
          this.socketTenantIds.delete(socket);
        }
      }
      return;
    }

    this.logSiemEvent('FAIL_CLOSED_TRIGGERED', 10, 'system', '127.0.0.1', 'Global fail-closed triggered. Zeroizing keys and shutting down all active connections.');
    for (const key of Object.values(this.options.resolvedKeys)) {
      key.fill(0);
    }
    for (const socket of this.activeConnections) {
      socket.destroy();
    }
    this.activeConnections.clear();
    this.socketTenantIds.clear();
  }

  private sslKey: string = '';
  private sslCert: string = '';

  constructor(private options: DbProxyOptions) {
    validateProxyDriverSecurityConfig(this.options.dbType || 'postgres', this.options.config);
    this.loadAllowlist();
    // Clone resolvedKeys to prevent mutating/zeroizing references shared by the caller (e.g. tests)
    const clonedKeys: Record<string, Buffer> = {};
    if (options.resolvedKeys) {
      for (const [k, v] of Object.entries(options.resolvedKeys)) {
        clonedKeys[k] = Buffer.from(v);
      }
    }
    this.options.resolvedKeys = clonedKeys;
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
    if (this.options.fipsMode) {
      let fipsActive = false;
      try {
        fipsActive = typeof crypto.getFips === 'function' && crypto.getFips() === 1;
      } catch {
        fipsActive = false;
      }
      if (!fipsActive) {
        throw new FipsStartupError();
      }
      this.logSiemEvent(
        'FIPS_INIT',
        1,
        'system',
        '127.0.0.1',
        'Node.js/OpenSSL FIPS mode is active. Deployment validation remains the operator responsibility.'
      );
    }

    if (this.options.xorKeySplitShares !== undefined) {
      if (this.options.allowSingleProcessXorKeySplit !== true) {
        throw new Error(
          'Single-process XOR key split is n-of-n compatibility behavior, not MPC; explicit acknowledgement is required'
        );
      }
      const reconstructedKey = reconstructKeyFromXorShares(
        this.options.xorKeySplitShares,
        this.options.xorKeySplitExpectedShares as number
      );
      this.options.resolvedKeys['1']?.fill(0);
      this.options.resolvedKeys['1'] = reconstructedKey;
      this.logSiemEvent(
        'XOR_KEY_SPLIT_INIT',
        1,
        'system',
        '127.0.0.1',
        'Decryption key reconstructed from the explicitly configured number of single-process n-of-n XOR shares.'
      );
    }

    const tlsConfig = this.options.tls;
    if ((tlsConfig?.keyPath && !tlsConfig.certPath) || (!tlsConfig?.keyPath && tlsConfig?.certPath)) {
      throw new Error('TLS requires both tls.keyPath and tls.certPath');
    }
    if (tlsConfig?.keyPath && tlsConfig.certPath) {
      this.sslKey = fs.readFileSync(tlsConfig.keyPath, 'utf8');
      this.sslCert = fs.readFileSync(tlsConfig.certPath, 'utf8');
      tls.createSecureContext({ key: this.sslKey, cert: this.sslCert });
    } else if (tlsConfig?.allowEphemeralSelfSigned === true) {
      const attrs = [{ name: 'commonName', value: 'localhost' }];
      const pems = await selfsigned.generate(attrs);
      this.sslKey = pems.private;
      this.sslCert = pems.cert;
    } else {
      this.sslKey = '';
      this.sslCert = '';
    }

    const configuredGossipSecret = this.options.config?.firewall?.gossipSecret;
    const configuredJitSecret = this.options.config?.firewall?.jitSecret;
    const clusteringConfigured = this.isClusterModeConfigured();
    if (clusteringConfigured) {
      if (!this.options.gossipPort || !this.options.peers) {
        throw new Error('Cluster mode requires both gossipPort and peers');
      }
      if (!configuredGossipSecret || configuredGossipSecret.length < 32) {
        throw new Error('Cluster mode requires firewall.gossipSecret with at least 32 characters');
      }
      const processLocalControls: string[] = [];
      if (this.options.config?.firewall?.jitApprovalRequired) {
        processLocalControls.push('firewall.jitApprovalRequired');
      }
      if (this.options.config?.firewall?.rateLimits?.maxQueriesPerSecond !== undefined) {
        processLocalControls.push('firewall.rateLimits.maxQueriesPerSecond');
      }
      if (this.options.config?.rateLimiter?.maxDecryptionsPerSecond !== undefined) {
        processLocalControls.push('rateLimiter.maxDecryptionsPerSecond');
      }
      if (processLocalControls.length > 0) {
        throw new Error(
          `Cluster mode rejects process-local security controls: ${processLocalControls.join(', ')}. Configure a distributed authorization and rate-limit service`
        );
      }
    }
    if (configuredGossipSecret && configuredJitSecret && configuredGossipSecret === configuredJitSecret) {
      throw new Error('firewall.gossipSecret and firewall.jitSecret must be distinct secrets');
    }
    this.gossipSecret = configuredGossipSecret || crypto.randomBytes(32).toString('hex');
    this.jitSecret = configuredJitSecret || crypto.randomBytes(32).toString('hex');

    if (this.options.gossipPort && this.options.peers) {
      this.clusterManager = new ClusterManager(
        this.nodeId,
        this.options.gossipPort,
        this.options.peers,
        this.gossipSecret,
        (msg) => this.handleClusterMessage(msg)
      );
      await this.clusterManager.start();
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
              config: this.options.config,
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
              config: this.options.config,
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
              config: this.options.config,
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
              config: this.options.config,
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
      this.socketTenantIds.clear();

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
    const runtime = this.createPostgresConnectionRuntime(clientSocket);
    this.attachPostgresClientListeners(runtime, clientSocket);
    this.attachPostgresBackendListeners(runtime);
  }

  private createPostgresConnectionRuntime(clientSocket: net.Socket): PostgresConnectionRuntime {
    this.activeConnections.add(clientSocket);
    const backendSocket = net.connect({
      host: this.options.dbHost,
      port: this.options.dbPort,
    });

    return {
      clientSocket,
      backendSocket,
      clientParser: new PostgresStreamParser(),
      backendParser: new PostgresStreamParser(),
      userContext: null,
      originalUsername: '',
      dbGuardContext: {
        role: 'GUEST',
        userId: 'guest-user',
        maxDecryptionsPerSecond: this.options.config?.rateLimiter?.maxDecryptionsPerSecond,
        rateLimiterMode: this.options.config?.rateLimiter?.mode,
      },
      currentColumns: [],
      currentAggregates: [],
      isSslNegotiated: false,
      rowCount: 0,
      bypassScanning: false,
      queryTimestamps: [],
      egressHistory: [],
      queryStartTime: 0,
      statements: new Map(),
      portals: new Map(),
      lastDescribeRequest: null,
      activeClientSocket: clientSocket,
      clientIp: clientSocket.remoteAddress || '127.0.0.1',
    };
  }

  private attachPostgresClientListeners(
    runtime: PostgresConnectionRuntime,
    socket: net.Socket | tls.TLSSocket
  ) {
    socket.on('data', async (data) => {
      try {
        const messages = runtime.clientParser.append(data);
        for (const msg of messages) {
          let forwardedMsg = msg;

          if (!runtime.userContext) {
            // Check if it is an SSLRequest (8 bytes, second 4 bytes code: 80877103)
            if (forwardedMsg.length === 8 && forwardedMsg.readInt32BE(4) === 80877103) {
              if (!this.sslKey || !this.sslCert) {
                socket.write(Buffer.from('N', 'ascii'));
                continue;
              }
              runtime.isSslNegotiated = true;
              socket.write(Buffer.from('S', 'ascii'));

              // Upgrade socket to TLS
              const secureContext = tls.createSecureContext({
                key: this.sslKey,
                cert: this.sslCert,
              });
              const tlsSocket = new tls.TLSSocket(runtime.clientSocket, {
                isServer: true,
                secureContext: secureContext,
              });

              // Remove plain listeners
              socket.removeAllListeners('data');
              socket.removeAllListeners('end');
              socket.removeAllListeners('close');
              socket.removeAllListeners('error');

              runtime.activeClientSocket = tlsSocket;
              this.activeConnections.add(tlsSocket);
              const existingTenantId = this.socketTenantIds.get(runtime.clientSocket);
              if (existingTenantId) {
                this.socketTenantIds.set(tlsSocket, existingTenantId);
              }
              this.activeConnections.delete(runtime.clientSocket);
              this.socketTenantIds.delete(runtime.clientSocket);

              this.attachPostgresClientListeners(runtime, tlsSocket);
              return;
            }

            // Otherwise, it must be the StartupMessage
            const params = parseStartupMessage(forwardedMsg);
            const username = params.user || 'guest';
            runtime.originalUsername = username;
            runtime.userContext = resolveUserContext(username, this.options.config);
            runtime.dbGuardContext.role = runtime.userContext.role;
            runtime.dbGuardContext.userId = runtime.userContext.userId;
            runtime.dbGuardContext.tenantId = runtime.userContext.tenantId;
            if (runtime.userContext.tenantId) {
              this.socketTenantIds.set(runtime.activeClientSocket, runtime.userContext.tenantId);
            }

            runtime.backendSocket.write(forwardedMsg);
          } else {
            // WAF Validation and Prepared Statement tracking
            const type = forwardedMsg[0];
            let queryStr: string | null = null;

            if (type === 67) { // 'C' (Close)
              const closeMsg = parseCloseMessage(forwardedMsg);
              if (closeMsg) {
                if (closeMsg.type === 'S') {
                  runtime.statements.delete(closeMsg.name);
                } else if (closeMsg.type === 'P') {
                  runtime.portals.delete(closeMsg.name);
                }
              }
            }

            if (type === 112) { // 'p' (PasswordMessage)
              const password = forwardedMsg.toString('utf8', 5, forwardedMsg.length - 1);
              const ssoSession = this.activeSsoSessions.get(password);
              if (ssoSession && ssoSession.expiresAt > Date.now()) {
                runtime.userContext = {
                  userId: `usr-sso-${ssoSession.username}`,
                  role: ssoSession.roles[0] || 'GUEST',
                };
                runtime.dbGuardContext.role = runtime.userContext.role;
                runtime.dbGuardContext.userId = runtime.userContext.userId;
                runtime.dbGuardContext.tenantId = runtime.userContext.tenantId;
                if (runtime.userContext.tenantId) {
                  this.socketTenantIds.set(runtime.activeClientSocket, runtime.userContext.tenantId);
                }

                const realDbPassword = this.options.dbPassword || 'postgres';
                const newMsg = serializePasswordMessage(realDbPassword);
                runtime.backendSocket.write(newMsg);
                continue;
              } else {
                runtime.backendSocket.write(forwardedMsg);
                continue;
              }
            }

            if (type === 81) { // 'Q' (Simple Query)
              runtime.queryStartTime = Date.now();
              queryStr = forwardedMsg.subarray(5, forwardedMsg.length - 1).toString('utf8');

              runtime.currentColumns = []; // Reset simple query schema state
              runtime.currentAggregates = identifyAggregates(queryStr);
              runtime.rowCount = 0;
              runtime.bypassScanning = false;
            } else if (type === 80) { // 'P' (Parse prepared statement)
              runtime.queryStartTime = Date.now();
              const destNameNull = forwardedMsg.indexOf(0, 5);
              if (destNameNull !== -1) {
                const statementName = forwardedMsg.toString('utf8', 5, destNameNull);
                const queryStart = destNameNull + 1;
                const queryNull = forwardedMsg.indexOf(0, queryStart);
                if (queryNull !== -1) {
                  queryStr = forwardedMsg.toString('utf8', queryStart, queryNull);
                  runtime.statements.set(statementName, {
                    query: queryStr,
                    aggregates: identifyAggregates(queryStr)
                  });
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
                  const stmt = runtime.statements.get(statementName);
                  runtime.portals.set(portalName, {
                    statementName,
                    columns: stmt?.columns,
                    aggregates: stmt?.aggregates,
                  });
                }
              }
            } else if (type === 68) { // 'D' (Describe)
              if (forwardedMsg.length >= 7) {
                const descType = String.fromCharCode(forwardedMsg[5]);
                const nameNull = forwardedMsg.indexOf(0, 6);
                if (nameNull !== -1) {
                  const name = forwardedMsg.toString('utf8', 6, nameNull);
                  runtime.lastDescribeRequest = { type: descType, name };
                  if (descType === 'p') {
                    const portal = runtime.portals.get(name);
                    if (portal) {
                      runtime.currentColumns = portal.columns || [];
                      runtime.currentAggregates = portal.aggregates || [];
                    }
                  }
                }
              }
            } else if (type === 69) { // 'E' (Execute)
              runtime.rowCount = 0;
              runtime.bypassScanning = false;
              const portalNull = forwardedMsg.indexOf(0, 5);
              if (portalNull !== -1) {
                const portalName = forwardedMsg.toString('utf8', 5, portalNull);
                const portal = runtime.portals.get(portalName);
                if (portal) {
                  if (portal.columns) runtime.currentColumns = portal.columns;
                  if (portal.aggregates) runtime.currentAggregates = portal.aggregates;
                }
              }
            }

            if (queryStr) {
              try {
                // 0. Dynamic JIT evaluation
                const activeJit = this.activeJitGrants.get(runtime.dbGuardContext.userId);
                if (activeJit) {
                  if (activeJit.expiresAt > Date.now()) {
                    runtime.dbGuardContext.role = activeJit.role;
                  } else {
                    const originalContext = resolveUserContext(runtime.originalUsername, this.options.config);
                    runtime.dbGuardContext.role = originalContext.role;
                  }
                }

                // JIT Temporary Access Approval Webhook Simulation
                if (this.options.config?.firewall?.jitApprovalRequired && runtime.dbGuardContext.role !== 'OWNER') {
                  const hasActiveGrant = activeJit && activeJit.expiresAt > Date.now();
                  if (!hasActiveGrant) {
                    this.logSiemEvent('JIT_REQUESTED', 6, runtime.dbGuardContext.userId, runtime.clientIp || '127.0.0.1', `JIT request triggered for query: ${queryStr}`);
                    let approved = false;

                    // 1. Signed JIT Token flow
                    const tokenMatch = queryStr.match(/--\s*JIT_TOKEN:\s*([^\s;]+)/i);
                    if (tokenMatch) {
                      const token = tokenMatch[1];
                      const parts = token.split(':');
                      if (parts.length === 3) {
                        const [tUserId, tExpiresAtStr, tSig] = parts;
                        const tExpiresAt = parseInt(tExpiresAtStr, 10);
                        if (tUserId === runtime.dbGuardContext.userId && tExpiresAt > Date.now()) {
                          const secret = this.jitSecret;
                          const expectedSig = crypto
                            .createHmac('sha256', secret)
                            .update(`${tUserId}:${tExpiresAt}`)
                            .digest('hex');
                          const expectedSigBuf = Buffer.from(expectedSig, 'hex');
                          const tokenSigBuf = Buffer.from(tSig, 'hex');
                          if (expectedSigBuf.length === tokenSigBuf.length && crypto.timingSafeEqual(expectedSigBuf, tokenSigBuf)) {
                            approved = true;
                            this.registerJitGrant(runtime.dbGuardContext.userId, 'OWNER', 3600000);
                            this.logSiemEvent('JIT_APPROVED', 6, 'system', '127.0.0.1', `JIT request approved for user ${runtime.dbGuardContext.userId} via cryptographically signed token`);
                            runtime.dbGuardContext.role = 'OWNER';
                          }
                        }
                      }
                    }

                    // 2. Webhook JIT Approval flow
                    if (!approved && this.options.config?.firewall?.jitWebhookUrl) {
                      const webhookUrl = this.options.config.firewall.jitWebhookUrl;
                      try {
                        const response = await fetch(webhookUrl, {
                          method: 'POST',
                          headers: { 'Content-Type': 'application/json' },
                          body: JSON.stringify({ userId: runtime.dbGuardContext.userId, role: 'OWNER', query: queryStr }),
                        });
                        if (response.ok) {
                          const body = await response.json();
                          if (body.approved) {
                            approved = true;
                            this.registerJitGrant(runtime.dbGuardContext.userId, 'OWNER', 3600000);
                            this.logSiemEvent('JIT_APPROVED', 6, 'system', '127.0.0.1', `JIT request approved for user ${runtime.dbGuardContext.userId} via webhook simulation`);
                            runtime.dbGuardContext.role = 'OWNER';
                          }
                        }
                      } catch (err) {
                        console.error('JIT webhook connection error:', err);
                      }
                    }

                    if (!approved) {
                      this.logSiemEvent('JIT_DENIED', 8, runtime.dbGuardContext.userId, runtime.clientIp || '127.0.0.1', `JIT request denied for query: ${queryStr}`);
                      throw new Error('JIT approval request denied: user is not in the approved JIT registry or webhook/token approval failed');
                    }
                  }
                }

                // Persistent per-user statistical query anomaly scoring
                if (this.options.config?.firewall?.anomalyEngine?.enabled) {
                  const baselineQueries = this.options.config?.firewall?.anomalyEngine?.baselineQueries || [
                    'SELECT * FROM users WHERE id = 1',
                    'SELECT id, username FROM users',
                    'SELECT email FROM users WHERE role = ?',
                  ];
                  if (!this.anomalyScorer.hasBaseline(runtime.dbGuardContext.userId)) {
                    this.anomalyScorer.learnBaseline(runtime.dbGuardContext.userId, baselineQueries);
                  }
                  const score = this.anomalyScorer.getAnomalyScore(runtime.dbGuardContext.userId, queryStr);
                  if (score > 0.7) {
                    this.logSiemEvent('ANOMALY_THREAT_DETECTION', 8, runtime.dbGuardContext.userId, socket.remoteAddress || '127.0.0.1', `Statistical query anomaly detected with threat score ${score.toFixed(2)}: ${queryStr}`);
                    throw new Error(`Query blocked by statistical anomaly detection (Score: ${score.toFixed(2)})`);
                  }
                }

                // 1. Rate limiting per connection
                const nowMs = Date.now();
                while (runtime.queryTimestamps.length > 0 && nowMs - runtime.queryTimestamps[0] > 1000) {
                  runtime.queryTimestamps.shift();
                }
                const maxQps = this.options.config?.firewall?.rateLimits?.maxQueriesPerSecond;
                if (maxQps && runtime.queryTimestamps.length >= maxQps) {
                  throw new Error(`Connection query rate limit exceeded (Limit: ${maxQps}/sec)`);
                }
                runtime.queryTimestamps.push(nowMs);

                // 2. Temporal constraints per role
                const constraints = this.options.config?.firewall?.temporalConstraints?.[runtime.dbGuardContext.role];
                if (constraints) {
                  const now = new Date();
                  const currentHour = now.getHours();
                  const currentDay = now.getDay();
                  if (!constraints.allowedDays.includes(currentDay) || currentHour < constraints.startHour || currentHour >= constraints.endHour) {
                    throw new Error(`Temporal access restriction. Role "${runtime.dbGuardContext.role}" is not permitted to query database at this time.`);
                  }
                }

                // 3. WAF signature & DDL checks
                if (!this.options.noWaf) {
                  validateQuery(queryStr, runtime.dbGuardContext.role);

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
                const rewritten = rewriteQuery(queryStr, runtime.dbGuardContext.role, runtime.userContext?.tenantId, this.options.config);
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
                this.logSiemEvent('WAF_BLOCK', 8, runtime.originalUsername || 'guest', socket.remoteAddress || '127.0.0.1', violationMsg);

                // Add to local ban list and broadcast to cluster if enabled
                const ipBanEnabled = (this.options.config as any)?.firewall?.ipBanning?.enabled;
                if (ipBanEnabled) {
                  const bannedClientIp = socket.remoteAddress || '127.0.0.1';
                  this.bannedIps.add(bannedClientIp);
                  if (this.clusterManager) {
                    this.clusterManager.broadcast({
                      type: 'BAN_IP',
                      senderId: this.nodeId,
                      data: { ip: bannedClientIp }
                    });
                  }
                }

                // Timing Attack Mitigation
                const minTime = this.options.minResponseTimeMs ?? 15;
                const elapsed = Date.now() - runtime.queryStartTime;
                if (elapsed < minTime) {
                  await new Promise(resolve => setTimeout(resolve, minTime - elapsed));
                }

                // Write standard PostgreSQL protocol error frame back to the client
                socket.write(serializeErrorResponse(`Vollcrypt WAF Blocked: ${violationMsg}`));
                // Send ReadyForQuery ('Z') so client CLI / DBeaver doesn't hang
                const readyForQuery = Buffer.from([0x5a, 0, 0, 0, 5, 0x49]);
                socket.write(readyForQuery);
                continue;
              }
            }

            runtime.backendSocket.write(forwardedMsg);
          }
        }
      } catch (err) {
        const errMsg = (err as Error).message;
        socket.write(serializeErrorResponse(`Vollcrypt Proxy: ${errMsg}`));
        socket.destroy();
      }
    });

    socket.on('close', () => {
      this.activeConnections.delete(socket);
      this.socketTenantIds.delete(socket);
      if (socket !== runtime.clientSocket) {
        this.activeConnections.delete(runtime.clientSocket);
        this.socketTenantIds.delete(runtime.clientSocket);
        runtime.clientSocket.destroy();
      }
      runtime.backendSocket.destroy();
    });

    socket.on('error', () => {
      runtime.backendSocket.destroy();
    });
  }

  private attachPostgresBackendListeners(runtime: PostgresConnectionRuntime) {
    runtime.backendSocket.on('data', async (data) => {
      try {
        const messages = runtime.backendParser.append(data);
        for (const msg of messages) {
          const type = msg[0];

          if (type === 84) { // 'T' -> RowDescription
            runtime.currentColumns = parseRowDescription(msg);
            
            const sensitiveKeywords = ['credit_card', 'email', 'tc_no', 'phone', 'iban', 'cc', 'ssn', 'salary', 'password', 'secret'];
            const hasSensitive = runtime.currentColumns.some(col => {
              const colLower = col.name.toLowerCase();
              return sensitiveKeywords.some(kw => colLower.includes(kw));
            });
            const hasAggregate = runtime.currentAggregates.some(agg => agg === true);
            runtime.bypassScanning = !hasSensitive && !hasAggregate;

            // Map the parsed description to the active prepared statement or portal
            if (runtime.lastDescribeRequest) {
              if (runtime.lastDescribeRequest.type === 'S') {
                const stmt = runtime.statements.get(runtime.lastDescribeRequest.name);
                if (stmt) {
                  stmt.columns = runtime.currentColumns;
                }
              } else if (runtime.lastDescribeRequest.type === 'P') {
                const portal = runtime.portals.get(runtime.lastDescribeRequest.name);
                if (portal) {
                  portal.columns = runtime.currentColumns;
                }
              }
            }
            runtime.activeClientSocket.write(msg);
          } else if (type === 68) { // 'D' -> DataRow
            runtime.rowCount++;
            const maxRows = this.options.config?.firewall?.maxRowsPerQuery || 5000;
            if (runtime.rowCount > maxRows) {
              runtime.activeClientSocket.write(serializeErrorResponse(`Vollcrypt WAF Blocked: Mass exfiltration limit exceeded (Limit: ${maxRows})`));
              runtime.activeClientSocket.destroy();
              runtime.backendSocket.destroy();
              break;
            }

            // Anomaly row rate limit check
            const now = Date.now();
            while (runtime.egressHistory.length > 0 && now - runtime.egressHistory[0].timestamp > 10000) {
              runtime.egressHistory.shift();
            }
            const totalEgress = runtime.egressHistory.reduce((sum, h) => sum + h.count, 0) + runtime.rowCount;
            if (totalEgress > 100) {
              this.logSiemEvent('ANOMALY_DETECTED', 7, runtime.originalUsername || 'guest', runtime.activeClientSocket.remoteAddress || '127.0.0.1', `High row egress volume anomaly detected (Total: ${totalEgress} rows in last 10s)`);
              // Throttling: introduce delay
              await new Promise(resolve => setTimeout(resolve, 50));
            }

            if (runtime.bypassScanning) {
              if (!msg.includes('VOLLVALT:')) {
                runtime.activeClientSocket.write(msg);
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
                const columnName = runtime.currentColumns[i] ? runtime.currentColumns[i].name : `col_${i}`;
                try {
                  // Decrypt using security controls inside user context store
                  const decrypted = dbGuardContextStore.run(
                    runtime.dbGuardContext,
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
                const columnName = runtime.currentColumns[i] ? runtime.currentColumns[i].name : `col_${i}`;
                const rbacConfig = getRbacConfig(this.options.config);
                const roleConfig = runtime.dbGuardContext.role ? rbacConfig?.roles?.[runtime.dbGuardContext.role] : undefined;
                let modelName = 'users';
                let fieldName = columnName;
                if (columnName.includes('.')) {
                  const parts = columnName.split('.');
                  modelName = parts[0];
                  fieldName = parts[1];
                }
                const fieldKey = `${modelName}.${fieldName}`;
                const maskRule = roleConfig?.mask?.[fieldKey];
                if (maskRule !== undefined) {
                  const maskedVal = maskValue(strVal, maskRule);
                  modifiedValues.push(Buffer.from(maskedVal, 'utf8'));
                  continue;
                }

                const isAggregate = runtime.currentAggregates[i] === true || (runtime.currentAggregates[i] === undefined && (columnName.toLowerCase().startsWith('avg') || columnName.toLowerCase().startsWith('sum') || columnName.toLowerCase().startsWith('count')));
                if (isAggregate) {
                  const colMeta = runtime.currentColumns[i];
                  const isBinary = colMeta && colMeta.formatCode === 1;
                  const oid = colMeta ? colMeta.dataTypeOid : 0;
                  
                  let floatVal = NaN;
                  if (isBinary) {
                    try {
                      if (oid === 23) {
                        floatVal = val.readInt32BE(0);
                      } else if (oid === 21) {
                        floatVal = val.readInt16BE(0);
                      } else if (oid === 20) {
                        floatVal = Number(val.readBigInt64BE(0));
                      } else if (oid === 700) {
                        floatVal = val.readFloatBE(0);
                      } else if (oid === 701) {
                        floatVal = val.readDoubleBE(0);
                      }
                    } catch (e) {
                      floatVal = NaN;
                    }
                  } else {
                    floatVal = parseFloat(strVal);
                  }

                  if (!isNaN(floatVal)) {
                    const noise = generateLaplaceNoise(0.5);
                    const noisyVal = floatVal + noise;
                    if (isBinary) {
                      let noisyBuf: Buffer;
                      if (oid === 20) {
                        noisyBuf = Buffer.alloc(8);
                        noisyBuf.writeBigInt64BE(BigInt(Math.round(noisyVal)), 0);
                      } else if (oid === 21) {
                        noisyBuf = Buffer.alloc(2);
                        noisyBuf.writeInt16BE(Math.round(noisyVal), 0);
                      } else if (oid === 700) {
                        noisyBuf = Buffer.alloc(4);
                        noisyBuf.writeFloatBE(noisyVal, 0);
                      } else if (oid === 701) {
                        noisyBuf = Buffer.alloc(8);
                        noisyBuf.writeDoubleBE(noisyVal, 0);
                      } else {
                        noisyBuf = Buffer.alloc(4);
                        noisyBuf.writeInt32BE(Math.round(noisyVal), 0);
                      }
                      modifiedValues.push(noisyBuf);
                    } else {
                      modifiedValues.push(Buffer.from(noisyVal.toFixed(2), 'utf8'));
                    }
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
              runtime.activeClientSocket.write(serializeErrorResponse(`Vollcrypt Cryptographic Access Violation: ${encryptionError.message}`));
              const isRateLimit = encryptionError.message.includes('rate limit') || encryptionError.message.includes('Fail-Closed');
              if (isRateLimit) {
                const rateLimiterMode = this.options.config?.rateLimiter?.mode || 'fail_closed';
                if (rateLimiterMode === 'fail_closed') {
                  this.triggerFailClosed(runtime.userContext?.tenantId);
                }
              }
              // End the packet flow for this stream
              break;
            } else {
              const newMsg = serializeDataRow(modifiedValues);
              runtime.activeClientSocket.write(newMsg);
            }
          } else if (type === 67 || type === 90) { // 'C' -> CommandComplete or 'Z' -> ReadyForQuery
            if (runtime.rowCount > 0) {
              runtime.egressHistory.push({ count: runtime.rowCount, timestamp: Date.now() });
            }
            if (type === 90) { // 'Z' -> ReadyForQuery
              const minTime = this.options.minResponseTimeMs ?? 15;
              const elapsed = Date.now() - runtime.queryStartTime;
              if (runtime.queryStartTime > 0 && elapsed < minTime) {
                await new Promise(resolve => setTimeout(resolve, minTime - elapsed));
              }
              runtime.queryStartTime = 0; // reset
            }
            runtime.activeClientSocket.write(msg);
          } else if (type === 83) { // 'S' -> ParameterStatus
            const status = parseParameterStatus(msg);
            if (status && status.name === 'server_version') {
              const maskedVersion = this.options.config?.firewall?.versionMask || '16.0';
              const newMsg = serializeParameterStatus('server_version', maskedVersion);
              runtime.activeClientSocket.write(newMsg);
            } else {
              runtime.activeClientSocket.write(msg);
            }
          } else {
            runtime.activeClientSocket.write(msg);
          }
        }
      } catch (err) {
        const errMsg = (err as Error).message;
        runtime.activeClientSocket.write(serializeErrorResponse(`Vollcrypt Proxy: ${errMsg}`));
        runtime.activeClientSocket.destroy();
      }
    });

    runtime.backendSocket.on('close', () => {
      runtime.activeClientSocket.destroy();
    });

    runtime.backendSocket.on('error', () => {
      runtime.activeClientSocket.destroy();
    });
  }
}










