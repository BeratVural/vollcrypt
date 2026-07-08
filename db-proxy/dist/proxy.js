"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.DbProxyServer = exports.ClusterManager = void 0;
exports.serializeErrorResponse = serializeErrorResponse;
exports.buildRowDescription = buildRowDescription;
const net = __importStar(require("net"));
const buffer_1 = require("buffer");
const fs = __importStar(require("fs"));
const crypto = __importStar(require("crypto"));
const tls = __importStar(require("tls"));
const selfsigned_1 = __importDefault(require("selfsigned"));
const pg_protocol_js_1 = require("./pg-protocol.js");
const auth_js_1 = require("./auth.js");
const db_guard_1 = require("@vollcrypt/db-guard");
const waf_js_1 = require("./waf.js");
const dlp_js_1 = require("./dlp.js");
/**
 * Serializes a PostgreSQL protocol ErrorResponse ('E') message.
 */
function serializeErrorResponse(message, code = '42501') {
    const fields = [
        { type: 'S', value: 'ERROR' },
        { type: 'C', value: code },
        { type: 'M', value: message },
    ];
    let totalSize = 0;
    for (const f of fields) {
        totalSize += 1 + buffer_1.Buffer.byteLength(f.value, 'utf8') + 1;
    }
    totalSize += 1; // final null byte
    const msgLen = 4 + totalSize;
    const buf = buffer_1.Buffer.alloc(1 + msgLen);
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
function buildRowDescription(columns) {
    let totalSize = 0;
    for (const col of columns) {
        totalSize += buffer_1.Buffer.byteLength(col, 'utf8') + 1 + 4 + 2 + 4 + 2 + 4 + 2;
    }
    const msgLen = 4 + 2 + totalSize;
    const buf = buffer_1.Buffer.alloc(1 + msgLen);
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
class ClusterManager {
    nodeId;
    gossipPort;
    peers;
    gossipSecret;
    onMessage;
    server = null;
    peerSockets = new Map();
    constructor(nodeId, gossipPort, peers, gossipSecret, onMessage) {
        this.nodeId = nodeId;
        this.gossipPort = gossipPort;
        this.peers = peers;
        this.gossipSecret = gossipSecret;
        this.onMessage = onMessage;
    }
    signMessage(msg) {
        const payload = JSON.stringify({
            type: msg.type,
            senderId: msg.senderId,
            data: msg.data,
            timestamp: msg.timestamp
        });
        return crypto.createHmac('sha256', this.gossipSecret).update(payload).digest('hex');
    }
    verifyMessage(msg) {
        if (!msg.signature || !msg.timestamp)
            return false;
        // Replay protection: check if timestamp is within 5 seconds
        const age = Math.abs(Date.now() - msg.timestamp);
        if (age > 5000)
            return false;
        const unsignedMsg = {
            type: msg.type,
            senderId: msg.senderId,
            data: msg.data,
            timestamp: msg.timestamp
        };
        const expectedSignature = this.signMessage(unsignedMsg);
        try {
            const expectedBuf = buffer_1.Buffer.from(expectedSignature, 'hex');
            const actualBuf = buffer_1.Buffer.from(msg.signature, 'hex');
            if (expectedBuf.length !== actualBuf.length)
                return false;
            return crypto.timingSafeEqual(expectedBuf, actualBuf);
        }
        catch (err) {
            return false;
        }
    }
    async start() {
        if (!this.gossipPort)
            return;
        this.server = net.createServer((socket) => {
            let buffer = buffer_1.Buffer.alloc(0);
            socket.on('data', (data) => {
                buffer = buffer_1.Buffer.concat([buffer, data]);
                while (true) {
                    const newlineIdx = buffer.indexOf('\n');
                    if (newlineIdx === -1)
                        break;
                    const line = buffer.subarray(0, newlineIdx).toString('utf8');
                    buffer = buffer.subarray(newlineIdx + 1);
                    try {
                        const msg = JSON.parse(line);
                        if (this.verifyMessage(msg)) {
                            this.onMessage(msg);
                        }
                    }
                    catch (err) {
                        // ignore malformed or unauthenticated messages
                    }
                }
            });
            socket.on('error', () => { });
        });
        return new Promise((resolve, reject) => {
            this.server.listen(this.gossipPort, () => {
                this.startHeartbeatLoop();
                resolve();
            });
            this.server.on('error', (err) => reject(err));
        });
    }
    startHeartbeatLoop() {
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
    broadcast(msg) {
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
            if (port === this.gossipPort)
                continue;
            let client = this.peerSockets.get(peer);
            if (!client || client.destroyed) {
                client = net.connect({ host, port }, () => {
                    client.write(payload);
                });
                client.on('error', () => { });
                this.peerSockets.set(peer, client);
            }
            else {
                try {
                    client.write(payload);
                }
                catch (err) {
                    // peer disconnected, will reconnect next time
                }
            }
        }
    }
    stop() {
        if (this.server) {
            this.server.close();
        }
        for (const socket of this.peerSockets.values()) {
            socket.destroy();
        }
        this.peerSockets.clear();
    }
}
exports.ClusterManager = ClusterManager;
function sanitizeCef(str) {
    return str.replace(/[\r\n]/g, ' ').replace(/\|/g, '\\|').replace(/\\/g, '\\\\');
}
class DbProxyServer {
    options;
    server = null;
    activeConnections = new Set();
    allowlistedFingerprints = new Set();
    activeSsoSessions = new Map();
    activeJitGrants = new Map();
    bannedIps = new Set();
    clusterManager = null;
    nodeId = Math.random().toString(36).substring(7);
    gossipSecret = '';
    jitSecret = '';
    registerSsoSession(username, passcode, roles, ttlMs = 900000) {
        this.activeSsoSessions.set(passcode, {
            username,
            expiresAt: Date.now() + ttlMs,
            roles,
        });
    }
    registerJitGrant(userId, role, durationMs) {
        this.activeJitGrants.set(userId, {
            role,
            expiresAt: Date.now() + durationMs,
        });
    }
    logSiemEvent(event, severity, username, clientIp, message) {
        const timestamp = new Date().toISOString();
        const cleanIp = sanitizeCef(clientIp);
        const cleanUser = sanitizeCef(username);
        const cleanMsg = sanitizeCef(message);
        const cleanEvent = sanitizeCef(event);
        const cefStr = `CEF:0|Vollcrypt|DB-Proxy|1.0|${cleanEvent}|${cleanEvent}|${severity}|src=${cleanIp} usrName=${cleanUser} msg=${cleanMsg}\n`;
        try {
            if (!fs.existsSync('logs')) {
                fs.mkdirSync('logs');
            }
            fs.appendFileSync('logs/siem.cef', cefStr, 'utf8');
        }
        catch (err) {
            console.error('Failed to write SIEM CEF log:', err);
        }
    }
    triggerFailClosed() {
        this.logSiemEvent('FAIL_CLOSED_TRIGGERED', 10, 'system', '127.0.0.1', 'Decryption rate limit or security violation threshold crossed. Zeroizing keys and shutting down all active connections.');
        for (const key of Object.values(this.options.resolvedKeys)) {
            key.fill(0);
        }
        for (const socket of this.activeConnections) {
            socket.destroy();
        }
        this.activeConnections.clear();
    }
    sslKey = '';
    sslCert = '';
    constructor(options) {
        this.options = options;
        this.loadAllowlist();
        // Clone resolvedKeys to prevent mutating/zeroizing references shared by the caller (e.g. tests)
        const clonedKeys = {};
        if (options.resolvedKeys) {
            for (const [k, v] of Object.entries(options.resolvedKeys)) {
                clonedKeys[k] = buffer_1.Buffer.from(v);
            }
        }
        this.options.resolvedKeys = clonedKeys;
    }
    loadAllowlist() {
        const config = this.options.config?.firewall?.fingerprinting;
        if (config?.enabled && config.allowlistPath) {
            if (fs.existsSync(config.allowlistPath)) {
                try {
                    const content = fs.readFileSync(config.allowlistPath, 'utf8');
                    const list = JSON.parse(content);
                    if (Array.isArray(list)) {
                        this.allowlistedFingerprints = new Set(list);
                    }
                }
                catch (err) {
                    console.error('Failed to parse WAF allowlist file:', err);
                }
            }
        }
    }
    saveAllowlist() {
        const config = this.options.config?.firewall?.fingerprinting;
        if (config?.enabled && config.allowlistPath) {
            try {
                const list = Array.from(this.allowlistedFingerprints);
                fs.writeFileSync(config.allowlistPath, JSON.stringify(list, null, 2), 'utf8');
            }
            catch (err) {
                console.error('Failed to save WAF allowlist file:', err);
            }
        }
    }
    handleClusterMessage(msg) {
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
        }
        else if (msg.type === 'ALLOWLIST_FP') {
            const fp = msg.data.fingerprint;
            if (fp && !this.allowlistedFingerprints.has(fp)) {
                this.allowlistedFingerprints.add(fp);
                this.saveAllowlist();
            }
        }
    }
    async start() {
        try {
            const attrs = [{ name: 'commonName', value: 'localhost' }];
            const pems = await selfsigned_1.default.generate(attrs);
            this.sslKey = pems.private;
            this.sslCert = pems.cert;
        }
        catch (err) {
            console.error('Failed to generate self-signed SSL/TLS certificate:', err);
        }
        this.gossipSecret = this.options.config?.firewall?.gossipSecret ||
            this.options.config?.firewall?.jitSecret ||
            crypto.randomBytes(32).toString('hex');
        this.jitSecret = this.options.config?.firewall?.jitSecret ||
            crypto.randomBytes(32).toString('hex');
        if (this.options.gossipPort && this.options.peers) {
            this.clusterManager = new ClusterManager(this.nodeId, this.options.gossipPort, this.options.peers, this.gossipSecret, (msg) => this.handleClusterMessage(msg));
            await this.clusterManager.start();
        }
        if (this.options.fipsMode) {
            const crypto = await import('crypto');
            let isFips = false;
            try {
                isFips = crypto.getFips?.() || false;
            }
            catch {
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
                            role: this.options.config ? 'GUEST' : 'OWNER',
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
                            role: this.options.config ? 'GUEST' : 'OWNER',
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
                            role: this.options.config ? 'GUEST' : 'OWNER',
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
                            role: this.options.config ? 'GUEST' : 'OWNER',
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
    stop() {
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
            }
            else {
                resolve();
            }
        });
    }
    handleConnection(clientSocket) {
        this.activeConnections.add(clientSocket);
        const clientIp = clientSocket.remoteAddress || '127.0.0.1';
        const backendSocket = net.connect({
            host: this.options.dbHost,
            port: this.options.dbPort,
        });
        const clientParser = new pg_protocol_js_1.PostgresStreamParser();
        const backendParser = new pg_protocol_js_1.PostgresStreamParser();
        let userContext = null;
        let originalUsername = '';
        const dbGuardContext = {
            role: 'GUEST',
            userId: 'guest-user',
            maxDecryptionsPerSecond: this.options.config?.rateLimiter?.maxDecryptionsPerSecond,
            rateLimiterMode: this.options.config?.rateLimiter?.mode,
        };
        let currentColumns = [];
        let currentAggregates = [];
        let isSslNegotiated = false;
        let rowCount = 0;
        let bypassScanning = false;
        const queryTimestamps = [];
        const egressHistory = [];
        let queryStartTime = 0;
        // Prepared statement and portal schema caches to prevent Extended Protocol bypasses
        const statements = new Map();
        const portals = new Map();
        let lastDescribeRequest = null;
        let activeClientSocket = clientSocket;
        const setupClientSocketListeners = (socket) => {
            socket.on('data', async (data) => {
                try {
                    const messages = clientParser.append(data);
                    for (const msg of messages) {
                        let forwardedMsg = msg;
                        if (!userContext) {
                            // Check if it is an SSLRequest (8 bytes, second 4 bytes code: 80877103)
                            if (forwardedMsg.length === 8 && forwardedMsg.readInt32BE(4) === 80877103) {
                                isSslNegotiated = true;
                                // Respond with 'S' to accept SSL
                                socket.write(buffer_1.Buffer.from('S', 'ascii'));
                                // Upgrade socket to TLS
                                const secureContext = tls.createSecureContext({
                                    key: this.sslKey,
                                    cert: this.sslCert,
                                });
                                const tlsSocket = new tls.TLSSocket(clientSocket, {
                                    isServer: true,
                                    secureContext: secureContext,
                                });
                                // Remove plain listeners
                                socket.removeAllListeners('data');
                                socket.removeAllListeners('end');
                                socket.removeAllListeners('close');
                                socket.removeAllListeners('error');
                                activeClientSocket = tlsSocket;
                                this.activeConnections.add(tlsSocket);
                                this.activeConnections.delete(clientSocket);
                                setupClientSocketListeners(tlsSocket);
                                return;
                            }
                            // Otherwise, it must be the StartupMessage
                            const params = (0, pg_protocol_js_1.parseStartupMessage)(forwardedMsg);
                            const username = params.user || 'guest';
                            originalUsername = username;
                            userContext = (0, auth_js_1.resolveUserContext)(username, this.options.config);
                            dbGuardContext.role = userContext.role;
                            dbGuardContext.userId = userContext.userId;
                            backendSocket.write(forwardedMsg);
                        }
                        else {
                            // WAF Validation and Prepared Statement tracking
                            const type = forwardedMsg[0];
                            let queryStr = null;
                            if (type === 67) { // 'C' (Close)
                                const closeMsg = (0, pg_protocol_js_1.parseCloseMessage)(forwardedMsg);
                                if (closeMsg) {
                                    if (closeMsg.type === 'S') {
                                        statements.delete(closeMsg.name);
                                    }
                                    else if (closeMsg.type === 'P') {
                                        portals.delete(closeMsg.name);
                                    }
                                }
                            }
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
                                    const newMsg = (0, pg_protocol_js_1.serializePasswordMessage)(realDbPassword);
                                    backendSocket.write(newMsg);
                                    continue;
                                }
                                else {
                                    backendSocket.write(forwardedMsg);
                                    continue;
                                }
                            }
                            if (type === 81) { // 'Q' (Simple Query)
                                queryStartTime = Date.now();
                                queryStr = forwardedMsg.subarray(5, forwardedMsg.length - 1).toString('utf8');
                                currentColumns = []; // Reset simple query schema state
                                currentAggregates = (0, waf_js_1.identifyAggregates)(queryStr);
                                rowCount = 0;
                                bypassScanning = false;
                            }
                            else if (type === 80) { // 'P' (Parse prepared statement)
                                queryStartTime = Date.now();
                                const destNameNull = forwardedMsg.indexOf(0, 5);
                                if (destNameNull !== -1) {
                                    const statementName = forwardedMsg.toString('utf8', 5, destNameNull);
                                    const queryStart = destNameNull + 1;
                                    const queryNull = forwardedMsg.indexOf(0, queryStart);
                                    if (queryNull !== -1) {
                                        queryStr = forwardedMsg.toString('utf8', queryStart, queryNull);
                                        statements.set(statementName, {
                                            query: queryStr,
                                            aggregates: (0, waf_js_1.identifyAggregates)(queryStr)
                                        });
                                    }
                                }
                            }
                            else if (type === 66) { // 'B' (Bind portal)
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
                                            aggregates: stmt?.aggregates,
                                        });
                                    }
                                }
                            }
                            else if (type === 68) { // 'D' (Describe)
                                if (forwardedMsg.length >= 7) {
                                    const descType = String.fromCharCode(forwardedMsg[5]);
                                    const nameNull = forwardedMsg.indexOf(0, 6);
                                    if (nameNull !== -1) {
                                        const name = forwardedMsg.toString('utf8', 6, nameNull);
                                        lastDescribeRequest = { type: descType, name };
                                        if (descType === 'p') {
                                            const portal = portals.get(name);
                                            if (portal) {
                                                currentColumns = portal.columns || [];
                                                currentAggregates = portal.aggregates || [];
                                            }
                                        }
                                    }
                                }
                            }
                            else if (type === 69) { // 'E' (Execute)
                                rowCount = 0;
                                bypassScanning = false;
                                const portalNull = forwardedMsg.indexOf(0, 5);
                                if (portalNull !== -1) {
                                    const portalName = forwardedMsg.toString('utf8', 5, portalNull);
                                    const portal = portals.get(portalName);
                                    if (portal) {
                                        if (portal.columns)
                                            currentColumns = portal.columns;
                                        if (portal.aggregates)
                                            currentAggregates = portal.aggregates;
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
                                        }
                                        else {
                                            const originalContext = (0, auth_js_1.resolveUserContext)(originalUsername, this.options.config);
                                            dbGuardContext.role = originalContext.role;
                                        }
                                    }
                                    // JIT Temporary Access Approval Webhook Simulation
                                    if (this.options.config?.firewall?.jitApprovalRequired && dbGuardContext.role !== 'OWNER') {
                                        const hasActiveGrant = activeJit && activeJit.expiresAt > Date.now();
                                        if (!hasActiveGrant) {
                                            this.logSiemEvent('JIT_REQUESTED', 6, dbGuardContext.userId, clientIp || '127.0.0.1', `JIT request triggered for query: ${queryStr}`);
                                            let approved = false;
                                            // 1. Signed JIT Token flow
                                            const tokenMatch = queryStr.match(/--\s*JIT_TOKEN:\s*([^\s;]+)/i);
                                            if (tokenMatch) {
                                                const token = tokenMatch[1];
                                                const parts = token.split(':');
                                                if (parts.length === 3) {
                                                    const [tUserId, tExpiresAtStr, tSig] = parts;
                                                    const tExpiresAt = parseInt(tExpiresAtStr, 10);
                                                    if (tUserId === dbGuardContext.userId && tExpiresAt > Date.now()) {
                                                        const secret = this.jitSecret;
                                                        const expectedSig = crypto
                                                            .createHmac('sha256', secret)
                                                            .update(`${tUserId}:${tExpiresAt}`)
                                                            .digest('hex');
                                                        if (tSig === expectedSig) {
                                                            approved = true;
                                                            this.registerJitGrant(dbGuardContext.userId, 'OWNER', 3600000);
                                                            this.logSiemEvent('JIT_APPROVED', 6, 'system', '127.0.0.1', `JIT request approved for user ${dbGuardContext.userId} via cryptographically signed token`);
                                                            dbGuardContext.role = 'OWNER';
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
                                                        body: JSON.stringify({ userId: dbGuardContext.userId, role: 'OWNER', query: queryStr }),
                                                    });
                                                    if (response.ok) {
                                                        const body = await response.json();
                                                        if (body.approved) {
                                                            approved = true;
                                                            this.registerJitGrant(dbGuardContext.userId, 'OWNER', 3600000);
                                                            this.logSiemEvent('JIT_APPROVED', 6, 'system', '127.0.0.1', `JIT request approved for user ${dbGuardContext.userId} via webhook simulation`);
                                                            dbGuardContext.role = 'OWNER';
                                                        }
                                                    }
                                                }
                                                catch (err) {
                                                    console.error('JIT webhook connection error:', err);
                                                }
                                            }
                                            if (!approved) {
                                                this.logSiemEvent('JIT_DENIED', 8, dbGuardContext.userId, clientIp || '127.0.0.1', `JIT request denied for query: ${queryStr}`);
                                                throw new Error('JIT approval request denied: user is not in the approved JIT registry or webhook/token approval failed');
                                            }
                                        }
                                    }
                                    // AI-Driven Anomaly Threat Scoring
                                    if (this.options.config?.firewall?.anomalyEngine?.enabled) {
                                        const baselineQueries = this.options.config?.firewall?.anomalyEngine?.baselineQueries || [
                                            'SELECT * FROM users WHERE id = 1',
                                            'SELECT id, username FROM users',
                                            'SELECT email FROM users WHERE role = ?',
                                        ];
                                        const { QueryAnomalyScorer } = await import('./anomaly.js');
                                        const scorer = new QueryAnomalyScorer();
                                        scorer.learnBaseline(dbGuardContext.userId, baselineQueries);
                                        const score = scorer.getAnomalyScore(dbGuardContext.userId, queryStr);
                                        if (score > 0.7) {
                                            this.logSiemEvent('ANOMALY_THREAT_DETECTION', 8, dbGuardContext.userId, socket.remoteAddress || '127.0.0.1', `Semantic anomaly detected with threat score ${score.toFixed(2)}: ${queryStr}`);
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
                                        (0, waf_js_1.validateQuery)(queryStr, dbGuardContext.role);
                                        // 4. Semantic threat score analysis
                                        const threatScore = (0, waf_js_1.evaluateThreatScore)(queryStr);
                                        const scoreLimit = 8; // threshold of 8 triggers block
                                        if (threatScore >= scoreLimit) {
                                            throw new Error(`Semantic SQLi threat detected: query score is ${threatScore} (Limit: ${scoreLimit})`);
                                        }
                                    }
                                    // 5. Query Fingerprinting & Allowlisting
                                    const fpConfig = this.options.config?.firewall?.fingerprinting;
                                    if (fpConfig?.enabled) {
                                        const fingerprint = (0, waf_js_1.generateFingerprint)(queryStr);
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
                                        }
                                        else if (fpConfig.mode === 'blocking') {
                                            if (!this.allowlistedFingerprints.has(fingerprint)) {
                                                throw new Error(`Blocked by allowlist: query shape "${fingerprint}" is not recognized`);
                                            }
                                        }
                                    }
                                    // 6. Dynamic SQL Query Rewriting (Masking & RLS Tenant Isolation)
                                    const rewritten = (0, waf_js_1.rewriteQuery)(queryStr, dbGuardContext.role, userContext?.tenantId, this.options.config);
                                    if (rewritten !== queryStr) {
                                        if (type === 81) { // Simple Query 'Q'
                                            forwardedMsg = (0, pg_protocol_js_1.serializeQueryMessage)(rewritten);
                                        }
                                        else if (type === 80) { // Parse 'P'
                                            const destNameNull = forwardedMsg.indexOf(0, 5);
                                            const statementName = destNameNull !== -1 ? forwardedMsg.toString('utf8', 5, destNameNull) : '';
                                            const queryNull = destNameNull !== -1 ? forwardedMsg.indexOf(0, destNameNull + 1) : -1;
                                            if (queryNull !== -1) {
                                                forwardedMsg = (0, pg_protocol_js_1.serializeParseMessage)(statementName, rewritten, forwardedMsg, queryNull);
                                            }
                                        }
                                        queryStr = rewritten;
                                    }
                                }
                                catch (err) {
                                    const violationMsg = err.message;
                                    this.logSiemEvent('WAF_BLOCK', 8, originalUsername || 'guest', socket.remoteAddress || '127.0.0.1', violationMsg);
                                    // Add to local ban list and broadcast to cluster if enabled
                                    const ipBanEnabled = this.options.config?.firewall?.ipBanning?.enabled;
                                    if (ipBanEnabled) {
                                        const clientIp = socket.remoteAddress || '127.0.0.1';
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
                                    socket.write(serializeErrorResponse(`Vollcrypt WAF Blocked: ${violationMsg}`));
                                    // Send ReadyForQuery ('Z') so client CLI / DBeaver doesn't hang
                                    const readyForQuery = buffer_1.Buffer.from([0x5a, 0, 0, 0, 5, 0x49]);
                                    socket.write(readyForQuery);
                                    continue;
                                }
                            }
                            backendSocket.write(forwardedMsg);
                        }
                    }
                }
                catch (err) {
                    const errMsg = err.message;
                    socket.write(serializeErrorResponse(`Vollcrypt Proxy: ${errMsg}`));
                    socket.destroy();
                }
            });
            socket.on('close', () => {
                this.activeConnections.delete(socket);
                if (socket !== clientSocket) {
                    this.activeConnections.delete(clientSocket);
                    clientSocket.destroy();
                }
                backendSocket.destroy();
            });
            socket.on('error', () => {
                backendSocket.destroy();
            });
        };
        setupClientSocketListeners(clientSocket);
        // Handle backend to client stream
        backendSocket.on('data', async (data) => {
            try {
                const messages = backendParser.append(data);
                for (const msg of messages) {
                    const type = msg[0];
                    if (type === 84) { // 'T' -> RowDescription
                        currentColumns = (0, pg_protocol_js_1.parseRowDescription)(msg);
                        const sensitiveKeywords = ['credit_card', 'email', 'tc_no', 'phone', 'iban', 'cc', 'ssn', 'salary', 'password', 'secret'];
                        const hasSensitive = currentColumns.some(col => {
                            const colLower = col.name.toLowerCase();
                            return sensitiveKeywords.some(kw => colLower.includes(kw));
                        });
                        const hasAggregate = currentAggregates.some(agg => agg === true);
                        bypassScanning = !hasSensitive && !hasAggregate;
                        // Map the parsed description to the active prepared statement or portal
                        if (lastDescribeRequest) {
                            if (lastDescribeRequest.type === 'S') {
                                const stmt = statements.get(lastDescribeRequest.name);
                                if (stmt) {
                                    stmt.columns = currentColumns;
                                }
                            }
                            else if (lastDescribeRequest.type === 'P') {
                                const portal = portals.get(lastDescribeRequest.name);
                                if (portal) {
                                    portal.columns = currentColumns;
                                }
                            }
                        }
                        activeClientSocket.write(msg);
                    }
                    else if (type === 68) { // 'D' -> DataRow
                        rowCount++;
                        const maxRows = this.options.config?.firewall?.maxRowsPerQuery || 5000;
                        if (rowCount > maxRows) {
                            activeClientSocket.write(serializeErrorResponse(`Vollcrypt WAF Blocked: Mass exfiltration limit exceeded (Limit: ${maxRows})`));
                            activeClientSocket.destroy();
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
                            this.logSiemEvent('ANOMALY_DETECTED', 7, originalUsername || 'guest', activeClientSocket.remoteAddress || '127.0.0.1', `High row egress volume anomaly detected (Total: ${totalEgress} rows in last 10s)`);
                            // Throttling: introduce delay
                            await new Promise(resolve => setTimeout(resolve, 50));
                        }
                        if (bypassScanning) {
                            if (!msg.includes('VOLLVALT:')) {
                                activeClientSocket.write(msg);
                                continue;
                            }
                        }
                        const values = (0, pg_protocol_js_1.parseDataRow)(msg);
                        const modifiedValues = [];
                        let encryptionError = null;
                        for (let i = 0; i < values.length; i++) {
                            const val = values[i];
                            if (val === null) {
                                modifiedValues.push(null);
                                continue;
                            }
                            const strVal = val.toString('utf8');
                            if (strVal.startsWith('VOLLVALT:')) {
                                const columnName = currentColumns[i] ? currentColumns[i].name : `col_${i}`;
                                try {
                                    // Decrypt using security controls inside user context store
                                    const decrypted = db_guard_1.dbGuardContextStore.run(dbGuardContext, () => {
                                        let modelName = 'default';
                                        let fieldName = columnName;
                                        if (columnName.includes('.')) {
                                            const parts = columnName.split('.');
                                            modelName = parts[0];
                                            fieldName = parts[1];
                                        }
                                        return (0, db_guard_1.decryptWithSecurity)(strVal, (cipherText) => (0, db_guard_1.decryptValue)(cipherText, this.options.resolvedKeys), modelName, fieldName, undefined, {
                                            cryptoRbac: (0, auth_js_1.getRbacConfig)(this.options.config),
                                            rateLimiter: this.options.config?.rateLimiter,
                                        });
                                    });
                                    const decryptedStr = typeof decrypted === 'string' ? decrypted : JSON.stringify(decrypted);
                                    modifiedValues.push(buffer_1.Buffer.from(decryptedStr, 'utf8'));
                                }
                                catch (err) {
                                    encryptionError = err;
                                    break;
                                }
                            }
                            else {
                                const columnName = currentColumns[i] ? currentColumns[i].name : `col_${i}`;
                                const rbacConfig = (0, auth_js_1.getRbacConfig)(this.options.config);
                                const roleConfig = dbGuardContext.role ? rbacConfig?.roles?.[dbGuardContext.role] : undefined;
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
                                    const maskedVal = (0, db_guard_1.maskValue)(strVal, maskRule);
                                    modifiedValues.push(buffer_1.Buffer.from(maskedVal, 'utf8'));
                                    continue;
                                }
                                const isAggregate = currentAggregates[i] === true || (currentAggregates[i] === undefined && (columnName.toLowerCase().startsWith('avg') || columnName.toLowerCase().startsWith('sum') || columnName.toLowerCase().startsWith('count')));
                                if (isAggregate) {
                                    const colMeta = currentColumns[i];
                                    const isBinary = colMeta && colMeta.formatCode === 1;
                                    const oid = colMeta ? colMeta.dataTypeOid : 0;
                                    let floatVal = NaN;
                                    if (isBinary) {
                                        try {
                                            if (oid === 23) {
                                                floatVal = val.readInt32BE(0);
                                            }
                                            else if (oid === 21) {
                                                floatVal = val.readInt16BE(0);
                                            }
                                            else if (oid === 20) {
                                                floatVal = Number(val.readBigInt64BE(0));
                                            }
                                            else if (oid === 700) {
                                                floatVal = val.readFloatBE(0);
                                            }
                                            else if (oid === 701) {
                                                floatVal = val.readDoubleBE(0);
                                            }
                                        }
                                        catch (e) {
                                            floatVal = NaN;
                                        }
                                    }
                                    else {
                                        floatVal = parseFloat(strVal);
                                    }
                                    if (!isNaN(floatVal)) {
                                        const noise = (0, waf_js_1.generateLaplaceNoise)(0.5);
                                        const noisyVal = floatVal + noise;
                                        if (isBinary) {
                                            let noisyBuf;
                                            if (oid === 20) {
                                                noisyBuf = buffer_1.Buffer.alloc(8);
                                                noisyBuf.writeBigInt64BE(BigInt(Math.round(noisyVal)), 0);
                                            }
                                            else if (oid === 21) {
                                                noisyBuf = buffer_1.Buffer.alloc(2);
                                                noisyBuf.writeInt16BE(Math.round(noisyVal), 0);
                                            }
                                            else if (oid === 700) {
                                                noisyBuf = buffer_1.Buffer.alloc(4);
                                                noisyBuf.writeFloatBE(noisyVal, 0);
                                            }
                                            else if (oid === 701) {
                                                noisyBuf = buffer_1.Buffer.alloc(8);
                                                noisyBuf.writeDoubleBE(noisyVal, 0);
                                            }
                                            else {
                                                noisyBuf = buffer_1.Buffer.alloc(4);
                                                noisyBuf.writeInt32BE(Math.round(noisyVal), 0);
                                            }
                                            modifiedValues.push(noisyBuf);
                                        }
                                        else {
                                            modifiedValues.push(buffer_1.Buffer.from(noisyVal.toFixed(2), 'utf8'));
                                        }
                                        continue;
                                    }
                                }
                                // DLP Auto-PII scanning on unencrypted text cells
                                if (!this.options.noDlp) {
                                    const maskedVal = (0, dlp_js_1.scanAndMaskCell)(strVal);
                                    if (maskedVal !== strVal) {
                                        modifiedValues.push(buffer_1.Buffer.from(maskedVal, 'utf8'));
                                    }
                                    else {
                                        modifiedValues.push(val);
                                    }
                                }
                                else {
                                    modifiedValues.push(val);
                                }
                            }
                        }
                        if (encryptionError) {
                            activeClientSocket.write(serializeErrorResponse(`Vollcrypt Cryptographic Access Violation: ${encryptionError.message}`));
                            const isRateLimit = encryptionError.message.includes('rate limit') || encryptionError.message.includes('Fail-Closed');
                            if (isRateLimit) {
                                const rateLimiterMode = this.options.config?.rateLimiter?.mode || 'fail_closed';
                                if (rateLimiterMode === 'fail_closed') {
                                    this.triggerFailClosed();
                                }
                            }
                            // End the packet flow for this stream
                            break;
                        }
                        else {
                            const newMsg = (0, pg_protocol_js_1.serializeDataRow)(modifiedValues);
                            activeClientSocket.write(newMsg);
                        }
                    }
                    else if (type === 67 || type === 90) { // 'C' -> CommandComplete or 'Z' -> ReadyForQuery
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
                        activeClientSocket.write(msg);
                    }
                    else if (type === 83) { // 'S' -> ParameterStatus
                        const status = (0, pg_protocol_js_1.parseParameterStatus)(msg);
                        if (status && status.name === 'server_version') {
                            const maskedVersion = this.options.config?.firewall?.versionMask || '16.0';
                            const newMsg = (0, pg_protocol_js_1.serializeParameterStatus)('server_version', maskedVersion);
                            activeClientSocket.write(newMsg);
                        }
                        else {
                            activeClientSocket.write(msg);
                        }
                    }
                    else {
                        activeClientSocket.write(msg);
                    }
                }
            }
            catch (err) {
                const errMsg = err.message;
                activeClientSocket.write(serializeErrorResponse(`Vollcrypt Proxy: ${errMsg}`));
                activeClientSocket.destroy();
            }
        });
        backendSocket.on('close', () => {
            activeClientSocket.destroy();
        });
        backendSocket.on('error', () => {
            activeClientSocket.destroy();
        });
    }
}
exports.DbProxyServer = DbProxyServer;
