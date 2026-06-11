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
Object.defineProperty(exports, "__esModule", { value: true });
exports.DbProxyServer = void 0;
exports.serializeErrorResponse = serializeErrorResponse;
const net = __importStar(require("net"));
const buffer_1 = require("buffer");
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
class DbProxyServer {
    options;
    server = null;
    activeConnections = new Set();
    constructor(options) {
        this.options = options;
    }
    start() {
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
    stop() {
        return new Promise((resolve) => {
            for (const socket of this.activeConnections) {
                socket.destroy();
            }
            this.activeConnections.clear();
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
        const backendSocket = net.connect({
            host: this.options.dbHost,
            port: this.options.dbPort,
        });
        const clientParser = new pg_protocol_js_1.PostgresStreamParser();
        const backendParser = new pg_protocol_js_1.PostgresStreamParser();
        let userContext = null;
        let currentColumns = [];
        let isSslNegotiated = false;
        // Prepared statement and portal schema caches to prevent Extended Protocol bypasses
        const statements = new Map();
        const portals = new Map();
        let lastDescribeRequest = null;
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
                            clientSocket.write(buffer_1.Buffer.from('N', 'ascii'));
                            continue;
                        }
                        // Otherwise, it must be the StartupMessage
                        const params = (0, pg_protocol_js_1.parseStartupMessage)(msg);
                        const username = params.user || 'guest';
                        userContext = (0, auth_js_1.resolveUserContext)(username, this.options.config);
                        backendSocket.write(msg);
                    }
                    else {
                        // WAF Validation and Prepared Statement tracking
                        const type = msg[0];
                        let queryStr = null;
                        if (type === 81) { // 'Q' (Simple Query)
                            queryStr = msg.subarray(5, msg.length - 1).toString('utf8');
                            currentColumns = []; // Reset simple query schema state
                        }
                        else if (type === 80) { // 'P' (Parse prepared statement)
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
                        }
                        else if (type === 66) { // 'B' (Bind portal)
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
                        }
                        else if (type === 68) { // 'D' (Describe)
                            if (msg.length >= 7) {
                                const descType = String.fromCharCode(msg[5]);
                                const nameNull = msg.indexOf(0, 6);
                                if (nameNull !== -1) {
                                    const name = msg.toString('utf8', 6, nameNull);
                                    lastDescribeRequest = { type: descType, name };
                                }
                            }
                        }
                        else if (type === 69) { // 'E' (Execute)
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
                                (0, waf_js_1.validateQuery)(queryStr, userContext.role);
                            }
                            catch (err) {
                                const violationMsg = err.message;
                                // Write standard PostgreSQL protocol error frame back to the client
                                clientSocket.write(serializeErrorResponse(`Vollcrypt WAF Blocked: ${violationMsg}`));
                                // Send ReadyForQuery ('Z') so client CLI / DBeaver doesn't hang
                                const readyForQuery = buffer_1.Buffer.from([0x5a, 0, 0, 0, 5, 0x49]);
                                clientSocket.write(readyForQuery);
                                continue;
                            }
                        }
                        backendSocket.write(msg);
                    }
                }
            }
            catch (err) {
                const errMsg = err.message;
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
                        currentColumns = (0, pg_protocol_js_1.parseRowDescription)(msg);
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
                        clientSocket.write(msg);
                    }
                    else if (type === 68) { // 'D' -> DataRow
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
                                const columnName = currentColumns[i] || `col_${i}`;
                                try {
                                    // Decrypt using security controls inside user context store
                                    const decrypted = db_guard_1.dbGuardContextStore.run({
                                        role: userContext?.role || 'GUEST',
                                        userId: userContext?.userId || 'guest-user',
                                    }, () => {
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
                                // DLP Auto-PII scanning on unencrypted text cells
                                const maskedVal = (0, dlp_js_1.scanAndMaskCell)(strVal);
                                if (maskedVal !== strVal) {
                                    modifiedValues.push(buffer_1.Buffer.from(maskedVal, 'utf8'));
                                }
                                else {
                                    modifiedValues.push(val);
                                }
                            }
                        }
                        if (encryptionError) {
                            clientSocket.write(serializeErrorResponse(`Vollcrypt Cryptographic Access Violation: ${encryptionError.message}`));
                            // End the packet flow for this stream
                            break;
                        }
                        else {
                            const newMsg = (0, pg_protocol_js_1.serializeDataRow)(modifiedValues);
                            clientSocket.write(newMsg);
                        }
                    }
                    else {
                        clientSocket.write(msg);
                    }
                }
            }
            catch (err) {
                const errMsg = err.message;
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
exports.DbProxyServer = DbProxyServer;
