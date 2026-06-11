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
                                modifiedValues.push(val);
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
