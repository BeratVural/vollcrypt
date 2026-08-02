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
exports.serializeOracleError = serializeOracleError;
exports.decryptOracleResponse = decryptOracleResponse;
exports.handleOracleConnection = handleOracleConnection;
const net = __importStar(require("net"));
const waf_js_1 = require("../waf.js");
const auth_js_1 = require("../auth.js");
const common_js_1 = require("./common.js");
/** Serializes an Oracle TNS refusal packet. */
function serializeOracleError(message) {
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
/** Decrypts encrypted values in an Oracle TNS data response. */
function decryptOracleResponse(packet, keys, role = 'GUEST', userId = 'guest-user', tenantId, config, modelName = 'default', columns = []) {
    if (packet.length < 8)
        return packet;
    const tnsType = packet[4];
    if (tnsType !== 0x06)
        return packet; // Only data packets contain rows
    const header = packet.subarray(0, 8);
    const payload = packet.subarray(8);
    const decryptPayload = (buf, cellIdx = 0) => {
        const payloadStr = buf.toString('ascii');
        const matchIndex = payloadStr.indexOf('VOLLVALT:');
        if (matchIndex === -1)
            return buf;
        // Find ciphertext boundary
        const ctextPart = payloadStr.substring(matchIndex);
        const boundaryMatch = ctextPart.match(/[^A-Za-z0-9+/=:]/);
        const ctext = boundaryMatch ? ctextPart.substring(0, boundaryMatch.index) : ctextPart;
        try {
            const { field, model } = (0, common_js_1.resolveProjectedField)(columns[cellIdx], modelName, 'column');
            const ptext = (0, common_js_1.decryptDriverValue)(ctext, model, field, { keys, role, userId, tenantId, config });
            const ptextBuf = Buffer.from(ptext, 'ascii');
            const ctextBuf = Buffer.from(ctext, 'ascii');
            const indexInBytes = buf.indexOf(ctextBuf);
            if (indexInBytes !== -1) {
                const before = buf.subarray(0, indexInBytes);
                const after = buf.subarray(indexInBytes + ctextBuf.length);
                // Try updating the length prefix preceding the string
                if (indexInBytes >= 1) {
                    const singleByteLen = buf[indexInBytes - 1];
                    if (singleByteLen === ctextBuf.length) {
                        before[indexInBytes - 1] = ptextBuf.length;
                    }
                    else if (indexInBytes >= 2) {
                        const doubleByteLen = buf.readUInt16BE(indexInBytes - 2);
                        if (doubleByteLen === ctextBuf.length) {
                            before.writeUInt16BE(ptextBuf.length, indexInBytes - 2);
                        }
                        else {
                            const doubleByteLenLE = buf.readUInt16LE(indexInBytes - 2);
                            if (doubleByteLenLE === ctextBuf.length) {
                                before.writeUInt16LE(ptextBuf.length, indexInBytes - 2);
                            }
                        }
                    }
                }
                const processedAfter = decryptPayload(after, cellIdx + 1);
                return Buffer.concat([before, ptextBuf, processedAfter]);
            }
        }
        catch (err) {
            throw err;
        }
        return buf;
    };
    const newPayload = decryptPayload(payload);
    if (newPayload === payload)
        return packet;
    const newPacket = Buffer.concat([header, newPayload]);
    // Update TNS header packet length (Big-Endian)
    if (newPacket.length >= 2) {
        newPacket.writeUInt16BE(newPacket.length, 0);
    }
    return newPacket;
}
/** Proxies one Oracle connection with identity, WAF, and decryption. */
function handleOracleConnection(clientSocket, options) {
    let connected = false;
    const queue = [];
    let currentUser = (0, common_js_1.createInitialUserContext)(options.role);
    let identityResolved = false;
    let currentTable = 'default';
    let currentColumns = [];
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
        let processedData = data;
        try {
            processedData = decryptOracleResponse(data, options.resolvedKeys, currentUser.role, currentUser.userId, currentUser.tenantId, options.config, currentTable, currentColumns);
        }
        catch (err) {
            options.logSiem('ORACLE_DECRYPT_ERROR', 8, `Oracle decryption error: ${err.message}`);
            const errPacket = serializeOracleError(err.message);
            clientSocket.write(errPacket);
            return;
        }
        if (clientSocket.writable) {
            clientSocket.write(processedData);
        }
    });
    clientSocket.on('data', (data) => {
        if (data.length > 8) {
            const type = data[4];
            // Parse usernames only from the initial TNS Connect packet.
            const packetStr = type === 0x01 && !identityResolved ? data.toString('ascii') : '';
            const userMatch = packetStr.match(/\(\s*USER\s*=\s*([^)]+)\)/i) || packetStr.match(/AUTH_USERNAME\s*=\s*([A-Za-z0-9_]+)/i);
            if (type === 0x01 && !identityResolved && userMatch && userMatch[1]) {
                const username = userMatch[1].trim();
                currentUser = (0, auth_js_1.resolveUserContext)(username, options.config);
                identityResolved = true;
            }
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
                            if (!options.noWaf) {
                                (0, waf_js_1.validateQuery)(query, currentUser.role);
                            }
                            (0, waf_js_1.ensureTenantScopedQuery)(query, currentUser.tenantId);
                        }
                        catch (err) {
                            options.logSiem('WAF_ORACLE_BLOCK', 9, `Oracle WAF violation blocked: ${err.message}`);
                            const errPacket = serializeOracleError(err.message);
                            clientSocket.write(errPacket);
                            return;
                        }
                        currentTable = 'default';
                        currentColumns = [];
                        try {
                            currentTable = (0, waf_js_1.extractTableName)(query);
                            currentColumns = (0, waf_js_1.extractProjectionColumns)(query);
                        }
                        catch (e) {
                            currentTable = 'default';
                            currentColumns = [];
                            // ignore parsing error
                        }
                    }
                }
            }
        }
        if (connected) {
            if (backendSocket.writable) {
                backendSocket.write(data);
            }
        }
        else {
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
    backendSocket.on('close', () => {
        clientSocket.destroy();
    });
}
