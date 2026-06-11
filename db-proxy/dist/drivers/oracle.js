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
const db_guard_1 = require("@vollcrypt/db-guard");
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
function decryptOracleResponse(packet, keys) {
    if (packet.length < 8)
        return packet;
    const tnsType = packet[4];
    if (tnsType !== 0x06)
        return packet; // Only data packets contain rows
    const payloadStr = packet.toString('ascii');
    const matchIndex = payloadStr.indexOf('VOLLVALT:');
    if (matchIndex === -1)
        return packet;
    // Find ciphertext boundary
    const ctextPart = payloadStr.substring(matchIndex);
    const boundaryMatch = ctextPart.match(/[^A-Za-z0-9+/=:]/);
    const ctext = boundaryMatch ? ctextPart.substring(0, boundaryMatch.index) : ctextPart;
    try {
        const ptext = (0, db_guard_1.decryptValue)(ctext, keys);
        const ptextBuf = Buffer.from(ptext, 'ascii');
        const ctextBuf = Buffer.from(ctext, 'ascii');
        const indexInBytes = packet.indexOf(ctextBuf);
        if (indexInBytes !== -1) {
            const before = packet.subarray(0, indexInBytes);
            const after = packet.subarray(indexInBytes + ctextBuf.length);
            // Try updating the length prefix preceding the string
            if (indexInBytes >= 1) {
                const singleByteLen = packet[indexInBytes - 1];
                if (singleByteLen === ctextBuf.length) {
                    before[indexInBytes - 1] = ptextBuf.length;
                }
                else if (indexInBytes >= 2) {
                    const doubleByteLen = packet.readUInt16BE(indexInBytes - 2);
                    if (doubleByteLen === ctextBuf.length) {
                        before.writeUInt16BE(ptextBuf.length, indexInBytes - 2);
                    }
                    else {
                        const doubleByteLenLE = packet.readUInt16LE(indexInBytes - 2);
                        if (doubleByteLenLE === ctextBuf.length) {
                            before.writeUInt16LE(ptextBuf.length, indexInBytes - 2);
                        }
                    }
                }
            }
            const newPayload = Buffer.concat([before, ptextBuf, after]);
            // Update TNS header packet length (Big-Endian)
            if (newPayload.length >= 2) {
                newPayload.writeUInt16BE(newPayload.length, 0);
            }
            return newPayload;
        }
    }
    catch {
        // Fallback
    }
    return packet;
}
function handleOracleConnection(clientSocket, options) {
    let connected = false;
    const queue = [];
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
            processedData = decryptOracleResponse(data, options.resolvedKeys);
        }
        catch {
            // Fallback
        }
        if (clientSocket.writable) {
            clientSocket.write(processedData);
        }
    });
    clientSocket.on('data', (data) => {
        if (data.length > 8 && !options.noWaf) {
            const type = data[4];
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
                            (0, waf_js_1.validateQuery)(query, options.role);
                        }
                        catch (err) {
                            options.logSiem('WAF_ORACLE_BLOCK', 9, `Oracle WAF violation blocked: ${err.message}`);
                            const errPacket = serializeOracleError(err.message);
                            clientSocket.write(errPacket);
                            return;
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
    clientSocket.on('close', () => {
        clientSocket.destroy();
    });
}
