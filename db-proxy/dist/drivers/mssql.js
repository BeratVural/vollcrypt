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
exports.serializeMssqlError = serializeMssqlError;
exports.decryptMssqlResponse = decryptMssqlResponse;
exports.handleMssqlConnection = handleMssqlConnection;
const net = __importStar(require("net"));
const waf_js_1 = require("../waf.js");
const db_guard_1 = require("@vollcrypt/db-guard");
function serializeMssqlError(message, code = 50000) {
    const msgBuf = Buffer.from(message, 'utf16le');
    const srvName = Buffer.from('VOLLCRYPT\0', 'utf16le');
    const procName = Buffer.from('PROXY\0', 'utf16le');
    const tokenLength = 11 + msgBuf.length + 1 + srvName.length + 1 + procName.length + 2;
    const token = Buffer.alloc(tokenLength);
    token[0] = 0xaa; // Error Token ID
    token.writeUInt16LE(tokenLength - 3, 1);
    token.writeInt32LE(code, 3); // Error Number
    token[7] = 1; // State
    token[8] = 16; // Severity
    token.writeUInt16LE(msgBuf.length / 2, 9); // Message Length in characters
    msgBuf.copy(token, 11);
    let cursor = 11 + msgBuf.length;
    token[cursor] = srvName.length / 2;
    cursor++;
    srvName.copy(token, cursor);
    cursor += srvName.length;
    token[cursor] = procName.length / 2;
    cursor++;
    procName.copy(token, cursor);
    cursor += procName.length;
    token.writeUInt16LE(1, cursor); // Line number
    // TDS Packet Header (8 bytes)
    const header = Buffer.alloc(8);
    header[0] = 0x04; // Tabular result packet type
    header[1] = 0x01; // EOM status
    header.writeUInt16BE(8 + token.length, 2);
    return Buffer.concat([header, token]);
}
/**
 * Intercepts and decrypts VOLLVALT: values inside TDS 7.4 response streams.
 */
function decryptMssqlResponse(packet, keys) {
    const payloadStr = packet.toString('utf16le');
    const matchIndex = payloadStr.indexOf('VOLLVALT:');
    if (matchIndex === -1)
        return packet;
    // Locate ciphertext boundaries
    const ctextPart = payloadStr.substring(matchIndex);
    const nullOrSpaceIndex = ctextPart.match(/[\s\0]/);
    const ctext = nullOrSpaceIndex ? ctextPart.substring(0, nullOrSpaceIndex.index) : ctextPart;
    try {
        const ptext = (0, db_guard_1.decryptValue)(ctext, keys);
        const ptextBuf = Buffer.from(ptext, 'utf16le');
        const ctextBuf = Buffer.from(ctext, 'utf16le');
        const indexInBytes = packet.indexOf(ctextBuf);
        if (indexInBytes !== -1) {
            const before = packet.subarray(0, indexInBytes);
            const after = packet.subarray(indexInBytes + ctextBuf.length);
            // Adjust column length prefix (which resides immediately before the string in TDS)
            if (indexInBytes >= 2) {
                const oldLen = packet.readUInt16LE(indexInBytes - 2);
                if (oldLen === ctextBuf.length) {
                    before.writeUInt16LE(ptextBuf.length, indexInBytes - 2);
                }
            }
            const newPayload = Buffer.concat([before, ptextBuf, after]);
            // Update TDS header message length field
            if (newPayload.length >= 8) {
                newPayload.writeUInt16BE(newPayload.length, 2);
            }
            return newPayload;
        }
    }
    catch {
        // Fallback on failure
    }
    return packet;
}
function handleMssqlConnection(clientSocket, options) {
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
            processedData = decryptMssqlResponse(data, options.resolvedKeys);
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
            const type = data[0];
            if (type === 0x01 || type === 0x03) { // SQL Batch or RPC
                const query = data.toString('utf16le', 8);
                try {
                    (0, waf_js_1.validateQuery)(query, options.role);
                }
                catch (err) {
                    options.logSiem('WAF_MSSQL_BLOCK', 9, `MSSQL WAF violation blocked: ${err.message}`);
                    const errPacket = serializeMssqlError(err.message, 50000);
                    clientSocket.write(errPacket);
                    return;
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
