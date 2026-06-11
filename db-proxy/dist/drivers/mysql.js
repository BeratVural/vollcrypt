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
exports.serializeMysqlError = serializeMysqlError;
exports.parseLengthEncodedString = parseLengthEncodedString;
exports.serializeLengthEncodedString = serializeLengthEncodedString;
exports.decryptMysqlRow = decryptMysqlRow;
exports.handleMysqlConnection = handleMysqlConnection;
const net = __importStar(require("net"));
const waf_js_1 = require("../waf.js");
const db_guard_1 = require("@vollcrypt/db-guard");
function serializeMysqlError(message, code = 1142, sqlState = '42000') {
    const msgBuf = Buffer.from(message, 'utf8');
    const body = Buffer.alloc(9 + msgBuf.length);
    body[0] = 0xff; // Error Packet Indicator
    body.writeUInt16LE(code, 1);
    body[3] = 0x23; // '#' SQL State marker
    body.write(sqlState, 4, 5, 'ascii');
    msgBuf.copy(body, 9);
    const header = Buffer.alloc(4);
    header.writeUIntLE(body.length, 0, 3);
    header[3] = 1; // Sequence ID
    return Buffer.concat([header, body]);
}
function parseLengthEncodedString(buf, offset) {
    if (offset >= buf.length) {
        return { value: null, nextOffset: offset };
    }
    const first = buf[offset];
    if (first === 0xfb) {
        return { value: null, nextOffset: offset + 1 };
    }
    let len = 0;
    let nextOffset = offset + 1;
    if (first < 0xfb) {
        len = first;
    }
    else if (first === 0xfc) {
        len = buf.readUInt16LE(offset + 1);
        nextOffset = offset + 3;
    }
    else if (first === 0xfd) {
        len = buf.readUIntLE(offset + 1, 3);
        nextOffset = offset + 4;
    }
    else if (first === 0xfe) {
        len = buf.readUIntLE(offset + 1, 8);
        nextOffset = offset + 9;
    }
    if (nextOffset + len > buf.length) {
        return { value: null, nextOffset: buf.length };
    }
    const value = buf.toString('utf8', nextOffset, nextOffset + len);
    return { value, nextOffset: nextOffset + len };
}
function serializeLengthEncodedString(value) {
    if (value === null) {
        return Buffer.from([0xfb]);
    }
    const strBuf = Buffer.from(value, 'utf8');
    const len = strBuf.length;
    let lenBuf;
    if (len < 251) {
        lenBuf = Buffer.from([len]);
    }
    else if (len <= 0xffff) {
        lenBuf = Buffer.alloc(3);
        lenBuf[0] = 0xfc;
        lenBuf.writeUInt16LE(len, 1);
    }
    else if (len <= 0xffffff) {
        lenBuf = Buffer.alloc(4);
        lenBuf[0] = 0xfd;
        lenBuf.writeUIntLE(len, 1, 3);
    }
    else {
        lenBuf = Buffer.alloc(9);
        lenBuf[0] = 0xfe;
        lenBuf.writeUIntLE(len, 1, 8);
    }
    return Buffer.concat([lenBuf, strBuf]);
}
function decryptMysqlRow(packet, keys) {
    if (packet.length < 5)
        return packet;
    const payloadLen = packet.readUIntLE(0, 3);
    const seqId = packet[3];
    const firstByte = packet[4];
    // Ignore OK, ERR, or EOF packets
    if (firstByte === 0x00 || firstByte === 0xfe || firstByte === 0xff) {
        return packet;
    }
    const cells = [];
    let cursor = 4;
    const end = 4 + payloadLen;
    while (cursor < end) {
        const { value, nextOffset } = parseLengthEncodedString(packet, cursor);
        cells.push(value);
        if (nextOffset === cursor)
            break;
        cursor = nextOffset;
    }
    let modified = false;
    const decryptedCells = cells.map((cell) => {
        if (cell && cell.startsWith('VOLLVALT:')) {
            modified = true;
            try {
                return (0, db_guard_1.decryptValue)(cell, keys);
            }
            catch {
                return cell;
            }
        }
        return cell;
    });
    if (!modified)
        return packet;
    const cellBuffers = decryptedCells.map((cell) => serializeLengthEncodedString(cell));
    const newPayload = Buffer.concat(cellBuffers);
    const header = Buffer.alloc(4);
    header.writeUIntLE(newPayload.length, 0, 3);
    header[3] = seqId;
    return Buffer.concat([header, newPayload]);
}
function handleMysqlConnection(clientSocket, options) {
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
        // Attempt decryption on MySQL response rows
        let processedData = data;
        try {
            processedData = decryptMysqlRow(data, options.resolvedKeys);
        }
        catch {
            // Fallback to raw on parse errors
        }
        if (clientSocket.writable) {
            clientSocket.write(processedData);
        }
    });
    clientSocket.on('data', (data) => {
        if (data.length > 5) {
            const packetLen = data.readUIntLE(0, 3);
            const command = data[4];
            if (command === 0x03 && !options.noWaf) { // COM_QUERY
                const query = data.toString('utf8', 5, 4 + packetLen);
                try {
                    (0, waf_js_1.validateQuery)(query, options.role);
                }
                catch (err) {
                    options.logSiem('WAF_MYSQL_BLOCK', 9, `MySQL WAF violation blocked: ${err.message}`);
                    const errPacket = serializeMysqlError(err.message, 1142, '42000');
                    clientSocket.write(errPacket);
                    return; // Halt and prevent forwarding to the backend DB
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
