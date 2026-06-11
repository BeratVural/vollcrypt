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
exports.handleMysqlConnection = handleMysqlConnection;
const net = __importStar(require("net"));
const waf_js_1 = require("../waf.js");
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
function handleMysqlConnection(clientSocket, options) {
    const backendSocket = net.connect({
        host: options.dbHost,
        port: options.dbPort,
    });
    clientSocket.pipe(backendSocket);
    backendSocket.on('data', (data) => {
        if (clientSocket.writable) {
            clientSocket.write(data);
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
                }
            }
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
