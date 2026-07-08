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
exports.parseBson = parseBson;
exports.serializeBson = serializeBson;
exports.decryptBsonObject = decryptBsonObject;
exports.serializeMongoError = serializeMongoError;
exports.handleMongoConnection = handleMongoConnection;
const net = __importStar(require("net"));
const waf_js_1 = require("../waf.js");
const db_guard_1 = require("@vollcrypt/db-guard");
const auth_js_1 = require("../auth.js");
function parseBson(buf, offset = 0) {
    const size = buf.readInt32LE(offset);
    const end = offset + size;
    let cursor = offset + 4;
    const obj = {};
    while (cursor < end - 1) {
        const type = buf[cursor];
        cursor++;
        const keyEnd = buf.indexOf(0, cursor);
        if (keyEnd === -1 || keyEnd >= end)
            break;
        const key = buf.toString('utf8', cursor, keyEnd);
        cursor = keyEnd + 1;
        let value;
        if (type === 0x01) { // Double
            value = buf.readDoubleLE(cursor);
            cursor += 8;
        }
        else if (type === 0x02) { // String
            const strLen = buf.readInt32LE(cursor);
            cursor += 4;
            value = buf.toString('utf8', cursor, cursor + strLen - 1);
            cursor += strLen;
        }
        else if (type === 0x03 || type === 0x04) { // Document or Array
            const nested = parseBson(buf, cursor);
            value = nested.value;
            cursor = nested.nextOffset;
            if (type === 0x04) {
                value = Object.keys(value)
                    .sort((a, b) => parseInt(a, 10) - parseInt(b, 10))
                    .map((k) => value[k]);
            }
        }
        else if (type === 0x05) { // Binary
            const binLen = buf.readInt32LE(cursor);
            cursor += 5; // Length + Subtype
            value = buf.subarray(cursor, cursor + binLen);
            cursor += binLen;
        }
        else if (type === 0x08) { // Boolean
            value = buf[cursor] !== 0;
            cursor += 1;
        }
        else if (type === 0x0a) { // Null
            value = null;
        }
        else if (type === 0x10) { // Int32
            value = buf.readInt32LE(cursor);
            cursor += 4;
        }
        else if (type === 0x12) { // Int64
            value = buf.readBigInt64LE(cursor);
            cursor += 8;
        }
        else {
            break;
        }
        obj[key] = value;
    }
    return { value: obj, nextOffset: end };
}
function serializeBson(obj) {
    const buffers = [];
    for (const [key, val] of Object.entries(obj)) {
        const keyBuf = Buffer.from(key + '\0', 'utf8');
        if (val === null || val === undefined) {
            buffers.push(Buffer.concat([Buffer.from([0x0a]), keyBuf]));
        }
        else if (typeof val === 'number') {
            if (Number.isInteger(val)) {
                const valBuf = Buffer.alloc(4);
                valBuf.writeInt32LE(val, 0);
                buffers.push(Buffer.concat([Buffer.from([0x10]), keyBuf, valBuf]));
            }
            else {
                const valBuf = Buffer.alloc(8);
                valBuf.writeDoubleLE(val, 0);
                buffers.push(Buffer.concat([Buffer.from([0x01]), keyBuf, valBuf]));
            }
        }
        else if (typeof val === 'bigint') {
            const valBuf = Buffer.alloc(8);
            valBuf.writeBigInt64LE(val, 0);
            buffers.push(Buffer.concat([Buffer.from([0x12]), keyBuf, valBuf]));
        }
        else if (typeof val === 'string') {
            const valBuf = Buffer.from(val + '\0', 'utf8');
            const lenBuf = Buffer.alloc(4);
            lenBuf.writeInt32LE(valBuf.length, 0);
            buffers.push(Buffer.concat([Buffer.from([0x02]), keyBuf, lenBuf, valBuf]));
        }
        else if (typeof val === 'boolean') {
            buffers.push(Buffer.concat([Buffer.from([0x08]), keyBuf, Buffer.from([val ? 1 : 0])]));
        }
        else if (Buffer.isBuffer(val)) {
            const lenBuf = Buffer.alloc(4);
            lenBuf.writeInt32LE(val.length, 0);
            buffers.push(Buffer.concat([Buffer.from([0x05]), keyBuf, lenBuf, Buffer.from([0]), val]));
        }
        else if (Array.isArray(val)) {
            const arrayObj = {};
            for (let i = 0; i < val.length; i++) {
                arrayObj[i.toString()] = val[i];
            }
            const nestedBson = serializeBson(arrayObj);
            buffers.push(Buffer.concat([Buffer.from([0x04]), keyBuf, nestedBson]));
        }
        else if (typeof val === 'object') {
            const nestedBson = serializeBson(val);
            buffers.push(Buffer.concat([Buffer.from([0x03]), keyBuf, nestedBson]));
        }
    }
    const elements = Buffer.concat(buffers);
    const sizeBuf = Buffer.alloc(4);
    sizeBuf.writeInt32LE(elements.length + 5, 0);
    return Buffer.concat([sizeBuf, elements, Buffer.from([0x00])]);
}
function decryptBsonObject(obj, keys, role = 'GUEST', userId = 'guest-user', tenantId, config, depth = 0, collectionName = 'default') {
    if (depth > 5)
        return obj; // Prevent stack overflows
    if (obj === null || obj === undefined)
        return obj;
    if (Array.isArray(obj)) {
        return obj.map((item) => decryptBsonObject(item, keys, role, userId, tenantId, config, depth + 1, collectionName));
    }
    if (typeof obj === 'object' && !Buffer.isBuffer(obj)) {
        const copy = {};
        for (const [k, v] of Object.entries(obj)) {
            if (typeof v === 'string' && v.startsWith('VOLLVALT:')) {
                try {
                    copy[k] = db_guard_1.dbGuardContextStore.run({
                        role,
                        userId,
                        tenantId,
                        maxDecryptionsPerSecond: config?.rateLimiter?.maxDecryptionsPerSecond,
                        rateLimiterMode: config?.rateLimiter?.mode,
                    }, () => (0, db_guard_1.decryptWithSecurity)(v, (cipherText) => (0, db_guard_1.decryptValue)(cipherText, keys), collectionName, k, undefined, {
                        cryptoRbac: (0, auth_js_1.getRbacConfig)(config),
                        rateLimiter: config?.rateLimiter,
                    }));
                }
                catch (err) {
                    throw err;
                }
            }
            else {
                copy[k] = decryptBsonObject(v, keys, role, userId, tenantId, config, depth + 1, collectionName);
            }
        }
        return copy;
    }
    return obj;
}
function serializeMongoError(message, code = 13) {
    const okName = Buffer.from('ok\0', 'ascii');
    const okVal = Buffer.alloc(8);
    okVal.writeDoubleLE(0.0, 0);
    const msgName = Buffer.from('errmsg\0', 'ascii');
    const msgVal = Buffer.from(message + '\0', 'utf8');
    const msgLen = Buffer.alloc(4);
    msgLen.writeInt32LE(msgVal.length, 0);
    const codeName = Buffer.from('code\0', 'ascii');
    const codeVal = Buffer.alloc(4);
    codeVal.writeInt32LE(code, 0);
    const body = Buffer.concat([
        Buffer.from([0x01]), okName, okVal,
        Buffer.from([0x02]), msgName, msgLen, msgVal,
        Buffer.from([0x10]), codeName, codeVal,
        Buffer.from([0x00])
    ]);
    const docSize = Buffer.alloc(4);
    docSize.writeInt32LE(body.length + 4, 0);
    const bsonDoc = Buffer.concat([docSize, body]);
    const header = Buffer.alloc(21);
    header.writeInt32LE(16 + 4 + 1 + bsonDoc.length, 0);
    header.writeInt32LE(Math.floor(Math.random() * 100000), 4);
    header.writeInt32LE(0, 8);
    header.writeInt32LE(2013, 12); // OP_MSG
    header.writeInt32LE(0, 16);
    header[20] = 0x00;
    return Buffer.concat([header, bsonDoc]);
}
function handleMongoConnection(clientSocket, options) {
    let connected = false;
    const queue = [];
    let currentRole = options.role;
    let currentUserId = options.role === 'OWNER' ? 'usr-admin' : 'guest-user';
    let currentTenantId;
    let currentCollection = 'default';
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
        if (data.length > 21) {
            const opCode = data.readInt32LE(12);
            if (opCode === 2013) { // OP_MSG
                try {
                    const flags = data.readInt32LE(16);
                    const sectionType = data[20];
                    if (sectionType === 0x00) {
                        const bsonOffset = 21;
                        const { value: parsedDoc } = parseBson(data, bsonOffset);
                        const decryptedDoc = decryptBsonObject(parsedDoc, options.resolvedKeys, currentRole, currentUserId, currentTenantId, options.config, 0, currentCollection);
                        const newBson = serializeBson(decryptedDoc);
                        const newMsg = Buffer.alloc(21 + newBson.length);
                        newMsg.writeInt32LE(newMsg.length, 0);
                        data.copy(newMsg, 4, 4, 16); // Copy request info
                        newMsg.writeInt32LE(flags, 16);
                        newMsg[20] = 0x00;
                        newBson.copy(newMsg, 21);
                        if (clientSocket.writable) {
                            clientSocket.write(newMsg);
                        }
                        return;
                    }
                }
                catch (err) {
                    options.logSiem('MONGO_DECRYPT_ERROR', 8, `MongoDB decryption error: ${err.message}`);
                    const errPacket = serializeMongoError(err.message, 13);
                    clientSocket.write(errPacket);
                    return;
                }
            }
        }
        if (clientSocket.writable) {
            clientSocket.write(data);
        }
    });
    clientSocket.on('data', (data) => {
        if (data.length > 16) {
            const opCode = data.readInt32LE(12);
            if (opCode === 2013 || opCode === 2004) {
                // Parse username from handshake saslStart command if present
                if (opCode === 2013) {
                    const sectionType = data[20];
                    if (sectionType === 0x00) {
                        try {
                            const { value: commandDoc } = parseBson(data, 21);
                            if (commandDoc) {
                                const keys = Object.keys(commandDoc);
                                if (keys.length > 0) {
                                    const cmd = keys[0];
                                    const collectionVal = commandDoc[cmd];
                                    if (typeof collectionVal === 'string') {
                                        currentCollection = collectionVal;
                                    }
                                }
                            }
                            // Check saslStart or saslContinue command
                            if (commandDoc && commandDoc.saslStart) {
                                const payload = commandDoc.payload;
                                if (payload && Buffer.isBuffer(payload)) {
                                    const payloadStr = payload.toString('utf8');
                                    // SASL client first message usually looks like "n,,n=username,r=..." or "n=username,r=..."
                                    const match = payloadStr.match(/\bn=([^,]+)/);
                                    if (match && match[1]) {
                                        const username = match[1];
                                        const userContext = (0, auth_js_1.resolveUserContext)(username, options.config);
                                        currentUserId = userContext.userId;
                                        currentRole = userContext.role;
                                        currentTenantId = userContext.tenantId;
                                    }
                                }
                            }
                        }
                        catch (e) {
                            // Ignore BSON parsing error in incoming request, WAF might still handle it
                        }
                    }
                }
                if (!options.noWaf) {
                    const payloadStr = data.toString('utf8');
                    try {
                        if (payloadStr.includes('dropDatabase') || payloadStr.includes('$where')) {
                            throw new Error('Dangerous command dropDatabase or $where is not allowed');
                        }
                        (0, waf_js_1.validateQuery)(payloadStr, currentRole);
                    }
                    catch (err) {
                        options.logSiem('WAF_MONGO_BLOCK', 9, `MongoDB WAF violation blocked: ${err.message}`);
                        const errPacket = serializeMongoError(err.message, 13);
                        clientSocket.write(errPacket);
                        return;
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
