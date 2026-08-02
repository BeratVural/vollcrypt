import * as net from 'net';
import { type ProxyConfig } from '../auth.js';
import { type DriverConnectionOptions } from './common.js';
/** Parses one BSON document and returns its next byte offset. */
export declare function parseBson(buf: Buffer, offset?: number): {
    value: any;
    nextOffset: number;
};
/** Serializes a JavaScript document into BSON bytes. */
export declare function serializeBson(obj: any): Buffer;
/** Decrypts encrypted values in a MongoDB response document. */
export declare function decryptMongoResponse(obj: any, keys: Record<string, Buffer>, role?: string, userId?: string, tenantId?: string, config?: ProxyConfig, collectionName?: string): any;
/** @deprecated Use decryptMongoResponse. */
export declare const decryptBsonObject: typeof decryptMongoResponse;
/** Serializes a MongoDB OP_MSG authorization error. */
export declare function serializeMongoError(message: string, code?: number): Buffer;
/** Proxies one MongoDB connection with command filtering and decryption. */
export declare function handleMongoConnection(clientSocket: net.Socket, options: DriverConnectionOptions): void;
