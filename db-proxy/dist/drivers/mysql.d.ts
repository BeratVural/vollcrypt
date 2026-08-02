import * as net from 'net';
import { type ProxyConfig } from '../auth.js';
import { type DriverConnectionOptions } from './common.js';
/** Serializes a MySQL protocol error packet. */
export declare function serializeMysqlError(message: string, code?: number, sqlState?: string): Buffer;
/** Parses one MySQL length-encoded string from a packet. */
export declare function parseLengthEncodedString(buf: Buffer, offset: number): {
    value: string | null;
    nextOffset: number;
};
/** Serializes one value using the MySQL length-encoded string format. */
export declare function serializeLengthEncodedString(value: string | null): Buffer;
/** Decrypts encrypted cells in a MySQL text-row response packet. */
export declare function decryptMysqlResponse(packet: Buffer, keys: Record<string, Buffer>, role?: string, userId?: string, tenantId?: string, config?: ProxyConfig, modelName?: string, columns?: string[]): Buffer;
/** @deprecated Use decryptMysqlResponse. */
export declare const decryptMysqlRow: typeof decryptMysqlResponse;
/** Proxies one MySQL client connection with WAF and response decryption. */
export declare function handleMysqlConnection(clientSocket: net.Socket, options: DriverConnectionOptions): void;
