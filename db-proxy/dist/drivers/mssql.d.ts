import * as net from 'net';
import { type ProxyConfig } from '../auth.js';
import { type DriverConnectionOptions } from './common.js';
/** Serializes an MS-TDS error response packet. */
export declare function serializeMssqlError(message: string, code?: number): Buffer;
/**
 * Intercepts and decrypts VOLLVALT: values inside TDS 7.4 response streams.
 */
export declare function decryptMssqlResponse(packet: Buffer, keys: Record<string, Buffer>, role?: string, userId?: string, tenantId?: string, config?: ProxyConfig, modelName?: string, columns?: string[]): Buffer;
/** Parses ibUserName/cchUserName from an MS-TDS LOGIN7 packet. */
export declare function parseLogin7Username(packet: Buffer): string | null;
/** Proxies one MSSQL connection with LOGIN7 identity, WAF, and decryption. */
export declare function handleMssqlConnection(clientSocket: net.Socket, options: DriverConnectionOptions): void;
