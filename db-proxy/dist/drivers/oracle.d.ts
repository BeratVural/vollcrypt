import * as net from 'net';
import { type ProxyConfig } from '../auth.js';
import { type DriverConnectionOptions } from './common.js';
/** Serializes an Oracle TNS refusal packet. */
export declare function serializeOracleError(message: string): Buffer;
/** Decrypts encrypted values in an Oracle TNS data response. */
export declare function decryptOracleResponse(packet: Buffer, keys: Record<string, Buffer>, role?: string, userId?: string, tenantId?: string, config?: ProxyConfig, modelName?: string, columns?: string[]): Buffer;
/** Proxies one Oracle connection with identity, WAF, and decryption. */
export declare function handleOracleConnection(clientSocket: net.Socket, options: DriverConnectionOptions): void;
