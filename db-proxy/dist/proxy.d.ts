import { Buffer } from 'buffer';
import { ProxyConfig } from './auth.js';
export interface DbProxyOptions {
    port: number;
    dbHost: string;
    dbPort: number;
    config?: ProxyConfig;
    resolvedKeys: Record<string, Buffer>;
}
/**
 * Serializes a PostgreSQL protocol ErrorResponse ('E') message.
 */
export declare function serializeErrorResponse(message: string, code?: string): Buffer;
export declare class DbProxyServer {
    private options;
    private server;
    private activeConnections;
    constructor(options: DbProxyOptions);
    start(): Promise<void>;
    stop(): Promise<void>;
    private handleConnection;
}
