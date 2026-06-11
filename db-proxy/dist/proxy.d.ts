import { Buffer } from 'buffer';
import { ProxyConfig } from './auth.js';
export interface DbProxyOptions {
    port: number;
    dbHost: string;
    dbPort: number;
    config?: ProxyConfig;
    resolvedKeys: Record<string, Buffer>;
    dbPassword?: string;
}
/**
 * Serializes a PostgreSQL protocol ErrorResponse ('E') message.
 */
export declare function serializeErrorResponse(message: string, code?: string): Buffer;
export declare class DbProxyServer {
    private options;
    private server;
    private activeConnections;
    private allowlistedFingerprints;
    private activeSsoSessions;
    private activeJitGrants;
    registerSsoSession(username: string, passcode: string, roles: string[], ttlMs?: number): void;
    registerJitGrant(userId: string, role: string, durationMs: number): void;
    constructor(options: DbProxyOptions);
    private loadAllowlist;
    private saveAllowlist;
    start(): Promise<void>;
    stop(): Promise<void>;
    private handleConnection;
}
