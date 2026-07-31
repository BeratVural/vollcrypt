import { Buffer } from 'buffer';
import { ProxyConfig } from './auth.js';
export interface DbProxyOptions {
    port: number;
    dbHost: string;
    dbPort: number;
    config?: ProxyConfig;
    resolvedKeys: Record<string, Buffer>;
    dbPassword?: string;
    gossipPort?: number;
    peers?: string[];
    minResponseTimeMs?: number;
    noDlp?: boolean;
    noWaf?: boolean;
    noIpBanning?: boolean;
    dbType?: 'postgres' | 'mysql' | 'mongodb' | 'mssql' | 'oracle';
    fipsMode?: boolean;
    xorKeySplitShares?: Buffer[];
    xorKeySplitExpectedShares?: number;
    allowSingleProcessXorKeySplit?: true;
    tls?: {
        keyPath?: string;
        certPath?: string;
        allowEphemeralSelfSigned?: boolean;
    };
}
/**
 * Serializes a PostgreSQL protocol ErrorResponse ('E') message.
 */
export declare function serializeErrorResponse(message: string, code?: string): Buffer;
/**
 * Helper to serialize RowDescription ('T') packet.
 */
export declare function buildRowDescription(columns: string[]): Buffer;
export declare class FipsStartupError extends Error {
    readonly code = "ERR_FIPS_RUNTIME_INACTIVE";
    constructor();
}
export declare function canonicalizeJson(value: unknown): string;
export interface ClusterMessage {
    type: 'HEARTBEAT' | 'BAN_IP' | 'ALLOWLIST_FP' | 'DECRYPTION_USAGE';
    senderId: string;
    data: any;
    timestamp?: number;
    signature?: string;
}
export declare class ClusterManager {
    private nodeId;
    private gossipPort;
    private peers;
    private gossipSecret;
    private onMessage;
    private server;
    private peerSockets;
    private acceptedSignatures;
    constructor(nodeId: string, gossipPort: number, peers: string[], gossipSecret: string, onMessage: (msg: ClusterMessage) => void);
    private signMessage;
    private verifyMessage;
    start(): Promise<void>;
    private startHeartbeatLoop;
    broadcast(msg: ClusterMessage): void;
    stop(): void;
}
export declare class DbProxyServer {
    private options;
    private server;
    private activeConnections;
    private socketTenantIds;
    private allowlistedFingerprints;
    private activeSsoSessions;
    private activeJitGrants;
    private bannedIps;
    private clusterManager;
    private nodeId;
    private gossipSecret;
    private jitSecret;
    private anomalyScorer;
    private isClusterModeConfigured;
    registerSsoSession(username: string, passcode: string, roles: string[], ttlMs?: number): void;
    registerJitGrant(userId: string, role: string, durationMs: number): void;
    logSiemEvent(event: string, severity: number, username: string, clientIp: string, message: string): void;
    triggerFailClosed(tenantId?: string): void;
    private sslKey;
    private sslCert;
    constructor(options: DbProxyOptions);
    private loadAllowlist;
    private saveAllowlist;
    private handleClusterMessage;
    start(): Promise<void>;
    stop(): Promise<void>;
    private handleConnection;
}
