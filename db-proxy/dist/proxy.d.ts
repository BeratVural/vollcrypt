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
/** Authenticated gossip transport for DB Proxy cluster events. */
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
    /** Starts the authenticated gossip listener and heartbeat loop. */
    start(): Promise<void>;
    private startHeartbeatLoop;
    /** Signs and broadcasts a cluster message to configured peers. */
    broadcast(msg: ClusterMessage): void;
    /** Stops gossip I/O and destroys all peer sockets. */
    stop(): void;
}
/** Multi-protocol database proxy enforcing Vollcrypt security controls. */
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
    /** Registers a process-local SSO session when cluster mode is disabled. */
    registerSsoSession(username: string, passcode: string, roles: string[], ttlMs?: number): void;
    /** Registers a temporary process-local JIT role grant. */
    registerJitGrant(userId: string, role: string, durationMs: number): void;
    /** Writes a redacted CEF event to the configured SIEM log. */
    logSiemEvent(event: string, severity: number, username: string, clientIp: string, message: string): void;
    /** Closes tenant-scoped or global connections and zeroizes global keys. */
    triggerFailClosed(tenantId?: string): void;
    private sslKey;
    private sslCert;
    constructor(options: DbProxyOptions);
    private loadAllowlist;
    private saveAllowlist;
    private handleClusterMessage;
    /** Validates runtime security prerequisites and starts the proxy listener. */
    start(): Promise<void>;
    /** Stops listeners, cluster transport, and active connections. */
    stop(): Promise<void>;
    private handleConnection;
    private createPostgresConnectionRuntime;
    private attachPostgresClientListeners;
    private attachPostgresBackendListeners;
}
