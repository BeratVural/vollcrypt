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
    noAttestation?: boolean;
    noDlp?: boolean;
    noWaf?: boolean;
    noIpBanning?: boolean;
    dbType?: 'postgres' | 'mysql' | 'mongodb';
    fipsMode?: boolean;
    mpcShares?: Buffer[];
}
/**
 * Serializes a PostgreSQL protocol ErrorResponse ('E') message.
 */
export declare function serializeErrorResponse(message: string, code?: string): Buffer;
/**
 * Helper to serialize RowDescription ('T') packet.
 */
export declare function buildRowDescription(columns: string[]): Buffer;
export interface ClusterMessage {
    type: 'HEARTBEAT' | 'BAN_IP' | 'ALLOWLIST_FP' | 'DECRYPTION_USAGE';
    senderId: string;
    data: any;
}
export declare class ClusterManager {
    private nodeId;
    private gossipPort;
    private peers;
    private onMessage;
    private server;
    private peerSockets;
    constructor(nodeId: string, gossipPort: number, peers: string[], onMessage: (msg: ClusterMessage) => void);
    start(): Promise<void>;
    private startHeartbeatLoop;
    broadcast(msg: ClusterMessage): void;
    stop(): void;
}
export declare class DbProxyServer {
    private options;
    private server;
    private activeConnections;
    private allowlistedFingerprints;
    private activeSsoSessions;
    private activeJitGrants;
    private bannedIps;
    private clusterManager;
    private nodeId;
    registerSsoSession(username: string, passcode: string, roles: string[], ttlMs?: number): void;
    registerJitGrant(userId: string, role: string, durationMs: number): void;
    logSiemEvent(event: string, severity: number, username: string, clientIp: string, message: string): void;
    constructor(options: DbProxyOptions);
    private loadAllowlist;
    private saveAllowlist;
    private handleClusterMessage;
    start(): Promise<void>;
    stop(): Promise<void>;
    private handleConnection;
}
