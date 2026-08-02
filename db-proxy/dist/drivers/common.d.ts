import type * as net from 'net';
import { type ProxyConfig, type ProxyUserContext } from '../auth.js';
/** Shared connection options implemented by every protocol driver. */
export interface DriverConnectionOptions {
    dbHost: string;
    dbPort: number;
    noWaf?: boolean;
    role: string;
    clientIp: string;
    resolvedKeys: Record<string, Buffer>;
    config?: ProxyConfig;
    logSiem: (event: string, severity: number, message: string) => void;
}
/** Security context required to decrypt one protocol value. */
export interface DriverDecryptContext {
    keys: Record<string, Buffer>;
    role: string;
    userId: string;
    tenantId?: string;
    config?: ProxyConfig;
}
/** Common callable contract for protocol connection handlers. */
export type DriverConnectionHandler = (clientSocket: net.Socket, options: DriverConnectionOptions) => void;
/** Creates the fail-closed initial identity for a new database connection. */
export declare function createInitialUserContext(role: string): ProxyUserContext;
/** Resolves a projected column qualifier into DB Guard model and field names. */
export declare function resolveProjectedField(projectedColumn: string | undefined, modelName: string, fallbackField: string): {
    model: string;
    field: string;
};
/** Runs one field decryption through the shared DB Guard security context. */
export declare function decryptDriverValue(ciphertext: string, model: string, field: string, context: DriverDecryptContext): string;
