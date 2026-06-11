import * as net from 'net';
export declare function serializeMssqlError(message: string, code?: number): Buffer;
/**
 * Intercepts and decrypts VOLLVALT: values inside TDS 7.4 response streams.
 */
export declare function decryptMssqlResponse(packet: Buffer, keys: Record<string, Buffer>): Buffer;
export declare function handleMssqlConnection(clientSocket: net.Socket, options: {
    dbHost: string;
    dbPort: number;
    noWaf?: boolean;
    role: string;
    clientIp: string;
    resolvedKeys: Record<string, Buffer>;
    logSiem: (event: string, severity: number, message: string) => void;
}): void;
