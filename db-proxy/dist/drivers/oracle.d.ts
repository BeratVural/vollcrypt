import * as net from 'net';
export declare function serializeOracleError(message: string): Buffer;
export declare function decryptOracleResponse(packet: Buffer, keys: Record<string, Buffer>, role?: string, userId?: string, tenantId?: string, config?: any, modelName?: string, columns?: string[]): Buffer;
export declare function handleOracleConnection(clientSocket: net.Socket, options: {
    dbHost: string;
    dbPort: number;
    noWaf?: boolean;
    role: string;
    clientIp: string;
    resolvedKeys: Record<string, Buffer>;
    config?: any;
    logSiem: (event: string, severity: number, message: string) => void;
}): void;
