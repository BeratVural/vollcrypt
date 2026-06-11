import * as net from 'net';
export declare function serializeOracleError(message: string): Buffer;
export declare function decryptOracleResponse(packet: Buffer, keys: Record<string, Buffer>): Buffer;
export declare function handleOracleConnection(clientSocket: net.Socket, options: {
    dbHost: string;
    dbPort: number;
    noWaf?: boolean;
    role: string;
    clientIp: string;
    resolvedKeys: Record<string, Buffer>;
    logSiem: (event: string, severity: number, message: string) => void;
}): void;
