import * as net from 'net';
export declare function serializeMysqlError(message: string, code?: number, sqlState?: string): Buffer;
export declare function handleMysqlConnection(clientSocket: net.Socket, options: {
    dbHost: string;
    dbPort: number;
    noWaf?: boolean;
    role: string;
    clientIp: string;
    logSiem: (event: string, severity: number, message: string) => void;
}): void;
