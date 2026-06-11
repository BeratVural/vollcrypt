import * as net from 'net';
export declare function serializeMongoError(message: string, code?: number): Buffer;
export declare function handleMongoConnection(clientSocket: net.Socket, options: {
    dbHost: string;
    dbPort: number;
    noWaf?: boolean;
    role: string;
    clientIp: string;
    logSiem: (event: string, severity: number, message: string) => void;
}): void;
