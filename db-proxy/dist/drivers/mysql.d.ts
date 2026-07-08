import * as net from 'net';
export declare function serializeMysqlError(message: string, code?: number, sqlState?: string): Buffer;
export declare function parseLengthEncodedString(buf: Buffer, offset: number): {
    value: string | null;
    nextOffset: number;
};
export declare function serializeLengthEncodedString(value: string | null): Buffer;
export declare function decryptMysqlRow(packet: Buffer, keys: Record<string, Buffer>, role?: string, userId?: string, tenantId?: string, config?: any, modelName?: string, columns?: string[]): Buffer;
export declare function handleMysqlConnection(clientSocket: net.Socket, options: {
    dbHost: string;
    dbPort: number;
    noWaf?: boolean;
    role: string;
    clientIp: string;
    resolvedKeys: Record<string, Buffer>;
    config?: any;
    logSiem: (event: string, severity: number, message: string) => void;
}): void;
