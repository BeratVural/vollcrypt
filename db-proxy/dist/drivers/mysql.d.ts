import * as net from 'net';
export declare function serializeMysqlError(message: string, code?: number, sqlState?: string): Buffer;
export declare function parseLengthEncodedString(buf: Buffer, offset: number): {
    value: string | null;
    nextOffset: number;
};
export declare function serializeLengthEncodedString(value: string | null): Buffer;
export declare function decryptMysqlRow(packet: Buffer, keys: Record<string, Buffer>): Buffer;
export declare function handleMysqlConnection(clientSocket: net.Socket, options: {
    dbHost: string;
    dbPort: number;
    noWaf?: boolean;
    role: string;
    clientIp: string;
    resolvedKeys: Record<string, Buffer>;
    logSiem: (event: string, severity: number, message: string) => void;
}): void;
