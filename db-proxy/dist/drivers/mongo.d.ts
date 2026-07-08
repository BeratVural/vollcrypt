import * as net from 'net';
export declare function parseBson(buf: Buffer, offset?: number): {
    value: any;
    nextOffset: number;
};
export declare function serializeBson(obj: any): Buffer;
export declare function decryptBsonObject(obj: any, keys: Record<string, Buffer>, role?: string, userId?: string, tenantId?: string, config?: any, depth?: number, collectionName?: string): any;
export declare function serializeMongoError(message: string, code?: number): Buffer;
export declare function handleMongoConnection(clientSocket: net.Socket, options: {
    dbHost: string;
    dbPort: number;
    noWaf?: boolean;
    role: string;
    clientIp: string;
    resolvedKeys: Record<string, Buffer>;
    config?: any;
    logSiem: (event: string, severity: number, message: string) => void;
}): void;
