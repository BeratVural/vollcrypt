#!/usr/bin/env node
type MigrationDirection = 'up' | 'down';
export interface MigrationRuntimeOptions {
    direction: MigrationDirection;
    statementTimeoutMs: number;
    lockTimeoutMs: number;
    mongoMaxTimeMs: number;
}
export declare const DEFAULT_MIGRATION_OPTIONS: MigrationRuntimeOptions;
export declare function parsePositiveIntegerOption(value: string | undefined, fallback: number, label: string): number;
export declare function parseMigrationDirection(value: string | undefined): MigrationDirection;
export declare function assertSafeIdentifier(identifier: string, label: string): string;
export declare function buildPostgresBatchSelectSql(table: string, column: string, idCol: string, direction: MigrationDirection, hasLastId: boolean): string;
export declare function migratePostgresWithClient(client: {
    query: (sql: string, params?: any[]) => Promise<any>;
}, table: string, column: string, idCol: string, key: Buffer, version: string, chunkSize: number, options?: MigrationRuntimeOptions): Promise<number>;
export declare function migratePostgres(url: string, table: string, column: string, idCol: string, key: Buffer, version: string, chunkSize: number, options?: MigrationRuntimeOptions): Promise<number>;
export declare function migrateMongoCollection(collection: {
    countDocuments: (filter: any, options?: any) => Promise<number>;
    find: (filter: any) => any;
    updateOne: (filter: any, update: any, options?: any) => Promise<any>;
}, collectionName: string, field: string, idCol: string, key: Buffer, version: string, chunkSize: number, options?: MigrationRuntimeOptions): Promise<number>;
export declare function migrateMongo(url: string, collectionName: string, field: string, idCol: string, key: Buffer, version: string, chunkSize: number, options?: MigrationRuntimeOptions): Promise<number>;
export {};
