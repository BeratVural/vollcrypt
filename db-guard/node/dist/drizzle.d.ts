import type { CommonDbGuardSecurityOptions } from './contract';
export interface DrizzleDbGuardOptions extends CommonDbGuardSecurityOptions {
    key: Buffer | Record<string, Buffer>;
    activeKeyVersion?: string;
    blindIndexes?: {
        rootSalt: Buffer;
        allowFrequencyLeakage: true;
    };
}
/**
 * Creates encrypted and blind-index Drizzle custom column types for supported SQL dialects.
 */
export declare const createDrizzleGuard: (options: DrizzleDbGuardOptions) => {
    pgText: (name: string, columnPath?: string) => import("drizzle-orm/pg-core").PgCustomColumnBuilder<{
        name: string;
        dataType: "custom";
        columnType: "PgCustomColumn";
        data: unknown;
        driverParam: unknown;
        enumValues: undefined;
    }>;
    mysqlText: (name: string, columnPath?: string) => import("drizzle-orm/mysql-core").MySqlCustomColumnBuilder<{
        name: string;
        dataType: "custom";
        columnType: "MySqlCustomColumn";
        data: unknown;
        driverParam: unknown;
        enumValues: undefined;
    }>;
    sqliteText: (name: string, columnPath?: string) => import("drizzle-orm/sqlite-core").SQLiteCustomColumnBuilder<{
        name: string;
        dataType: "custom";
        columnType: "SQLiteCustomColumn";
        data: unknown;
        driverParam: unknown;
        enumValues: undefined;
    }>;
    pgBlindIndex: (name: string, columnName: string) => import("drizzle-orm/pg-core").PgCustomColumnBuilder<{
        name: string;
        dataType: "custom";
        columnType: "PgCustomColumn";
        data: unknown;
        driverParam: unknown;
        enumValues: undefined;
    }>;
    mysqlBlindIndex: (name: string, columnName: string) => import("drizzle-orm/mysql-core").MySqlCustomColumnBuilder<{
        name: string;
        dataType: "custom";
        columnType: "MySqlCustomColumn";
        data: unknown;
        driverParam: unknown;
        enumValues: undefined;
    }>;
    sqliteBlindIndex: (name: string, columnName: string) => import("drizzle-orm/sqlite-core").SQLiteCustomColumnBuilder<{
        name: string;
        dataType: "custom";
        columnType: "SQLiteCustomColumn";
        data: unknown;
        driverParam: unknown;
        enumValues: undefined;
    }>;
};
