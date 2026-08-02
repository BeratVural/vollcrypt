import type { CommonDbGuardSecurityOptions } from './contract';
export interface DbGuardDriverOptions extends CommonDbGuardSecurityOptions {
    key: Buffer | Record<string, Buffer>;
    activeKeyVersion?: string;
    entities: Record<string, string[]>;
}
/**
 * Wraps a SQLite-compatible database and enforces parameterized encrypted writes.
 */
export declare function wrapSqliteDatabase(db: any, options: DbGuardDriverOptions): any;
/**
 * Wraps an Oracle connection and encrypts configured bind values before execution.
 */
export declare function wrapOracleConnection(connection: any, options: DbGuardDriverOptions): any;
