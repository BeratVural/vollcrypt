import { RateLimiterOptions } from './security.js';
export interface DbGuardDriverOptions {
    key: Buffer | Record<string, Buffer>;
    activeKeyVersion?: string;
    entities: Record<string, string[]>;
    cryptoRbac?: {
        roles: Record<string, {
            decrypt: string[];
            mask?: Record<string, 'credit_card' | 'email' | 'tc_no' | ((v: any) => any) | string>;
        }>;
    };
    rateLimiter?: RateLimiterOptions;
}
export declare function wrapSqliteDatabase(db: any, options: DbGuardDriverOptions): any;
export declare function wrapOracleConnection(connection: any, options: DbGuardDriverOptions): any;
