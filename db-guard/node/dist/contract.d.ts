import type { PrismaDbGuardOptions } from './prisma';
import type { MongooseDbGuardOptions } from './mongoose';
import type { DrizzleDbGuardOptions } from './drizzle';
import type { TypeOrmDbGuardOptions } from './typeorm';
import type { RateLimiterOptions } from './security';
export declare const DB_GUARD_CONTRACT_VERSION: 1;
export declare const SUPPORTED_KEY_VERSIONS: readonly ["1", "2"];
export type DbGuardContractErrorCode = 'UNSUPPORTED_CONTRACT_VERSION' | 'INVALID_KEYRING' | 'INVALID_RESOURCE_SCOPE' | 'RESOURCE_NOT_FOUND';
export declare class DbGuardContractError extends Error {
    readonly code: DbGuardContractErrorCode;
    constructor(code: DbGuardContractErrorCode, message: string);
}
export type DbGuardMask = 'credit_card' | 'email' | 'tc_no' | ((value: any) => any) | string;
export interface CryptoRbacConfig {
    roles: Record<string, {
        decrypt: string[];
        mask?: Record<string, DbGuardMask>;
    }>;
}
export interface CommonDbGuardSecurityOptions {
    cryptoRbac?: CryptoRbacConfig;
    rateLimiter?: RateLimiterOptions;
    allowUnrestrictedDecrypt?: boolean;
}
export interface DbGuardContractV1 {
    contractVersion: typeof DB_GUARD_CONTRACT_VERSION;
    keyring: {
        keys: Buffer | Record<string, Buffer>;
        activeVersion?: string;
    };
    resources: Record<string, string[]>;
    blindIndexes?: {
        rootSalt: Buffer;
        allowFrequencyLeakage: true;
        resources: Record<string, string[]>;
    };
    security?: CommonDbGuardSecurityOptions;
}
export declare function validateDbGuardContract(contract: DbGuardContractV1): void;
export declare function toPrismaDbGuardOptions(contract: DbGuardContractV1): PrismaDbGuardOptions;
export declare function toMongooseDbGuardOptions(contract: DbGuardContractV1, resource: string): MongooseDbGuardOptions;
export declare function toDrizzleDbGuardOptions(contract: DbGuardContractV1): DrizzleDbGuardOptions;
export declare function toTypeOrmDbGuardOptions(contract: DbGuardContractV1): TypeOrmDbGuardOptions;
