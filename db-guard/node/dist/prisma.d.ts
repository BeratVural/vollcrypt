import { KmsProvider } from './kms';
import { RateLimiterOptions } from './security';
export interface PrismaDbGuardOptions {
    key?: Buffer | Record<string, Buffer>;
    kms?: {
        provider: KmsProvider;
        wrappedKey: Buffer | Record<string, Buffer>;
        wrappedKek?: Buffer | Record<string, Buffer>;
        activeKeyVersion?: string;
    };
    models: Record<string, string[]>;
    blindIndexes?: {
        rootSalt: Buffer;
        models: Record<string, string[]>;
    };
    cryptoRbac?: {
        roles: Record<string, {
            decrypt: string[];
            mask?: Record<string, 'credit_card' | 'email' | 'tc_no' | ((v: any) => any) | string>;
        }>;
    };
    rateLimiter?: RateLimiterOptions;
    multiTenant?: {
        tenants?: Record<string, {
            key?: Buffer | Record<string, Buffer>;
            kms?: any;
        }>;
        getTenantConfig?: (tenantId: string) => Promise<{
            key?: Buffer | Record<string, Buffer>;
            kms?: any;
        } | undefined>;
    };
}
/**
 * Resolves the plaintext keys asynchronously from local config or KMS provider.
 */
export declare function resolveKeys(options: PrismaDbGuardOptions): Promise<Record<string, Buffer>>;
export declare function encryptValue(val: any, key: Buffer, version: string): string;
export declare function decryptValue(stored: any, keys: Record<string, Buffer>): any;
/**
 * Traverses query `where` arguments to rewrite exact match queries on encrypted fields
 * to target shadow `_bidx` columns using dynamic HKDF-SHA256 blind indexing.
 */
export declare function rewriteQueryWhere(where: any, fields: string[], rootSalt: Buffer, modelName: string): void;
/**
 * Appends calculated blind indexes to the write payload (create/update).
 */
export declare function addBlindIndexes(data: any, fields: string[], rootSalt: Buffer, modelName: string): void;
/**
 * Prisma DbGuard Extension Factory
 *
 * Bootstraps client-level field encryption, query translation, and automatic decryption.
 */
export declare const prismaDbGuard: (options: PrismaDbGuardOptions, resolvedKeys?: Record<string, Buffer>) => (client: any) => import("@prisma/client").PrismaClientExtends<import("@prisma/client/runtime/library").InternalArgs<{}, {}, {}, {}> & import("@prisma/client/runtime/library").DefaultArgs>;
