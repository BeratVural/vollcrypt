import { DbGuardKeysOptions } from './kms';
import { RateLimiterOptions } from './security';
export interface PrismaDbGuardOptions extends DbGuardKeysOptions {
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
 * Prisma DbGuard Extension Factory
 *
 * Bootstraps client-level field encryption, query translation, and automatic decryption.
 */
export declare const prismaDbGuard: (options: PrismaDbGuardOptions, resolvedKeys?: Record<string, Buffer>) => (client: any) => import("@prisma/client").PrismaClientExtends<import("@prisma/client/runtime/library").InternalArgs<{}, {}, {}, {}> & import("@prisma/client/runtime/library").DefaultArgs>;
export { encryptValue, decryptValue, rewriteQueryWhere, addBlindIndexes } from './security';
export { resolveKeys } from './kms';
