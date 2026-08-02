import type { DbGuardKeysOptions } from './kms';
import type { CommonDbGuardSecurityOptions } from './contract';
import { MultiTenantKeyOptions } from './tenant';
export interface PrismaDbGuardOptions extends DbGuardKeysOptions, CommonDbGuardSecurityOptions {
    models: Record<string, string[]>;
    activeKeyVersion?: string;
    blindIndexes?: {
        rootSalt: Buffer;
        allowFrequencyLeakage: true;
        models: Record<string, string[]>;
    };
    multiTenant?: MultiTenantKeyOptions;
}
/**
 * Prisma DbGuard Extension Factory
 *
 * Bootstraps client-level field encryption, query translation, and automatic decryption.
 */
export declare const prismaDbGuard: (options: PrismaDbGuardOptions, resolvedKeys?: Record<string, Buffer>) => (client: any) => import("@prisma/client").PrismaClientExtends<import("@prisma/client/runtime/library").InternalArgs<{}, {}, {}, {}> & import("@prisma/client/runtime/library").DefaultArgs>;
export { encryptValue, decryptValue, rewriteQueryWhere, addBlindIndexes } from './security';
export { resolveKeys } from './kms';
