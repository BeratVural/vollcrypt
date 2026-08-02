import type { DbGuardKeysOptions } from './kms';
export interface TenantKeyConfig {
    key?: Buffer | Record<string, Buffer>;
    kms?: DbGuardKeysOptions['kms'];
}
export interface MultiTenantKeyOptions {
    cacheTtlMs?: number;
    tenants?: Record<string, TenantKeyConfig>;
    getTenantConfig?: (tenantId: string) => Promise<TenantKeyConfig | undefined>;
}
export interface ResolvedTenantKeys {
    keys: Record<string, Buffer>;
    activeKey: Buffer;
    activeVersion: string;
}
interface TenantKeyResolverOptions extends DbGuardKeysOptions {
    activeKeyVersion?: string;
    multiTenant?: MultiTenantKeyOptions;
}
/** Creates one tenant-aware key resolver shared by all Node ORM adapters. */
export declare function createTenantKeyResolver(options: TenantKeyResolverOptions, globalKeys?: ResolvedTenantKeys): (tenantId: string | undefined) => ResolvedTenantKeys | Promise<ResolvedTenantKeys>;
export {};
