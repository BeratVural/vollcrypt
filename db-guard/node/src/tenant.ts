import { dbGuardError } from './errors';
import type { DbGuardKeysOptions } from './kms';
import { resolveKeys } from './kms';
import { normalizeKeys } from './keys';
import {
  getBreakGlassKey,
  getCachedKey,
  isBreakGlassActive,
  registerKeysForZeroization,
  setCachedKey
} from './security';

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
export function createTenantKeyResolver(
  options: TenantKeyResolverOptions,
  globalKeys?: ResolvedTenantKeys
): (tenantId: string | undefined) => ResolvedTenantKeys | Promise<ResolvedTenantKeys> {
  return (tenantId: string | undefined) => {
    const breakGlassTenant = options.multiTenant ? tenantId : undefined;
    if (isBreakGlassActive(breakGlassTenant)) {
      const breakGlassKey = getBreakGlassKey(breakGlassTenant);
      if (breakGlassKey) {
        return { keys: { '1': breakGlassKey }, activeKey: breakGlassKey, activeVersion: '1' };
      }
    }

    if (options.multiTenant && !tenantId) {
      throw dbGuardError('Vollcrypt DbGuard: tenantId must be provided in multi-tenant mode.');
    }

    if (!options.multiTenant) {
      if (!globalKeys) {
        throw dbGuardError('Vollcrypt DbGuard: Global keys are not resolved.');
      }
      return globalKeys;
    }

    const tId = tenantId as string;
    const requestedVersion = options.activeKeyVersion || options.kms?.activeKeyVersion || '1';
    const cachedActiveKey = getCachedKey(tId, requestedVersion);
    if (cachedActiveKey) {
      return {
        keys: { [requestedVersion]: cachedActiveKey },
        activeKey: cachedActiveKey,
        activeVersion: requestedVersion
      };
    }

    return (async () => {
      const multiTenant = options.multiTenant as MultiTenantKeyOptions;
      const tenantConfig = multiTenant.tenants
        ? multiTenant.tenants[tId]
        : await multiTenant.getTenantConfig?.(tId);

      if (!tenantConfig) {
        throw dbGuardError('Vollcrypt DbGuard: Configuration not found for tenantId "' + tId + '".');
      }

      const rawKeys = await resolveKeys({
        ...options,
        key: tenantConfig.key,
        kms: tenantConfig.kms
      });
      const requestedTenantVersion = tenantConfig.kms?.activeKeyVersion || '1';
      const resolved = normalizeKeys(rawKeys, requestedTenantVersion);
      registerKeysForZeroization(resolved.keys, tId);

      for (const [version, key] of Object.entries(resolved.keys)) {
        setCachedKey(tId, version, key, multiTenant.cacheTtlMs);
      }

      return resolved;
    })();
  };
}