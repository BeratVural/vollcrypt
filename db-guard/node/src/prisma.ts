import type { Prisma as PrismaNamespace } from '@prisma/client';
import { KmsProvider, resolveKeys, DbGuardKeysOptions } from './kms';
import {
  registerKeysForZeroization,
  decryptWithSecurity,
  RateLimiterOptions,
  checkPageSize,
  dbGuardContextStore,
  parseCiphertext,
  CRYPTO_ALGORITHMS,
  isBreakGlassActive,
  getBreakGlassKey,
  getCachedKey,
  setCachedKey,
  getFailClosedStatus,
  encryptValue,
  decryptValue,
  rewriteQueryWhere,
  addBlindIndexes,
  computeBlindIndex
} from './security';

export interface PrismaDbGuardOptions extends DbGuardKeysOptions {
  models: Record<string, string[]>; // fields to encrypt/decrypt
  blindIndexes?: {
    rootSalt: Buffer;
    models: Record<string, string[]>; // fields to calculate blind indexes for
  };
  cryptoRbac?: {
    roles: Record<string, {
      decrypt: string[];
      mask?: Record<string, 'credit_card' | 'email' | 'tc_no' | ((v: any) => any) | string>;
    }>;
  };
  rateLimiter?: RateLimiterOptions;
  multiTenant?: {
    tenants?: Record<string, { key?: Buffer | Record<string, Buffer>; kms?: any }>;
    getTenantConfig?: (tenantId: string) => Promise<{ key?: Buffer | Record<string, Buffer>; kms?: any } | undefined>;
  };
}

/**
 * Prisma DbGuard Extension Factory
 *
 * Bootstraps client-level field encryption, query translation, and automatic decryption.
 */
export const prismaDbGuard = (options: PrismaDbGuardOptions, resolvedKeys?: Record<string, Buffer>) => {
  let keys = resolvedKeys;
  if (!keys) {
    if (options.key) {
      if (Buffer.isBuffer(options.key)) {
        keys = { '1': Buffer.from(options.key) };
      } else {
        keys = {};
        for (const [v, k] of Object.entries(options.key)) {
          keys[v] = Buffer.from(k);
        }
      }
    } else if (options.kms || options.multiTenant) {
      // Keys might be resolved dynamically per tenant, or resolved later
    } else {
      throw new Error("Resolved keys must be provided as the second argument when using KMS.");
    }
  }

  if (keys) {
    const clonedKeys: Record<string, Buffer> = {};
    for (const [v, k] of Object.entries(keys)) {
      clonedKeys[v] = Buffer.from(k);
    }
    keys = clonedKeys;
    registerKeysForZeroization(keys);
  }

  const activeVersion = options.kms?.activeKeyVersion || '1';
  const activeKey = keys ? keys[activeVersion] : undefined;

  const resolveTenantKeysAndActiveKey = async (tenantId: string | undefined): Promise<{ keys: Record<string, Buffer>; activeKey: Buffer; activeVersion: string }> => {
    if (isBreakGlassActive()) {
      const bgKey = getBreakGlassKey();
      if (bgKey) {
        return { keys: { '1': bgKey }, activeKey: bgKey, activeVersion: '1' };
      }
    }

    if (options.multiTenant && !tenantId) {
      throw new Error("Vollcrypt Security: tenantId must be provided in multi-tenant mode.");
    }

    if (!options.multiTenant) {
      if (!keys || !activeKey) {
        throw new Error("Vollcrypt Security: Global keys are not resolved.");
      }
      return { keys, activeKey, activeVersion };
    }

    const tId = tenantId!;

    // Check Secure TTL Cache
    const cachedActiveKey = getCachedKey(tId, activeVersion);
    if (cachedActiveKey) {
      return { keys: { [activeVersion]: cachedActiveKey }, activeKey: cachedActiveKey, activeVersion };
    }

    // Cache miss: resolve configuration
    let tenantConfig: { key?: Buffer | Record<string, Buffer>; kms?: any } | undefined;
    if (options.multiTenant.tenants) {
      tenantConfig = options.multiTenant.tenants[tId];
    } else if (options.multiTenant.getTenantConfig) {
      tenantConfig = await options.multiTenant.getTenantConfig(tId);
    }

    if (!tenantConfig) {
      throw new Error(`Vollcrypt Security: Configuration not found for tenantId "${tId}".`);
    }

    const resolvedTenantKeysRaw = await resolveKeys({
      ...options,
      key: tenantConfig.key,
      kms: tenantConfig.kms
    } as any);

    const resolvedTenantKeys: Record<string, Buffer> = {};
    for (const [v, k] of Object.entries(resolvedTenantKeysRaw)) {
      resolvedTenantKeys[v] = Buffer.from(k);
    }

    registerKeysForZeroization(resolvedTenantKeys, tId);

    const tActiveVersion = tenantConfig.kms?.activeKeyVersion || '1';
    const tActiveKey = resolvedTenantKeys[tActiveVersion];
    if (!tActiveKey) {
      throw new Error(`Vollcrypt Security: Active key version "${tActiveVersion}" not found for tenantId "${tId}".`);
    }

    for (const [ver, keyBuf] of Object.entries(resolvedTenantKeys)) {
      setCachedKey(tId, ver, keyBuf);
    }

    return { keys: resolvedTenantKeys, activeKey: tActiveKey, activeVersion: tActiveVersion };
  };

  const encryptPayload = (modelName: string, data: any, encKey: Buffer, encVer: string) => {
    const fieldsToEncrypt = options.models[modelName];
    if (!fieldsToEncrypt || !data || typeof data !== 'object') return data;

    const cloned = { ...data };
    for (const field of fieldsToEncrypt) {
      if (cloned[field] !== undefined) {
        cloned[field] = encryptValue(cloned[field], encKey, encVer);
      }
    }
    return cloned;
  };

  const decryptResult = (modelName: string, result: any, decKeys: Record<string, Buffer>): any => {
    const fieldsToEncrypt = options.models[modelName];
    if (!fieldsToEncrypt || !result) return result;

    if (Array.isArray(result)) {
      const pageSizeStatus = checkPageSize(result.length, options.rateLimiter);
      if (pageSizeStatus === 'bypass') {
        const currentCtx = dbGuardContextStore.getStore() || {};
        return dbGuardContextStore.run({ ...currentCtx, bypassRateLimit: true }, () => {
          return result.map((item) => decryptResult(modelName, item, decKeys));
        });
      }
      return result.map((item) => decryptResult(modelName, item, decKeys));
    }

    if (typeof result !== 'object') return result;

    const cloned = { ...result };
    for (const field of fieldsToEncrypt) {
      if (cloned[field] !== undefined) {
        cloned[field] = decryptWithSecurity(
          cloned[field],
          (val) => decryptValue(val, decKeys),
          modelName,
          field,
          cloned.id || cloned._id,
          options
        );
      }
    }
    return cloned;
  };

  const processWriteQuery = (modelName: string, args: any, encKey: Buffer, encVer: string) => {
    if (!args) return;
    
    // Encrypt write payload
    if (args.data) {
      args.data = encryptPayload(modelName, args.data, encKey, encVer);
    }
    if (args.create) {
      args.create = encryptPayload(modelName, args.create, encKey, encVer);
    }
    if (args.update) {
      args.update = encryptPayload(modelName, args.update, encKey, encVer);
    }

    // Add blind indexes if enabled
    const bidxFields = options.blindIndexes?.models[modelName];
    if (bidxFields && options.blindIndexes?.rootSalt) {
      if (args.data) {
        addBlindIndexes(args.data, bidxFields, options.blindIndexes.rootSalt, modelName);
      }
      if (args.create) {
        addBlindIndexes(args.create, bidxFields, options.blindIndexes.rootSalt, modelName);
      }
      if (args.update) {
        addBlindIndexes(args.update, bidxFields, options.blindIndexes.rootSalt, modelName);
      }
    }
  };

  const processReadQuery = (modelName: string, args: any) => {
    if (!args) return;

    // Rewrite queries targeting encrypted columns to use the blind index column
    const bidxFields = options.blindIndexes?.models[modelName];
    if (bidxFields && options.blindIndexes?.rootSalt && args.where) {
      rewriteQueryWhere(args.where, bidxFields, options.blindIndexes.rootSalt, modelName);
    }
  };

  const { Prisma } = require('@prisma/client') as { Prisma: typeof PrismaNamespace };
  return Prisma.defineExtension((client) => {
    return client.$extends({
      name: 'vollcrypt-db-guard',
      query: {
        $allModels: {
          async create({ model, args, query }) {
            const context = dbGuardContextStore.getStore();
            const resolved = await resolveTenantKeysAndActiveKey(context?.tenantId);
            processWriteQuery(model, args, resolved.activeKey, resolved.activeVersion);
            const result = await query(args);
            return decryptResult(model, result, resolved.keys);
          },
          async createMany({ model, args, query }) {
            const context = dbGuardContextStore.getStore();
            const resolved = await resolveTenantKeysAndActiveKey(context?.tenantId);
            if (args.data) {
              if (Array.isArray(args.data)) {
                args.data = args.data.map((item) => {
                  const encrypted = encryptPayload(model, item, resolved.activeKey, resolved.activeVersion);
                  const bidxFields = options.blindIndexes?.models[model];
                  if (bidxFields && options.blindIndexes?.rootSalt) {
                    addBlindIndexes(encrypted, bidxFields, options.blindIndexes.rootSalt, model);
                  }
                  return encrypted;
                });
              } else {
                processWriteQuery(model, args, resolved.activeKey, resolved.activeVersion);
              }
            }
            const result = await query(args);
            return decryptResult(model, result, resolved.keys);
          },
          async update({ model, args, query }) {
            const context = dbGuardContextStore.getStore();
            const resolved = await resolveTenantKeysAndActiveKey(context?.tenantId);
            processWriteQuery(model, args, resolved.activeKey, resolved.activeVersion);
            processReadQuery(model, args);
            const result = await query(args);
            return decryptResult(model, result, resolved.keys);
          },
          async updateMany({ model, args, query }) {
            const context = dbGuardContextStore.getStore();
            const resolved = await resolveTenantKeysAndActiveKey(context?.tenantId);
            processWriteQuery(model, args, resolved.activeKey, resolved.activeVersion);
            processReadQuery(model, args);
            const result = await query(args);
            return decryptResult(model, result, resolved.keys);
          },
          async upsert({ model, args, query }) {
            const context = dbGuardContextStore.getStore();
            const resolved = await resolveTenantKeysAndActiveKey(context?.tenantId);
            processWriteQuery(model, args, resolved.activeKey, resolved.activeVersion);
            processReadQuery(model, args);
            const result = await query(args);
            return decryptResult(model, result, resolved.keys);
          },
          async findFirst({ model, args, query }) {
            const context = dbGuardContextStore.getStore();
            const resolved = await resolveTenantKeysAndActiveKey(context?.tenantId);
            processReadQuery(model, args);
            const result = await query(args);
            return decryptResult(model, result, resolved.keys);
          },
          async findUnique({ model, args, query }) {
            const context = dbGuardContextStore.getStore();
            const resolved = await resolveTenantKeysAndActiveKey(context?.tenantId);
            processReadQuery(model, args);
            const result = await query(args);
            return decryptResult(model, result, resolved.keys);
          },
          async findMany({ model, args, query }) {
            const context = dbGuardContextStore.getStore();
            const resolved = await resolveTenantKeysAndActiveKey(context?.tenantId);
            processReadQuery(model, args);
            const result = await query(args);
            return decryptResult(model, result, resolved.keys);
          },
        },
      },
    });
  });
};

export { encryptValue, decryptValue, rewriteQueryWhere, addBlindIndexes } from './security';
export { resolveKeys } from './kms';
