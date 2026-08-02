import { dbGuardError } from './errors';
import type { Prisma as PrismaNamespace } from '@prisma/client';
import type { DbGuardKeysOptions } from './kms';
import type { CommonDbGuardSecurityOptions } from './contract';
import { normalizeKeys } from './keys';
import { createTenantKeyResolver, MultiTenantKeyOptions } from './tenant';
import {
  registerKeysForZeroization,
  decryptWithSecurity,
  checkPageSize,
  dbGuardContextStore,
  parseCiphertext,
  CRYPTO_ALGORITHMS,

  getFailClosedStatus,
  encryptValue,
  decryptValue,
  rewriteQueryWhere,
  addBlindIndexes,
  computeBlindIndex,
  validateBlindIndexConfiguration
} from './security';

export interface PrismaDbGuardOptions extends DbGuardKeysOptions, CommonDbGuardSecurityOptions {
  models: Record<string, string[]>; // fields to encrypt/decrypt
  activeKeyVersion?: string;
  blindIndexes?: {
    rootSalt: Buffer;
    allowFrequencyLeakage: true;
    models: Record<string, string[]>; // fields to calculate blind indexes for
  };

  multiTenant?: MultiTenantKeyOptions;
}

/**
 * Prisma DbGuard Extension Factory
 *
 * Bootstraps client-level field encryption, query translation, and automatic decryption.
 */
export const prismaDbGuard = (options: PrismaDbGuardOptions, resolvedKeys?: Record<string, Buffer>) => {
  if (options.blindIndexes) {
    validateBlindIndexConfiguration(
      options.blindIndexes.rootSalt,
      options.blindIndexes.allowFrequencyLeakage
    );
  }
  let keys: Record<string, Buffer> | undefined;
  let activeVersion = options.activeKeyVersion || options.kms?.activeKeyVersion || '1';

  const initialKeys = resolvedKeys ?? options.key;
  if (initialKeys) {
    const normalized = normalizeKeys(initialKeys, activeVersion);
    keys = normalized.keys;
    activeVersion = normalized.activeVersion;
    registerKeysForZeroization(keys);
  } else if (!options.kms && !options.multiTenant) {
    throw dbGuardError('Resolved keys must be provided as the second argument when using KMS.');
  }

  const activeKey = keys?.[activeVersion];

  const resolveTenantKeysAndActiveKey = createTenantKeyResolver(
    options,
    keys && activeKey ? { keys, activeKey, activeVersion } : undefined
  );

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
        addBlindIndexes(args.data, bidxFields, options.blindIndexes.rootSalt, modelName, options.blindIndexes.allowFrequencyLeakage);
      }
      if (args.create) {
        addBlindIndexes(args.create, bidxFields, options.blindIndexes.rootSalt, modelName, options.blindIndexes.allowFrequencyLeakage);
      }
      if (args.update) {
        addBlindIndexes(args.update, bidxFields, options.blindIndexes.rootSalt, modelName, options.blindIndexes.allowFrequencyLeakage);
      }
    }
  };

  const processReadQuery = (modelName: string, args: any) => {
    if (!args) return;

    // Rewrite queries targeting encrypted columns to use the blind index column
    const bidxFields = options.blindIndexes?.models[modelName];
    if (bidxFields && options.blindIndexes?.rootSalt && args.where) {
      rewriteQueryWhere(args.where, bidxFields, options.blindIndexes.rootSalt, modelName, options.blindIndexes.allowFrequencyLeakage);
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
                    addBlindIndexes(encrypted, bidxFields, options.blindIndexes.rootSalt, model, options.blindIndexes.allowFrequencyLeakage);
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
