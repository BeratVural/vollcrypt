import { Prisma } from '@prisma/client';
import { encryptAesGcmPadded, decryptAesGcmPadded } from './security';
import { KmsProvider } from './kms';
import { computeBlindIndex } from './blind-index';

import { unwrapDekLocal } from './kms';

import { registerKeysForZeroization, decryptWithSecurity, RateLimiterOptions, checkPageSize, dbGuardContextStore, parseCiphertext, CRYPTO_ALGORITHMS, isBreakGlassActive, getBreakGlassKey, getCachedKey, setCachedKey } from './security';

export interface PrismaDbGuardOptions {
  key?: Buffer | Record<string, Buffer>;
  kms?: {
    provider: KmsProvider;
    wrappedKey: Buffer | Record<string, Buffer>;
    wrappedKek?: Buffer | Record<string, Buffer>;
    activeKeyVersion?: string;
  };
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
 * Resolves the plaintext keys asynchronously from local config or KMS provider.
 */
export async function resolveKeys(options: PrismaDbGuardOptions): Promise<Record<string, Buffer>> {
  let rawKeys: Record<string, Buffer> = {};

  if (options.key) {
    if (Buffer.isBuffer(options.key)) {
      rawKeys = { '1': options.key };
    } else {
      rawKeys = { ...options.key };
    }
  } else if (options.kms) {
    const { provider, wrappedKey, wrappedKek } = options.kms;
    if (Buffer.isBuffer(wrappedKey)) {
      if (wrappedKek && Buffer.isBuffer(wrappedKek)) {
        const unwrappedKek = await provider.decrypt(wrappedKek);
        const dek = unwrapDekLocal(wrappedKey, unwrappedKek);
        unwrappedKek.fill(0); // RAM Security: zeroize KEK immediately
        rawKeys = { '1': dek };
      } else {
        const key = await provider.decrypt(wrappedKey);
        rawKeys = { '1': key };
      }
    } else {
      for (const [ver, wrapped] of Object.entries(wrappedKey)) {
        if (wrappedKek) {
          const wKek = Buffer.isBuffer(wrappedKek) ? wrappedKek : (wrappedKek as Record<string, Buffer>)[ver];
          if (wKek) {
            const unwrappedKek = await provider.decrypt(wKek);
            const dek = unwrapDekLocal(wrapped, unwrappedKek);
            unwrappedKek.fill(0); // RAM Security: zeroize KEK immediately
            rawKeys[ver] = dek;
          } else {
            rawKeys[ver] = await provider.decrypt(wrapped);
          }
        } else {
          rawKeys[ver] = await provider.decrypt(wrapped);
        }
      }
    }
  } else {
    throw new Error("Either 'key' or 'kms' configuration must be provided.");
  }

  return rawKeys;
}

export function encryptValue(val: any, key: Buffer, version: string): string {
  if (val === null || val === undefined) return val;
  const plaintext = typeof val === 'string' ? val : JSON.stringify(val);
  const plaintextBuf = Buffer.from(plaintext, 'utf8');
  
  const encrypted = CRYPTO_ALGORITHMS['1'].encrypt(plaintextBuf, key);
  
  // RAM Security: Zeroize the plaintext buffer immediately
  plaintextBuf.fill(0);
  
  return `VOLLVALT:v${version}:${encrypted.toString('base64')}`;
}

export function decryptValue(stored: any, keys: Record<string, Buffer>): any {
  if (typeof stored !== 'string') {
    return stored;
  }
  
  const parsed = parseCiphertext(stored);
  if (!parsed) {
    return stored;
  }

  const { algoId, version, base64Data } = parsed;

  const key = keys[version];
  if (!key) {
    throw new Error(`Decryption key version "${version}" not found in registered keys`);
  }

  try {
    const encryptedBuf = Buffer.from(base64Data, 'base64');
    const decryptor = CRYPTO_ALGORITHMS[algoId];
    if (!decryptor) {
      throw new Error(`Unsupported decryption algorithm ID "${algoId}"`);
    }
    const decrypted = decryptor.decrypt(encryptedBuf, key);
    const plaintext = decrypted.toString('utf8');
    
    // RAM Security: Zeroize the decrypted buffer
    decrypted.fill(0);

    try {
      return JSON.parse(plaintext);
    } catch {
      return plaintext;
    }
  } catch (err) {
    throw new Error(`Failed to decrypt field value: ${(err as Error).message}`);
  }
}

/**
 * Traverses query `where` arguments to rewrite exact match queries on encrypted fields
 * to target shadow `_bidx` columns using dynamic HKDF-SHA256 blind indexing.
 */
export function rewriteQueryWhere(where: any, fields: string[], rootSalt: Buffer, modelName: string) {
  if (!where || typeof where !== 'object') return;

  for (const field of fields) {
    if (where[field] !== undefined) {
      const val = where[field];
      const bidxField = `${field}_bidx`;

      if (typeof val === 'string' || typeof val === 'number' || typeof val === 'boolean') {
        where[bidxField] = computeBlindIndex(val, rootSalt, `${modelName}.${field}`);
        delete where[field];
      } else if (val && typeof val === 'object') {
        if (val.equals !== undefined) {
          where[bidxField] = {
            equals: computeBlindIndex(val.equals, rootSalt, `${modelName}.${field}`),
          };
          delete where[field];
        }
      }
    }
  }

  // Recurse into compound logical operators
  const operators = ['AND', 'OR', 'NOT'];
  for (const op of operators) {
    if (Array.isArray(where[op])) {
      where[op].forEach((item: any) => rewriteQueryWhere(item, fields, rootSalt, modelName));
    } else if (where[op] && typeof where[op] === 'object') {
      rewriteQueryWhere(where[op], fields, rootSalt, modelName);
    }
  }
}

/**
 * Appends calculated blind indexes to the write payload (create/update).
 */
export function addBlindIndexes(data: any, fields: string[], rootSalt: Buffer, modelName: string) {
  if (!data || typeof data !== 'object') return;

  if (Array.isArray(data)) {
    data.forEach((item) => addBlindIndexes(item, fields, rootSalt, modelName));
    return;
  }

  for (const field of fields) {
    if (data[field] !== undefined && data[field] !== null) {
      const bidxField = `${field}_bidx`;
      data[bidxField] = computeBlindIndex(data[field], rootSalt, `${modelName}.${field}`);
    }
  }
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
        keys = { '1': options.key };
      } else {
        keys = { ...options.key };
      }
    } else if (options.kms || options.multiTenant) {
      // Keys might be resolved dynamically per tenant, or resolved later
    } else {
      throw new Error("Resolved keys must be provided as the second argument when using KMS.");
    }
  }

  if (keys) {
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

    if (!tenantId || !options.multiTenant) {
      if (!keys || !activeKey) {
        throw new Error("Vollcrypt Security: Global keys are not resolved.");
      }
      return { keys, activeKey, activeVersion };
    }

    // Check Secure TTL Cache
    const cachedActiveKey = getCachedKey(tenantId, activeVersion);
    if (cachedActiveKey) {
      return { keys: { [activeVersion]: cachedActiveKey }, activeKey: cachedActiveKey, activeVersion };
    }

    // Cache miss: resolve configuration
    let tenantConfig: { key?: Buffer | Record<string, Buffer>; kms?: any } | undefined;
    if (options.multiTenant.tenants) {
      tenantConfig = options.multiTenant.tenants[tenantId];
    } else if (options.multiTenant.getTenantConfig) {
      tenantConfig = await options.multiTenant.getTenantConfig(tenantId);
    }

    if (!tenantConfig) {
      throw new Error(`Vollcrypt Security: Configuration not found for tenantId "${tenantId}".`);
    }

    const resolvedTenantKeys = await resolveKeys({
      ...options,
      key: tenantConfig.key,
      kms: tenantConfig.kms
    } as any);

    registerKeysForZeroization(resolvedTenantKeys);

    const tActiveVersion = tenantConfig.kms?.activeKeyVersion || '1';
    const tActiveKey = resolvedTenantKeys[tActiveVersion];
    if (!tActiveKey) {
      throw new Error(`Vollcrypt Security: Active key version "${tActiveVersion}" not found for tenantId "${tenantId}".`);
    }

    for (const [ver, keyBuf] of Object.entries(resolvedTenantKeys)) {
      setCachedKey(tenantId, ver, keyBuf);
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
