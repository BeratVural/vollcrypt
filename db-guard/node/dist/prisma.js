"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.resolveKeys = exports.addBlindIndexes = exports.rewriteQueryWhere = exports.decryptValue = exports.encryptValue = exports.prismaDbGuard = void 0;
const kms_1 = require("./kms");
const security_1 = require("./security");
/**
 * Prisma DbGuard Extension Factory
 *
 * Bootstraps client-level field encryption, query translation, and automatic decryption.
 */
const prismaDbGuard = (options, resolvedKeys) => {
    let keys = resolvedKeys;
    if (!keys) {
        if (options.key) {
            if (Buffer.isBuffer(options.key)) {
                keys = { '1': Buffer.from(options.key) };
            }
            else {
                keys = {};
                for (const [v, k] of Object.entries(options.key)) {
                    keys[v] = Buffer.from(k);
                }
            }
        }
        else if (options.kms || options.multiTenant) {
            // Keys might be resolved dynamically per tenant, or resolved later
        }
        else {
            throw new Error("Resolved keys must be provided as the second argument when using KMS.");
        }
    }
    if (keys) {
        const clonedKeys = {};
        for (const [v, k] of Object.entries(keys)) {
            clonedKeys[v] = Buffer.from(k);
        }
        keys = clonedKeys;
        (0, security_1.registerKeysForZeroization)(keys);
    }
    const activeVersion = options.kms?.activeKeyVersion || '1';
    const activeKey = keys ? keys[activeVersion] : undefined;
    const resolveTenantKeysAndActiveKey = async (tenantId) => {
        if ((0, security_1.isBreakGlassActive)()) {
            const bgKey = (0, security_1.getBreakGlassKey)();
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
        const tId = tenantId;
        // Check Secure TTL Cache
        const cachedActiveKey = (0, security_1.getCachedKey)(tId, activeVersion);
        if (cachedActiveKey) {
            return { keys: { [activeVersion]: cachedActiveKey }, activeKey: cachedActiveKey, activeVersion };
        }
        // Cache miss: resolve configuration
        let tenantConfig;
        if (options.multiTenant.tenants) {
            tenantConfig = options.multiTenant.tenants[tId];
        }
        else if (options.multiTenant.getTenantConfig) {
            tenantConfig = await options.multiTenant.getTenantConfig(tId);
        }
        if (!tenantConfig) {
            throw new Error(`Vollcrypt Security: Configuration not found for tenantId "${tId}".`);
        }
        const resolvedTenantKeysRaw = await (0, kms_1.resolveKeys)({
            ...options,
            key: tenantConfig.key,
            kms: tenantConfig.kms
        });
        const resolvedTenantKeys = {};
        for (const [v, k] of Object.entries(resolvedTenantKeysRaw)) {
            resolvedTenantKeys[v] = Buffer.from(k);
        }
        (0, security_1.registerKeysForZeroization)(resolvedTenantKeys, tId);
        const tActiveVersion = tenantConfig.kms?.activeKeyVersion || '1';
        const tActiveKey = resolvedTenantKeys[tActiveVersion];
        if (!tActiveKey) {
            throw new Error(`Vollcrypt Security: Active key version "${tActiveVersion}" not found for tenantId "${tId}".`);
        }
        for (const [ver, keyBuf] of Object.entries(resolvedTenantKeys)) {
            (0, security_1.setCachedKey)(tId, ver, keyBuf);
        }
        return { keys: resolvedTenantKeys, activeKey: tActiveKey, activeVersion: tActiveVersion };
    };
    const encryptPayload = (modelName, data, encKey, encVer) => {
        const fieldsToEncrypt = options.models[modelName];
        if (!fieldsToEncrypt || !data || typeof data !== 'object')
            return data;
        const cloned = { ...data };
        for (const field of fieldsToEncrypt) {
            if (cloned[field] !== undefined) {
                cloned[field] = (0, security_1.encryptValue)(cloned[field], encKey, encVer);
            }
        }
        return cloned;
    };
    const decryptResult = (modelName, result, decKeys) => {
        const fieldsToEncrypt = options.models[modelName];
        if (!fieldsToEncrypt || !result)
            return result;
        if (Array.isArray(result)) {
            const pageSizeStatus = (0, security_1.checkPageSize)(result.length, options.rateLimiter);
            if (pageSizeStatus === 'bypass') {
                const currentCtx = security_1.dbGuardContextStore.getStore() || {};
                return security_1.dbGuardContextStore.run({ ...currentCtx, bypassRateLimit: true }, () => {
                    return result.map((item) => decryptResult(modelName, item, decKeys));
                });
            }
            return result.map((item) => decryptResult(modelName, item, decKeys));
        }
        if (typeof result !== 'object')
            return result;
        const cloned = { ...result };
        for (const field of fieldsToEncrypt) {
            if (cloned[field] !== undefined) {
                cloned[field] = (0, security_1.decryptWithSecurity)(cloned[field], (val) => (0, security_1.decryptValue)(val, decKeys), modelName, field, cloned.id || cloned._id, options);
            }
        }
        return cloned;
    };
    const processWriteQuery = (modelName, args, encKey, encVer) => {
        if (!args)
            return;
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
                (0, security_1.addBlindIndexes)(args.data, bidxFields, options.blindIndexes.rootSalt, modelName);
            }
            if (args.create) {
                (0, security_1.addBlindIndexes)(args.create, bidxFields, options.blindIndexes.rootSalt, modelName);
            }
            if (args.update) {
                (0, security_1.addBlindIndexes)(args.update, bidxFields, options.blindIndexes.rootSalt, modelName);
            }
        }
    };
    const processReadQuery = (modelName, args) => {
        if (!args)
            return;
        // Rewrite queries targeting encrypted columns to use the blind index column
        const bidxFields = options.blindIndexes?.models[modelName];
        if (bidxFields && options.blindIndexes?.rootSalt && args.where) {
            (0, security_1.rewriteQueryWhere)(args.where, bidxFields, options.blindIndexes.rootSalt, modelName);
        }
    };
    const { Prisma } = require('@prisma/client');
    return Prisma.defineExtension((client) => {
        return client.$extends({
            name: 'vollcrypt-db-guard',
            query: {
                $allModels: {
                    async create({ model, args, query }) {
                        const context = security_1.dbGuardContextStore.getStore();
                        const resolved = await resolveTenantKeysAndActiveKey(context?.tenantId);
                        processWriteQuery(model, args, resolved.activeKey, resolved.activeVersion);
                        const result = await query(args);
                        return decryptResult(model, result, resolved.keys);
                    },
                    async createMany({ model, args, query }) {
                        const context = security_1.dbGuardContextStore.getStore();
                        const resolved = await resolveTenantKeysAndActiveKey(context?.tenantId);
                        if (args.data) {
                            if (Array.isArray(args.data)) {
                                args.data = args.data.map((item) => {
                                    const encrypted = encryptPayload(model, item, resolved.activeKey, resolved.activeVersion);
                                    const bidxFields = options.blindIndexes?.models[model];
                                    if (bidxFields && options.blindIndexes?.rootSalt) {
                                        (0, security_1.addBlindIndexes)(encrypted, bidxFields, options.blindIndexes.rootSalt, model);
                                    }
                                    return encrypted;
                                });
                            }
                            else {
                                processWriteQuery(model, args, resolved.activeKey, resolved.activeVersion);
                            }
                        }
                        const result = await query(args);
                        return decryptResult(model, result, resolved.keys);
                    },
                    async update({ model, args, query }) {
                        const context = security_1.dbGuardContextStore.getStore();
                        const resolved = await resolveTenantKeysAndActiveKey(context?.tenantId);
                        processWriteQuery(model, args, resolved.activeKey, resolved.activeVersion);
                        processReadQuery(model, args);
                        const result = await query(args);
                        return decryptResult(model, result, resolved.keys);
                    },
                    async updateMany({ model, args, query }) {
                        const context = security_1.dbGuardContextStore.getStore();
                        const resolved = await resolveTenantKeysAndActiveKey(context?.tenantId);
                        processWriteQuery(model, args, resolved.activeKey, resolved.activeVersion);
                        processReadQuery(model, args);
                        const result = await query(args);
                        return decryptResult(model, result, resolved.keys);
                    },
                    async upsert({ model, args, query }) {
                        const context = security_1.dbGuardContextStore.getStore();
                        const resolved = await resolveTenantKeysAndActiveKey(context?.tenantId);
                        processWriteQuery(model, args, resolved.activeKey, resolved.activeVersion);
                        processReadQuery(model, args);
                        const result = await query(args);
                        return decryptResult(model, result, resolved.keys);
                    },
                    async findFirst({ model, args, query }) {
                        const context = security_1.dbGuardContextStore.getStore();
                        const resolved = await resolveTenantKeysAndActiveKey(context?.tenantId);
                        processReadQuery(model, args);
                        const result = await query(args);
                        return decryptResult(model, result, resolved.keys);
                    },
                    async findUnique({ model, args, query }) {
                        const context = security_1.dbGuardContextStore.getStore();
                        const resolved = await resolveTenantKeysAndActiveKey(context?.tenantId);
                        processReadQuery(model, args);
                        const result = await query(args);
                        return decryptResult(model, result, resolved.keys);
                    },
                    async findMany({ model, args, query }) {
                        const context = security_1.dbGuardContextStore.getStore();
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
exports.prismaDbGuard = prismaDbGuard;
var security_2 = require("./security");
Object.defineProperty(exports, "encryptValue", { enumerable: true, get: function () { return security_2.encryptValue; } });
Object.defineProperty(exports, "decryptValue", { enumerable: true, get: function () { return security_2.decryptValue; } });
Object.defineProperty(exports, "rewriteQueryWhere", { enumerable: true, get: function () { return security_2.rewriteQueryWhere; } });
Object.defineProperty(exports, "addBlindIndexes", { enumerable: true, get: function () { return security_2.addBlindIndexes; } });
var kms_2 = require("./kms");
Object.defineProperty(exports, "resolveKeys", { enumerable: true, get: function () { return kms_2.resolveKeys; } });
