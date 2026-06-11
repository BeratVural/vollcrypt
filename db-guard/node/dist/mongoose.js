"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.mongooseDbGuard = mongooseDbGuard;
const prisma_1 = require("./prisma");
const blind_index_1 = require("./blind-index");
const security_1 = require("./security");
function mongooseDbGuard(schema, options) {
    const { fields } = options;
    let keys;
    let activeVersion;
    if (Buffer.isBuffer(options.key)) {
        keys = { '1': options.key };
        activeVersion = '1';
    }
    else {
        keys = options.key;
        activeVersion = options.activeKeyVersion || Object.keys(keys)[0];
    }
    (0, security_1.registerKeysForZeroization)(keys);
    const activeKey = keys[activeVersion];
    if (!activeKey) {
        throw new Error(`Active encryption key version "${activeVersion}" is not present in the key map.`);
    }
    const resolveTenantKeysAndActiveKeySyncOrAsync = (tenantId) => {
        if ((0, security_1.isBreakGlassActive)()) {
            const bgKey = (0, security_1.getBreakGlassKey)();
            if (bgKey) {
                return { keys: { '1': bgKey }, activeKey: bgKey, activeVersion: '1' };
            }
        }
        if (!tenantId || !options.multiTenant) {
            return { keys, activeKey, activeVersion };
        }
        // Check Secure TTL Cache
        const cachedActiveKey = (0, security_1.getCachedKey)(tenantId, activeVersion);
        if (cachedActiveKey) {
            return { keys: { [activeVersion]: cachedActiveKey }, activeKey: cachedActiveKey, activeVersion };
        }
        // Cache miss: resolve configuration (this part is async)
        const resolveAsync = async () => {
            const multiTenant = options.multiTenant;
            if (!multiTenant) {
                throw new Error(`Vollcrypt Security: Multi-tenant configuration is not defined.`);
            }
            let tenantConfig;
            if (multiTenant.tenants) {
                tenantConfig = multiTenant.tenants[tenantId];
            }
            else if (multiTenant.getTenantConfig) {
                tenantConfig = await multiTenant.getTenantConfig(tenantId);
            }
            if (!tenantConfig) {
                throw new Error(`Vollcrypt Security: Configuration not found for tenantId "${tenantId}".`);
            }
            const resolvedTenantKeys = await (0, prisma_1.resolveKeys)({
                ...options,
                key: tenantConfig.key,
                kms: tenantConfig.kms
            });
            (0, security_1.registerKeysForZeroization)(resolvedTenantKeys);
            const tActiveVersion = tenantConfig.kms?.activeKeyVersion || '1';
            const tActiveKey = resolvedTenantKeys[tActiveVersion];
            if (!tActiveKey) {
                throw new Error(`Vollcrypt Security: Active key version "${tActiveVersion}" not found for tenantId "${tenantId}".`);
            }
            for (const [ver, keyBuf] of Object.entries(resolvedTenantKeys)) {
                (0, security_1.setCachedKey)(tenantId, ver, keyBuf);
            }
            return { keys: resolvedTenantKeys, activeKey: tActiveKey, activeVersion: tActiveVersion };
        };
        return resolveAsync();
    };
    // Pre-save document middleware (handles document.save(), Model.create())
    schema.pre('save', function (next) {
        const doc = this;
        const modelName = options.blindIndexes?.modelName || this.constructor.modelName || 'Model';
        const context = security_1.dbGuardContextStore.getStore();
        const runSync = (resolved) => {
            // 1. Encrypt fields
            for (const field of fields) {
                if (doc.isModified(field) && doc[field] !== undefined && doc[field] !== null) {
                    doc[field] = (0, prisma_1.encryptValue)(doc[field], resolved.activeKey, resolved.activeVersion);
                }
            }
            // 2. Compute blind indexes
            if (options.blindIndexes && options.blindIndexes.rootSalt) {
                for (const field of options.blindIndexes.fields) {
                    if (doc.isModified(field) && doc[field] !== undefined && doc[field] !== null) {
                        const bidxField = `${field}_bidx`;
                        // Decrypt temporary value if it was already encrypted in the previous step
                        const rawVal = doc.isModified(field) && doc[field].startsWith('VOLLVALT:')
                            ? (0, prisma_1.decryptValue)(doc[field], keys)
                            : doc[field];
                        doc[bidxField] = (0, blind_index_1.computeBlindIndex)(rawVal, options.blindIndexes.rootSalt, `${modelName}.${field}`);
                    }
                }
            }
            if (typeof next === 'function') {
                next();
            }
        };
        const resOrPromise = resolveTenantKeysAndActiveKeySyncOrAsync(context?.tenantId);
        if (resOrPromise instanceof Promise) {
            resOrPromise.then(runSync).catch((err) => {
                if (typeof next === 'function')
                    next(err);
            });
        }
        else {
            try {
                runSync(resOrPromise);
            }
            catch (err) {
                if (typeof next === 'function')
                    next(err);
            }
        }
    });
    // Helper to encrypt and calculate blind indexes on update payloads
    const encryptAndIndexUpdates = (update, modelName, encKey, encVer) => {
        if (!update || typeof update !== 'object')
            return;
        const encryptPathRecursive = (obj, pathParts, fullPath) => {
            if (!obj || typeof obj !== 'object')
                return;
            const currentPart = pathParts[0];
            if (pathParts.length === 1) {
                if (obj[currentPart] !== undefined && obj[currentPart] !== null) {
                    if (options.blindIndexes && options.blindIndexes.fields.includes(fullPath) && options.blindIndexes.rootSalt) {
                        const bidxField = `${currentPart}_bidx`;
                        obj[bidxField] = (0, blind_index_1.computeBlindIndex)(obj[currentPart], options.blindIndexes.rootSalt, `${modelName}.${fullPath}`);
                    }
                    obj[currentPart] = (0, prisma_1.encryptValue)(obj[currentPart], encKey, encVer);
                }
            }
            else {
                if (obj[currentPart] && typeof obj[currentPart] === 'object') {
                    encryptPathRecursive(obj[currentPart], pathParts.slice(1), fullPath);
                }
                const dotNotatedPath = pathParts.join('.');
                if (obj[dotNotatedPath] !== undefined && obj[dotNotatedPath] !== null) {
                    if (options.blindIndexes && options.blindIndexes.fields.includes(fullPath) && options.blindIndexes.rootSalt) {
                        const bidxField = `${dotNotatedPath}_bidx`;
                        obj[bidxField] = (0, blind_index_1.computeBlindIndex)(obj[dotNotatedPath], options.blindIndexes.rootSalt, `${modelName}.${fullPath}`);
                    }
                    obj[dotNotatedPath] = (0, prisma_1.encryptValue)(obj[dotNotatedPath], encKey, encVer);
                }
            }
        };
        const encryptTargetFields = (target) => {
            for (const field of fields) {
                encryptPathRecursive(target, field.split('.'), field);
            }
        };
        // Handle direct object properties
        encryptTargetFields(update);
        // Handle MongoDB update operators ($set, $setOnInsert)
        const operators = ['$set', '$setOnInsert'];
        for (const op of operators) {
            if (update[op] && typeof update[op] === 'object') {
                encryptTargetFields(update[op]);
            }
        }
    };
    // Pre-query update middleware (handles Model.updateOne(), Model.findOneAndUpdate(), etc.)
    const updateHooks = ['updateOne', 'updateMany', 'findOneAndUpdate', 'update'];
    updateHooks.forEach((hook) => {
        schema.pre(hook, function (next) {
            const query = this;
            const modelName = options.blindIndexes?.modelName || query.model?.modelName || 'Model';
            const update = typeof query.getUpdate === 'function' ? query.getUpdate() : null;
            const context = security_1.dbGuardContextStore.getStore();
            const runSync = (resolved) => {
                // 1. Process writes
                if (update) {
                    encryptAndIndexUpdates(update, modelName, resolved.activeKey, resolved.activeVersion);
                }
                // 2. Process query criteria (rewrite exact match search queries on conditions)
                const conditions = typeof query.getQuery === 'function' ? query.getQuery() : null;
                if (conditions && options.blindIndexes && options.blindIndexes.rootSalt) {
                    (0, prisma_1.rewriteQueryWhere)(conditions, options.blindIndexes.fields, options.blindIndexes.rootSalt, modelName);
                }
                if (typeof next === 'function') {
                    next();
                }
            };
            const resOrPromise = resolveTenantKeysAndActiveKeySyncOrAsync(context?.tenantId);
            if (resOrPromise instanceof Promise) {
                resOrPromise.then(runSync).catch((err) => {
                    if (typeof next === 'function')
                        next(err);
                });
            }
            else {
                try {
                    runSync(resOrPromise);
                }
                catch (err) {
                    if (typeof next === 'function')
                        next(err);
                }
            }
        });
    });
    // Pre-query read middleware (handles Model.find(), Model.findOne(), etc.)
    const readHooks = ['find', 'findOne', 'countDocuments', 'distinct'];
    readHooks.forEach((hook) => {
        schema.pre(hook, function (next) {
            const query = this;
            const modelName = options.blindIndexes?.modelName || query.model?.modelName || 'Model';
            const conditions = typeof query.getQuery === 'function' ? query.getQuery() : null;
            if (conditions && options.blindIndexes && options.blindIndexes.rootSalt) {
                (0, prisma_1.rewriteQueryWhere)(conditions, options.blindIndexes.fields, options.blindIndexes.rootSalt, modelName);
            }
            next();
        });
    });
    // Helper to decrypt documents
    const decryptDoc = (doc, modelName, decKeys) => {
        if (!doc)
            return;
        for (const field of fields) {
            if (doc[field] !== undefined && doc[field] !== null) {
                try {
                    doc[field] = (0, security_1.decryptWithSecurity)(doc[field], (val) => (0, prisma_1.decryptValue)(val, decKeys), modelName, field, doc.id || doc._id, options);
                }
                catch (err) {
                    throw new Error(`Mongoose db-guard failed to decrypt field "${field}": ${err.message}`);
                }
            }
        }
    };
    // Post-find query middleware (handles Model.find())
    schema.post('find', function (docs, next) {
        try {
            const modelName = options.blindIndexes?.modelName || this.model?.modelName || 'Model';
            if (!Array.isArray(docs)) {
                if (typeof next === 'function')
                    next();
                return;
            }
            const context = security_1.dbGuardContextStore.getStore();
            const resOrPromise = resolveTenantKeysAndActiveKeySyncOrAsync(context?.tenantId);
            const runSync = (resolved) => {
                const pageSizeStatus = (0, security_1.checkPageSize)(docs.length, options.rateLimiter);
                if (pageSizeStatus === 'bypass') {
                    const currentCtx = security_1.dbGuardContextStore.getStore() || {};
                    security_1.dbGuardContextStore.run({ ...currentCtx, bypassRateLimit: true }, () => {
                        docs.forEach((d) => decryptDoc(d, modelName, resolved.keys));
                    });
                }
                else {
                    docs.forEach((d) => decryptDoc(d, modelName, resolved.keys));
                }
                if (typeof next === 'function') {
                    next();
                }
            };
            if (resOrPromise instanceof Promise) {
                resOrPromise.then(runSync).catch((err) => {
                    if (typeof next === 'function')
                        next(err);
                });
            }
            else {
                runSync(resOrPromise);
            }
        }
        catch (err) {
            if (typeof next === 'function') {
                next(err);
            }
            else {
                throw err;
            }
        }
    });
    // Post-findOne query middleware (handles Model.findOne(), Model.findOneAndUpdate(), etc.)
    const singleReadHooks = ['findOne', 'findOneAndUpdate', 'findOneAndDelete'];
    singleReadHooks.forEach((hook) => {
        schema.post(hook, function (doc, next) {
            try {
                const modelName = options.blindIndexes?.modelName || this.model?.modelName || 'Model';
                if (!doc) {
                    if (typeof next === 'function')
                        next();
                    return;
                }
                const context = security_1.dbGuardContextStore.getStore();
                const resOrPromise = resolveTenantKeysAndActiveKeySyncOrAsync(context?.tenantId);
                const runSync = (resolved) => {
                    decryptDoc(doc, modelName, resolved.keys);
                    if (typeof next === 'function') {
                        next();
                    }
                };
                if (resOrPromise instanceof Promise) {
                    resOrPromise.then(runSync).catch((err) => {
                        if (typeof next === 'function')
                            next(err);
                    });
                }
                else {
                    runSync(resOrPromise);
                }
            }
            catch (err) {
                if (typeof next === 'function') {
                    next(err);
                }
                else {
                    throw err;
                }
            }
        });
    });
}
