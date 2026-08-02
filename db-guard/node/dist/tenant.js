"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.createTenantKeyResolver = createTenantKeyResolver;
const errors_1 = require("./errors");
const kms_1 = require("./kms");
const keys_1 = require("./keys");
const security_1 = require("./security");
/** Creates one tenant-aware key resolver shared by all Node ORM adapters. */
function createTenantKeyResolver(options, globalKeys) {
    return (tenantId) => {
        const breakGlassTenant = options.multiTenant ? tenantId : undefined;
        if ((0, security_1.isBreakGlassActive)(breakGlassTenant)) {
            const breakGlassKey = (0, security_1.getBreakGlassKey)(breakGlassTenant);
            if (breakGlassKey) {
                return { keys: { '1': breakGlassKey }, activeKey: breakGlassKey, activeVersion: '1' };
            }
        }
        if (options.multiTenant && !tenantId) {
            throw (0, errors_1.dbGuardError)('Vollcrypt DbGuard: tenantId must be provided in multi-tenant mode.');
        }
        if (!options.multiTenant) {
            if (!globalKeys) {
                throw (0, errors_1.dbGuardError)('Vollcrypt DbGuard: Global keys are not resolved.');
            }
            return globalKeys;
        }
        const tId = tenantId;
        const requestedVersion = options.activeKeyVersion || options.kms?.activeKeyVersion || '1';
        const cachedActiveKey = (0, security_1.getCachedKey)(tId, requestedVersion);
        if (cachedActiveKey) {
            return {
                keys: { [requestedVersion]: cachedActiveKey },
                activeKey: cachedActiveKey,
                activeVersion: requestedVersion
            };
        }
        return (async () => {
            const multiTenant = options.multiTenant;
            const tenantConfig = multiTenant.tenants
                ? multiTenant.tenants[tId]
                : await multiTenant.getTenantConfig?.(tId);
            if (!tenantConfig) {
                throw (0, errors_1.dbGuardError)('Vollcrypt DbGuard: Configuration not found for tenantId "' + tId + '".');
            }
            const rawKeys = await (0, kms_1.resolveKeys)({
                ...options,
                key: tenantConfig.key,
                kms: tenantConfig.kms
            });
            const requestedTenantVersion = tenantConfig.kms?.activeKeyVersion || '1';
            const resolved = (0, keys_1.normalizeKeys)(rawKeys, requestedTenantVersion);
            (0, security_1.registerKeysForZeroization)(resolved.keys, tId);
            for (const [version, key] of Object.entries(resolved.keys)) {
                (0, security_1.setCachedKey)(tId, version, key, multiTenant.cacheTtlMs);
            }
            return resolved;
        })();
    };
}
