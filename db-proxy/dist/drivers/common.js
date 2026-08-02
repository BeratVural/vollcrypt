"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.createInitialUserContext = createInitialUserContext;
exports.resolveProjectedField = resolveProjectedField;
exports.decryptDriverValue = decryptDriverValue;
const db_guard_1 = require("@vollcrypt/db-guard");
const auth_js_1 = require("../auth.js");
/** Creates the fail-closed initial identity for a new database connection. */
function createInitialUserContext(role) {
    return {
        role,
        userId: role === 'OWNER' ? 'usr-admin' : 'guest-user',
    };
}
/** Resolves a projected column qualifier into DB Guard model and field names. */
function resolveProjectedField(projectedColumn, modelName, fallbackField) {
    if (!projectedColumn)
        return { model: modelName, field: fallbackField };
    const parts = projectedColumn.split('.');
    const field = parts[parts.length - 1];
    const qualifier = parts.length > 1 ? parts[0] : undefined;
    const model = qualifier && qualifier !== 'u' && qualifier !== 't'
        ? qualifier
        : modelName;
    return { model, field };
}
/** Runs one field decryption through the shared DB Guard security context. */
function decryptDriverValue(ciphertext, model, field, context) {
    return db_guard_1.dbGuardContextStore.run({
        role: context.role,
        userId: context.userId,
        tenantId: context.tenantId,
        maxDecryptionsPerSecond: context.config?.rateLimiter?.maxDecryptionsPerSecond,
        rateLimiterMode: context.config?.rateLimiter?.mode,
    }, () => (0, db_guard_1.decryptWithSecurity)(ciphertext, (value) => (0, db_guard_1.decryptValue)(value, context.keys), model, field, undefined, {
        cryptoRbac: (0, auth_js_1.getRbacConfig)(context.config),
        rateLimiter: context.config?.rateLimiter,
    }));
}
