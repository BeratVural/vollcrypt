"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.DbGuardError = exports.DB_GUARD_ERROR_PREFIX = void 0;
exports.dbGuardError = dbGuardError;
exports.DB_GUARD_ERROR_PREFIX = 'Vollcrypt DbGuard:';
/** Error type used consistently by every Node DB Guard adapter and provider. */
class DbGuardError extends Error {
    constructor(message, options) {
        const detail = message.replace(/^Vollcrypt (?:Security|DbGuard):\s*/, '');
        super(exports.DB_GUARD_ERROR_PREFIX + ' ' + detail, options);
        this.name = 'DbGuardError';
    }
}
exports.DbGuardError = DbGuardError;
function dbGuardError(message, options) {
    return new DbGuardError(message, options);
}
