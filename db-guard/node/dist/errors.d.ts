export declare const DB_GUARD_ERROR_PREFIX = "Vollcrypt DbGuard:";
/** Error type used consistently by every Node DB Guard adapter and provider. */
export declare class DbGuardError extends Error {
    constructor(message: string, options?: ErrorOptions);
}
export declare function dbGuardError(message: string, options?: ErrorOptions): DbGuardError;
