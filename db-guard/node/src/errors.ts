export const DB_GUARD_ERROR_PREFIX = 'Vollcrypt DbGuard:';

/** Error type used consistently by every Node DB Guard adapter and provider. */
export class DbGuardError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    const detail = message.replace(/^Vollcrypt (?:Security|DbGuard):\s*/, '');
    super(DB_GUARD_ERROR_PREFIX + ' ' + detail, options);
    this.name = 'DbGuardError';
  }
}

export function dbGuardError(message: string, options?: ErrorOptions): DbGuardError {
  return new DbGuardError(message, options);
}