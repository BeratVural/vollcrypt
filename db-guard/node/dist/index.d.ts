export { wrapSqliteDatabase, wrapOracleConnection, DbGuardDriverOptions } from './drivers';
export { KmsProvider, AwsKmsProvider, GcpKmsProvider, VaultKmsProvider, unwrapDekLocal, Pkcs11KmsProvider, resolveKeys, DbGuardKeysOptions } from './kms';
export { computeBlindIndex } from './blind-index';
export { dbGuardContextStore, configureAuditLogger, decryptWithSecurity, checkRateLimit, checkPageSize, resetFailClosedStatusForTesting, resetAuditLoggerForTesting, verifyAuditLogEntries, getCachedKey, setCachedKey, invalidateCachedKeys, DEFAULT_KEY_CACHE_TTL_MS, resetSecureKeyCacheForTesting, configureBreakGlass, deactivateBreakGlass, isBreakGlassActive, getBreakGlassKey, activateBreakGlass, parseCiphertext, CRYPTO_ALGORITHMS, VERSION_ALGORITHMS, maskValue, encryptValue, decryptBufferValue, decryptValue, MAX_CIPHERTEXT_STRING_LENGTH, MAX_PLAINTEXT_BYTES } from './security';
export { auditConfiguration, generateComplianceHtmlReport, ComplianceAuditInput, ComplianceScorecard } from './compliance';
export type { AuditLogEntry } from './security';
