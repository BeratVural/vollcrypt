export { wrapSqliteDatabase, wrapOracleConnection, DbGuardDriverOptions } from './drivers';
export { KmsProvider, AwsKmsProvider, GcpKmsProvider, VaultKmsProvider, unwrapDekLocal, Pkcs11KmsProvider, resolveKeys, DbGuardKeysOptions } from './kms';
export { computeBlindIndex } from './blind-index';
export { dbGuardContextStore, configureAuditLogger, decryptWithSecurity, checkRateLimit, checkPageSize, resetFailClosedStatusForTesting, resetAuditLoggerForTesting, getCachedKey, setCachedKey, resetSecureKeyCacheForTesting, configureBreakGlass, deactivateBreakGlass, isBreakGlassActive, getBreakGlassKey, activateBreakGlass, parseCiphertext, CRYPTO_ALGORITHMS, VERSION_ALGORITHMS, maskValue, encryptValue, decryptValue } from './security';
export { auditConfiguration, generateComplianceHtmlReport, ComplianceAuditInput, ComplianceScorecard } from './compliance';
