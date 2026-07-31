export { DB_GUARD_CONTRACT_VERSION, SUPPORTED_KEY_VERSIONS, DbGuardContractError, validateDbGuardContract, toPrismaDbGuardOptions, toMongooseDbGuardOptions, toDrizzleDbGuardOptions, toTypeOrmDbGuardOptions } from './contract';
export type { DbGuardContractV1, DbGuardContractErrorCode, CommonDbGuardSecurityOptions, CryptoRbacConfig } from './contract';
export { wrapSqliteDatabase, wrapOracleConnection, DbGuardDriverOptions } from './drivers';
export { KmsProvider, AwsKmsProvider, GcpKmsProvider, VaultKmsProvider, unwrapDekLocal, Pkcs11KmsProvider, resolveKeys, resolveBlindIndexRootSalt, AwsKmsCredentialIdentity, AwsKmsProviderConfig, GcpKmsClientOptions, GcpKmsProviderConfig, DbGuardKeysOptions } from './kms';
export { computeBlindIndex } from './blind-index';
export { dbGuardContextStore, configureAuditLogger, decryptWithSecurity, checkRateLimit, checkPageSize, resetFailClosedStatusForTesting, resetAuditLoggerForTesting, verifyAuditLogEntries, getCachedKey, setCachedKey, invalidateCachedKeys, DEFAULT_KEY_CACHE_TTL_MS, resetSecureKeyCacheForTesting, configureBreakGlass, deactivateBreakGlass, isBreakGlassActive, getBreakGlassKey, activateBreakGlass, parseCiphertext, CRYPTO_ALGORITHMS, VERSION_ALGORITHMS, maskValue, encryptValue, decryptBufferValue, decryptValue, MAX_CIPHERTEXT_STRING_LENGTH, MAX_PLAINTEXT_BYTES } from './security';
export { auditConfiguration, generateComplianceHtmlReport, ComplianceAuditInput, ComplianceScorecard } from './compliance';
export type { AuditLogEntry } from './security';
