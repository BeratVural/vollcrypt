import { AsyncLocalStorage } from 'async_hooks';
export declare const MAX_CIPHERTEXT_STRING_LENGTH: number;
export declare const MAX_PLAINTEXT_BYTES: number;
export declare function wrapKey(kek: Buffer, keyToWrap: Buffer): Buffer;
export declare function unwrapKey(kek: Buffer, wrappedKey: Buffer): Buffer;
export declare function calculatePadding(contentLen: number): Buffer;
export declare function padMessageWithLen(content: Buffer): Buffer;
export declare function unpadMessageWithLen(padded: Buffer): Buffer;
export declare function encryptAesGcmPadded(key: Buffer, plaintext: Buffer, aad?: Buffer | null): Buffer;
export declare function decryptAesGcmPadded(key: Buffer, encryptedData: Buffer, aad?: Buffer | null): Buffer;
export declare function verifySignature(publicKey: Buffer, message: Buffer, signature: Buffer): boolean;
export declare function deriveHkdf(ikm: Buffer, salt: Buffer | null, info: Buffer | null, keyLen: number): Buffer;
export declare function generateEd25519Keypair(): [Buffer, Buffer];
export declare function signMessage(secretKey: Buffer, message: Buffer): Buffer;
export interface UserContext {
    role?: string;
    userId?: string;
    maxDecryptionsPerSecond?: number;
    bypassRateLimit?: boolean;
    rateLimiterMode?: 'fail_closed' | 'warn' | 'disabled';
    maxPageSize?: number;
    onPageSizeExceeded?: 'warn' | 'error' | 'bypass';
    tenantId?: string;
    decryptCount?: number;
    windowStart?: number;
}
export declare const dbGuardContextStore: AsyncLocalStorage<UserContext>;
export declare function maskValue(val: any, rule: 'credit_card' | 'email' | 'tc_no' | ((v: any) => any) | string): any;
export interface RateLimitDecision {
    count: number;
    exceeded: boolean;
}
/**
 * Authoritative cross-instance coordinator. consume must atomically increment
 * one tenant window and return the resulting count.
 */
export interface RateLimitCoordinator {
    isFailClosed(tenantId: string): boolean;
    consume(tenantId: string, nowMs: number, limit: number): RateLimitDecision;
    markFailClosed(tenantId: string): void;
}
export interface RateLimiterOptions {
    maxDecryptionsPerSecond?: number;
    onFailClosed?: () => void;
    mode?: 'fail_closed' | 'warn' | 'disabled';
    maxPageSize?: number;
    onPageSizeExceeded?: 'warn' | 'error' | 'bypass';
    coordinator?: RateLimitCoordinator;
    coordinatorFailureMode?: 'fail_closed' | 'local_fallback';
}
export declare const DEFAULT_KEY_CACHE_TTL_MS = 120000;
/**
 * Returns a tenant/version cache entry as a fresh plaintext buffer, or undefined when absent or expired.
 */
export declare function getCachedKey(tenantId: string | undefined, version: string): Buffer | undefined;
/**
 * Wraps and caches a tenant/version key for a bounded lifetime.
 */
export declare function setCachedKey(tenantId: string | undefined, version: string, plaintextKey: Buffer, ttlMs?: number): void;
/**
 * Zeroizes and removes matching cached tenant key generations.
 */
export declare function invalidateCachedKeys(tenantId: string | undefined, version?: string): number;
export declare function resetSecureKeyCacheForTesting(): void;
/**
 * Configures the threshold and trusted Ed25519 keys for emergency access.
 */
export declare function configureBreakGlass(options: {
    threshold: number;
    publicKeys: string[];
}): void;
/**
 * Disables emergency access and zeroizes its mutable key material.
 */
export declare function deactivateBreakGlass(tenantId?: string): void;
/**
 * Reports whether global or tenant-scoped emergency access is active.
 */
export declare function isBreakGlassActive(tenantId?: string): boolean;
/**
 * Returns the active emergency key buffer for internal adapter resolution.
 */
export declare function getBreakGlassKey(tenantId?: string): Buffer | undefined;
/**
 * Verifies threshold approvals before installing a copied emergency key.
 */
export declare function activateBreakGlass(signatures: {
    publicKey: string;
    signature: string;
    timestamp: number;
}[], emergencyBackupKey: Buffer, tenantId?: string): void;
/**
 * Registers mutable adapter key maps for tenant-scoped fail-closed zeroization.
 */
export declare function registerKeysForZeroization(keys: Record<string, Buffer>, tenantId?: string): void;
/**
 * Marks a tenant fail-closed, zeroizes registered key material, and aborts the operation.
 */
export declare function triggerFailClosed(onFailClosedCallback?: () => void, tenantId?: string, coordinator?: RateLimitCoordinator): void;
/**
 * Consumes one tenant-scoped decryption allowance and enforces the configured policy.
 */
export declare function checkRateLimit(options?: RateLimiterOptions): void;
/**
 * Applies the configured anti-scraping page-size policy before bulk decryption.
 */
export declare function checkPageSize(count: number, options?: RateLimiterOptions): 'ok' | 'warn' | 'bypass' | 'error';
/**
 * Returns the current tenant-scoped fail-closed state.
 */
export declare function getFailClosedStatus(tenantId?: string): boolean;
export declare function resetFailClosedStatusForTesting(): void;
export interface AuditLogEntry {
    timestamp: string;
    userId?: string;
    role?: string;
    model: string;
    field: string;
    recordId?: string;
    action: 'decrypt';
    prevHash: string;
    hash: string;
}
/**
 * Verifies the cryptographic hash chain of serialized decryption audit entries.
 */
export declare function verifyAuditLogEntries(entries: readonly AuditLogEntry[], integrityKey: Buffer): boolean;
/**
 * Configures hash-chained audit persistence and an optional observer callback.
 */
export declare function configureAuditLogger(options?: {
    integrityKey: Buffer;
    path?: string;
    onAuditLog?: (entry: AuditLogEntry) => void;
}): void;
export declare function resetAuditLoggerForTesting(): void;
/**
 * Appends one hash-chained decryption event without exposing plaintext.
 */
export declare function logDecryption(model: string, field: string, recordId?: string): void;
/**
 * Enforces RBAC, masking, rate limits, fail-closed state, and audit logging around decryption.
 */
export declare function decryptWithSecurity(stored: any, decryptRawFn: (val: string) => any, modelName: string, fieldName: string, recordId: string | undefined, options?: {
    allowUnrestrictedDecrypt?: boolean;
    cryptoRbac?: {
        roles: Record<string, {
            decrypt: string[];
            mask?: Record<string, 'credit_card' | 'email' | 'tc_no' | ((v: any) => any) | string>;
        }>;
    };
    rateLimiter?: RateLimiterOptions;
}): any;
export declare const VERSION_ALGORITHMS: Record<string, string>;
export declare const CRYPTO_ALGORITHMS: Record<string, {
    encrypt: (plaintext: Buffer, key: Buffer) => Buffer;
    decrypt: (ciphertext: Buffer, key: Buffer) => Buffer;
}>;
/**
 * Parses and validates the bounded, versioned VOLLVALT ciphertext envelope.
 */
export declare function parseCiphertext(stored: string): {
    algoId: string;
    version: string;
    base64Data: string;
} | null;
/**
 * Computes a keyed deterministic equality index.
 *
 * Equal plaintexts in the same column produce equal indexes and therefore leak
 * frequency information. Callers must explicitly acknowledge that tradeoff.
 */
/**
 * Validates explicit frequency-leakage consent and root-salt strength.
 */
export declare function validateBlindIndexConfiguration(rootSalt: Buffer, allowFrequencyLeakage: true): void;
/**
 * Computes a domain-separated deterministic blind index for an approved field.
 */
export declare function computeBlindIndex(value: any, rootSalt: Buffer, columnName: string, allowFrequencyLeakage: true): string;
/**
 * Serializes and encrypts one bounded field value with an explicit supported key version.
 */
export declare function encryptValue(val: any, key: Buffer, version: string): string;
/**
 * Decrypts directly to a mutable Buffer and avoids creating an immutable V8 plaintext string.
 * The caller owns the returned buffer and must zeroize it with fill(0) after use.
 */
/**
 * Decrypts one field into a mutable Buffer so callers can zeroize plaintext.
 */
export declare function decryptBufferValue(stored: string, keys: Record<string, Buffer>): Buffer;
/**
 * Decrypts one field and restores its serialized JavaScript value.
 */
export declare function decryptValue(stored: any, keys: Record<string, Buffer>): any;
/**
 * Rewrites supported encrypted-field equality filters to blind-index columns.
 */
export declare function rewriteQueryWhere(where: any, fields: string[], rootSalt: Buffer, modelName: string, allowFrequencyLeakage: true): void;
/**
 * Adds blind-index companion fields before an ORM write.
 */
export declare function addBlindIndexes(data: any, fields: string[], rootSalt: Buffer, modelName: string, allowFrequencyLeakage: true): void;
