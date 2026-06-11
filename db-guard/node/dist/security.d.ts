import { AsyncLocalStorage } from 'async_hooks';
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
}
export declare const dbGuardContextStore: AsyncLocalStorage<UserContext>;
export declare function maskValue(val: any, rule: 'credit_card' | 'email' | 'tc_no' | ((v: any) => any) | string): any;
export interface RateLimiterOptions {
    maxDecryptionsPerSecond?: number;
    onFailClosed?: () => void;
    mode?: 'fail_closed' | 'warn' | 'disabled';
    maxPageSize?: number;
    onPageSizeExceeded?: 'warn' | 'error' | 'bypass';
}
export declare function getCachedKey(tenantId: string | undefined, version: string): Buffer | undefined;
export declare function setCachedKey(tenantId: string | undefined, version: string, plaintextKey: Buffer, ttlMs?: number): void;
export declare function resetSecureKeyCacheForTesting(): void;
export declare function configureBreakGlass(options: {
    threshold: number;
    publicKeys: string[];
}): void;
export declare function deactivateBreakGlass(): void;
export declare function isBreakGlassActive(): boolean;
export declare function getBreakGlassKey(): Buffer | undefined;
export declare function activateBreakGlass(signatures: {
    publicKey: string;
    signature: string;
    timestamp: number;
}[], emergencyBackupKey: Buffer): void;
export declare function registerKeysForZeroization(keys: Record<string, Buffer>): void;
export declare function triggerFailClosed(onFailClosedCallback?: () => void): void;
export declare function checkRateLimit(options?: RateLimiterOptions): void;
export declare function checkPageSize(count: number, options?: RateLimiterOptions): 'ok' | 'warn' | 'bypass' | 'error';
export declare function getFailClosedStatus(): boolean;
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
export declare function configureAuditLogger(options?: {
    path?: string;
    onAuditLog?: (entry: AuditLogEntry) => void;
}): void;
export declare function resetAuditLoggerForTesting(): void;
export declare function logDecryption(model: string, field: string, recordId?: string): void;
export declare function decryptWithSecurity(stored: any, decryptRawFn: (val: string) => any, modelName: string, fieldName: string, recordId: string | undefined, options?: {
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
export declare function parseCiphertext(stored: string): {
    algoId: string;
    version: string;
    base64Data: string;
} | null;
