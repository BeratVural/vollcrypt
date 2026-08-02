"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.CRYPTO_ALGORITHMS = exports.VERSION_ALGORITHMS = exports.DEFAULT_KEY_CACHE_TTL_MS = exports.dbGuardContextStore = exports.MAX_PLAINTEXT_BYTES = exports.MAX_CIPHERTEXT_STRING_LENGTH = void 0;
exports.wrapKey = wrapKey;
exports.unwrapKey = unwrapKey;
exports.calculatePadding = calculatePadding;
exports.padMessageWithLen = padMessageWithLen;
exports.unpadMessageWithLen = unpadMessageWithLen;
exports.encryptAesGcmPadded = encryptAesGcmPadded;
exports.decryptAesGcmPadded = decryptAesGcmPadded;
exports.verifySignature = verifySignature;
exports.deriveHkdf = deriveHkdf;
exports.generateEd25519Keypair = generateEd25519Keypair;
exports.signMessage = signMessage;
exports.maskValue = maskValue;
exports.getCachedKey = getCachedKey;
exports.setCachedKey = setCachedKey;
exports.invalidateCachedKeys = invalidateCachedKeys;
exports.resetSecureKeyCacheForTesting = resetSecureKeyCacheForTesting;
exports.configureBreakGlass = configureBreakGlass;
exports.deactivateBreakGlass = deactivateBreakGlass;
exports.isBreakGlassActive = isBreakGlassActive;
exports.getBreakGlassKey = getBreakGlassKey;
exports.activateBreakGlass = activateBreakGlass;
exports.registerKeysForZeroization = registerKeysForZeroization;
exports.triggerFailClosed = triggerFailClosed;
exports.checkRateLimit = checkRateLimit;
exports.checkPageSize = checkPageSize;
exports.getFailClosedStatus = getFailClosedStatus;
exports.resetFailClosedStatusForTesting = resetFailClosedStatusForTesting;
exports.verifyAuditLogEntries = verifyAuditLogEntries;
exports.configureAuditLogger = configureAuditLogger;
exports.resetAuditLoggerForTesting = resetAuditLoggerForTesting;
exports.logDecryption = logDecryption;
exports.decryptWithSecurity = decryptWithSecurity;
exports.parseCiphertext = parseCiphertext;
exports.validateBlindIndexConfiguration = validateBlindIndexConfiguration;
exports.computeBlindIndex = computeBlindIndex;
exports.encryptValue = encryptValue;
exports.decryptBufferValue = decryptBufferValue;
exports.decryptValue = decryptValue;
exports.rewriteQueryWhere = rewriteQueryWhere;
exports.addBlindIndexes = addBlindIndexes;
const errors_1 = require("./errors");
const async_hooks_1 = require("async_hooks");
const crypto = __importStar(require("crypto"));
const fs = __importStar(require("fs"));
const KEY_WRAP_IV = Buffer.from('A6A6A6A6A6A6A6A6', 'hex');
exports.MAX_CIPHERTEXT_STRING_LENGTH = 8 * 1024 * 1024;
exports.MAX_PLAINTEXT_BYTES = 6 * 1024 * 1024;
function wrapKey(kek, keyToWrap) {
    if (kek.length !== 32) {
        throw (0, errors_1.dbGuardError)('KEK must be exactly 32 bytes');
    }
    const cipher = crypto.createCipheriv('id-aes256-wrap', kek, KEY_WRAP_IV);
    return Buffer.concat([cipher.update(keyToWrap), cipher.final()]);
}
function unwrapKey(kek, wrappedKey) {
    if (kek.length !== 32) {
        throw (0, errors_1.dbGuardError)('KEK must be exactly 32 bytes');
    }
    const decipher = crypto.createDecipheriv('id-aes256-wrap', kek, KEY_WRAP_IV);
    return Buffer.concat([decipher.update(wrappedKey), decipher.final()]);
}
function calculatePadding(contentLen) {
    const sizes = [64, 128, 256, 512, 1024, 2048];
    const minPadding = 2;
    let target = sizes.find(s => s >= contentLen + minPadding);
    if (target === undefined) {
        const remainder = (contentLen + minPadding) % 1024;
        if (remainder === 0) {
            target = contentLen + minPadding;
        }
        else {
            target = contentLen + minPadding + (1024 - remainder);
        }
    }
    const paddingLen = target - contentLen;
    return crypto.randomBytes(paddingLen);
}
function padMessageWithLen(content) {
    const lenBytes = Buffer.alloc(4);
    lenBytes.writeUInt32BE(content.length, 0);
    const baseLen = 4 + content.length;
    const paddingBytes = calculatePadding(baseLen);
    return Buffer.concat([lenBytes, content, paddingBytes]);
}
function unpadMessageWithLen(padded) {
    if (padded.length < 4) {
        throw (0, errors_1.dbGuardError)('Padded message too short');
    }
    const len = padded.readUInt32BE(0);
    if (len > padded.length - 4) {
        throw (0, errors_1.dbGuardError)('Invalid padded message length');
    }
    return padded.subarray(4, 4 + len);
}
function encryptAesGcmPadded(key, plaintext, aad = null) {
    if (plaintext.length > exports.MAX_PLAINTEXT_BYTES) {
        throw (0, errors_1.dbGuardError)('Plaintext exceeds the maximum supported field size');
    }
    const padded = padMessageWithLen(plaintext);
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    if (aad)
        cipher.setAAD(aad);
    let updateChunk;
    let finalChunk;
    try {
        updateChunk = cipher.update(padded);
        finalChunk = cipher.final();
        const tag = cipher.getAuthTag();
        return Buffer.concat([iv, updateChunk, finalChunk, tag]);
    }
    finally {
        padded.fill(0);
        updateChunk?.fill(0);
        finalChunk?.fill(0);
    }
}
function decryptAesGcmPadded(key, encryptedData, aad = null) {
    if (encryptedData.length < 28 || encryptedData.length > exports.MAX_CIPHERTEXT_STRING_LENGTH) {
        throw (0, errors_1.dbGuardError)('Ciphertext length is outside the supported field bounds');
    }
    const iv = encryptedData.subarray(0, 12);
    const tag = encryptedData.subarray(encryptedData.length - 16);
    const ciphertext = encryptedData.subarray(12, encryptedData.length - 16);
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(tag);
    if (aad)
        decipher.setAAD(aad);
    let updateChunk;
    let finalChunk;
    let padded;
    try {
        updateChunk = decipher.update(ciphertext);
        finalChunk = decipher.final();
        padded = Buffer.concat([updateChunk, finalChunk]);
        return Buffer.from(unpadMessageWithLen(padded));
    }
    finally {
        updateChunk?.fill(0);
        finalChunk?.fill(0);
        padded?.fill(0);
    }
}
function verifySignature(publicKey, message, signature) {
    try {
        const spkiHeader = Buffer.from('302a300506032b6570032100', 'hex');
        const pubKey = crypto.createPublicKey({
            key: Buffer.concat([spkiHeader, publicKey]),
            format: 'der',
            type: 'spki'
        });
        return crypto.verify(null, message, pubKey, signature);
    }
    catch (err) {
        return false;
    }
}
function deriveHkdf(ikm, salt, info, keyLen) {
    return Buffer.from(crypto.hkdfSync('sha256', ikm, salt || Buffer.alloc(0), info || Buffer.alloc(0), keyLen));
}
function generateEd25519Keypair() {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    const publicDer = publicKey.export({ type: 'spki', format: 'der' });
    const privateDer = privateKey.export({ type: 'pkcs8', format: 'der' });
    try {
        return [
            Buffer.from(privateDer.subarray(16)),
            Buffer.from(publicDer.subarray(12))
        ];
    }
    finally {
        privateDer.fill(0);
    }
}
function signMessage(secretKey, message) {
    if (!Buffer.isBuffer(secretKey) || secretKey.length !== 32) {
        throw (0, errors_1.dbGuardError)('Ed25519 secret key must be a 32-byte Buffer');
    }
    const pkcs8Header = Buffer.from('302e020100300506032b657004220420', 'hex');
    const privateDer = Buffer.alloc(pkcs8Header.length + secretKey.length);
    pkcs8Header.copy(privateDer);
    secretKey.copy(privateDer, pkcs8Header.length);
    try {
        const privateKeyObj = crypto.createPrivateKey({
            key: privateDer,
            format: 'der',
            type: 'pkcs8'
        });
        return crypto.sign(null, message, privateKeyObj);
    }
    finally {
        privateDer.fill(0);
    }
}
// 1. Request Context Store (AsyncLocalStorage)
exports.dbGuardContextStore = new async_hooks_1.AsyncLocalStorage();
// 2. Dynamic Data Masking (DDM)
function maskValue(val, rule) {
    if (val === null || val === undefined)
        return val;
    const str = typeof val === 'string' ? val : String(val);
    if (typeof rule === 'function') {
        return rule(str);
    }
    switch (rule) {
        case 'credit_card':
            if (str.length >= 12) {
                return str.slice(0, 4) + '-XXXX-XXXX-' + str.slice(-4);
            }
            return 'XXXX-XXXX-XXXX-XXXX';
        case 'email':
            const parts = str.split('@');
            if (parts.length === 2) {
                const name = parts[0];
                if (name.length > 3) {
                    return name.slice(0, 3) + '***@' + parts[1];
                }
                return name + '***@' + parts[1];
            }
            return '***@***.***';
        case 'tc_no':
            if (str.length >= 11) {
                return str.slice(0, 3) + 'XXXXXX' + str.slice(-2);
            }
            return 'XXXXXXXXXXX';
        default:
            if (typeof rule === 'string' && rule !== 'credit_card' && rule !== 'email' && rule !== 'tc_no') {
                return rule; // static mask string
            }
            return '***';
    }
}
// Ephemeral Master Key generated randomly on startup
let ephemeralMasterKey = crypto.randomBytes(32);
const tenantFailClosed = new Map();
const tenantKeys = new Map();
const tenantRateLimitStates = new Map();
function consumeLocalRateLimit(tenantId, now, limit) {
    let state = tenantRateLimitStates.get(tenantId);
    if (!state) {
        state = { decryptCount: 0, windowStart: now };
        tenantRateLimitStates.set(tenantId, state);
    }
    if (now - state.windowStart > 1000) {
        state.decryptCount = 0;
        state.windowStart = now;
    }
    state.decryptCount++;
    return { count: state.decryptCount, exceeded: state.decryptCount > limit };
}
const secureKeyCache = new Map();
exports.DEFAULT_KEY_CACHE_TTL_MS = 120_000;
/**
 * Returns a tenant/version cache entry as a fresh plaintext buffer, or undefined when absent or expired.
 */
function getCachedKey(tenantId, version) {
    const cacheKey = JSON.stringify([tenantId || 'global', version]);
    const entry = secureKeyCache.get(cacheKey);
    if (!entry)
        return undefined;
    if (Date.now() > entry.expiresAt) {
        entry.wrappedKey.fill(0);
        secureKeyCache.delete(cacheKey);
        return undefined;
    }
    try {
        return unwrapKey(ephemeralMasterKey, entry.wrappedKey);
    }
    catch {
        return undefined;
    }
}
/**
 * Wraps and caches a tenant/version key for a bounded lifetime.
 */
function setCachedKey(tenantId, version, plaintextKey, ttlMs = exports.DEFAULT_KEY_CACHE_TTL_MS) {
    if (!Number.isSafeInteger(ttlMs) || ttlMs <= 0) {
        throw (0, errors_1.dbGuardError)('Key cache TTL must be a positive integer in milliseconds');
    }
    const cacheKey = JSON.stringify([tenantId || 'global', version]);
    const existing = secureKeyCache.get(cacheKey);
    if (existing) {
        existing.wrappedKey.fill(0);
    }
    const wrapped = wrapKey(ephemeralMasterKey, plaintextKey);
    secureKeyCache.set(cacheKey, {
        wrappedKey: wrapped,
        expiresAt: Date.now() + ttlMs
    });
}
/**
 * Zeroizes and removes matching cached tenant key generations.
 */
function invalidateCachedKeys(tenantId, version) {
    const normalizedTenant = tenantId || 'global';
    let invalidated = 0;
    for (const [cacheKey, entry] of secureKeyCache.entries()) {
        try {
            const parsed = JSON.parse(cacheKey);
            if (Array.isArray(parsed) &&
                parsed[0] === normalizedTenant &&
                (version === undefined || parsed[1] === version)) {
                entry.wrappedKey.fill(0);
                secureKeyCache.delete(cacheKey);
                invalidated++;
            }
        }
        catch {
            entry.wrappedKey.fill(0);
            secureKeyCache.delete(cacheKey);
            invalidated++;
        }
    }
    return invalidated;
}
// Background cleanup worker (scans every 30s)
const cacheCleanupInterval = setInterval(() => {
    const now = Date.now();
    for (const [key, entry] of secureKeyCache.entries()) {
        if (now > entry.expiresAt) {
            entry.wrappedKey.fill(0);
            secureKeyCache.delete(key);
        }
    }
}, 30000);
if (typeof cacheCleanupInterval.unref === 'function') {
    cacheCleanupInterval.unref();
}
function resetSecureKeyCacheForTesting() {
    for (const entry of secureKeyCache.values()) {
        entry.wrappedKey.fill(0);
    }
    secureKeyCache.clear();
    ephemeralMasterKey = crypto.randomBytes(32);
    isBreakGlassActiveFlag = false;
    if (breakGlassEmergencyKey) {
        breakGlassEmergencyKey.fill(0);
        breakGlassEmergencyKey = undefined;
    }
    for (const key of tenantBreakGlassEmergencyKeys.values()) {
        key.fill(0);
    }
    tenantBreakGlassEmergencyKeys.clear();
    tenantBreakGlassActive.clear();
    breakGlassThreshold = 0;
    breakGlassPublicKeys = [];
}
// Emergency Break-Glass variables
let breakGlassThreshold = 0;
let breakGlassPublicKeys = [];
let breakGlassEmergencyKey;
let isBreakGlassActiveFlag = false;
const tenantBreakGlassEmergencyKeys = new Map();
const tenantBreakGlassActive = new Set();
/**
 * Configures the threshold and trusted Ed25519 keys for emergency access.
 */
function configureBreakGlass(options) {
    breakGlassThreshold = options.threshold;
    breakGlassPublicKeys = options.publicKeys;
}
/**
 * Disables emergency access and zeroizes its mutable key material.
 */
function deactivateBreakGlass(tenantId) {
    if (tenantId) {
        tenantBreakGlassActive.delete(tenantId);
        const tenantKey = tenantBreakGlassEmergencyKeys.get(tenantId);
        if (tenantKey) {
            tenantKey.fill(0);
            tenantBreakGlassEmergencyKeys.delete(tenantId);
        }
        logDecryption('SYSTEM', `BREAK_GLASS_DEACTIVATED:${tenantId}`, undefined);
        return;
    }
    isBreakGlassActiveFlag = false;
    if (breakGlassEmergencyKey) {
        breakGlassEmergencyKey.fill(0);
        breakGlassEmergencyKey = undefined;
    }
    for (const key of tenantBreakGlassEmergencyKeys.values()) {
        key.fill(0);
    }
    tenantBreakGlassEmergencyKeys.clear();
    tenantBreakGlassActive.clear();
    logDecryption('SYSTEM', 'BREAK_GLASS_DEACTIVATED', undefined);
}
/**
 * Reports whether global or tenant-scoped emergency access is active.
 */
function isBreakGlassActive(tenantId) {
    if (tenantId)
        return tenantBreakGlassActive.has(tenantId);
    return isBreakGlassActiveFlag;
}
/**
 * Returns the active emergency key buffer for internal adapter resolution.
 */
function getBreakGlassKey(tenantId) {
    if (tenantId)
        return tenantBreakGlassEmergencyKeys.get(tenantId);
    return breakGlassEmergencyKey;
}
/**
 * Verifies threshold approvals before installing a copied emergency key.
 */
function activateBreakGlass(signatures, emergencyBackupKey, tenantId) {
    if (breakGlassThreshold <= 0 || breakGlassPublicKeys.length === 0) {
        throw (0, errors_1.dbGuardError)('Vollcrypt DbGuard: Break-Glass protocol is not configured.');
    }
    if (signatures.length < breakGlassThreshold) {
        throw (0, errors_1.dbGuardError)(`Vollcrypt DbGuard: Insufficient signatures. Required: ${breakGlassThreshold}, Provided: ${signatures.length}`);
    }
    const verifiedKeys = new Set();
    for (const sig of signatures) {
        if (!breakGlassPublicKeys.includes(sig.publicKey)) {
            throw (0, errors_1.dbGuardError)(`Vollcrypt DbGuard: Public key ${sig.publicKey} is not in the authorized break-glass list.`);
        }
        if (verifiedKeys.has(sig.publicKey)) {
            throw (0, errors_1.dbGuardError)(`Vollcrypt DbGuard: Duplicate signature from public key ${sig.publicKey}.`);
        }
        if (Math.abs(Date.now() - sig.timestamp) > 15 * 60 * 1000) {
            throw (0, errors_1.dbGuardError)(`Vollcrypt DbGuard: Signature timestamp ${sig.timestamp} is outside the allowed 15-minute window.`);
        }
        const message = `break-glass-activate|${sig.timestamp}`;
        const pubKeyBuf = Buffer.from(sig.publicKey, 'hex');
        const msgBuf = Buffer.from(message, 'utf8');
        const sigBuf = Buffer.from(sig.signature, 'hex');
        const isValid = verifySignature(pubKeyBuf, msgBuf, sigBuf);
        if (!isValid) {
            throw (0, errors_1.dbGuardError)(`Vollcrypt DbGuard: Invalid signature for public key ${sig.publicKey}.`);
        }
        verifiedKeys.add(sig.publicKey);
    }
    if (tenantId) {
        const existing = tenantBreakGlassEmergencyKeys.get(tenantId);
        if (existing)
            existing.fill(0);
        tenantBreakGlassEmergencyKeys.set(tenantId, Buffer.from(emergencyBackupKey));
        tenantBreakGlassActive.add(tenantId);
        logDecryption('SYSTEM', `BREAK_GLASS_ACTIVATED:${tenantId}`, undefined);
        return;
    }
    breakGlassEmergencyKey = Buffer.from(emergencyBackupKey);
    isBreakGlassActiveFlag = true;
    logDecryption('SYSTEM', 'BREAK_GLASS_ACTIVATED', undefined);
}
/**
 * Registers mutable adapter key maps for tenant-scoped fail-closed zeroization.
 */
function registerKeysForZeroization(keys, tenantId) {
    const tId = tenantId || 'global';
    let list = tenantKeys.get(tId);
    if (!list) {
        list = [];
        tenantKeys.set(tId, list);
    }
    if (!list.includes(keys)) {
        list.push(keys);
    }
}
/**
 * Marks a tenant fail-closed, zeroizes registered key material, and aborts the operation.
 */
function triggerFailClosed(onFailClosedCallback, tenantId, coordinator) {
    const tId = tenantId || exports.dbGuardContextStore.getStore()?.tenantId || 'global';
    try {
        coordinator?.markFailClosed(tId);
    }
    catch {
        // Local zeroization must still complete when distributed coordination is unavailable.
    }
    tenantFailClosed.set(tId, true);
    // Zeroize all registered keys immediately in memory for this tenant
    const list = tenantKeys.get(tId);
    if (list && list.length > 0) {
        for (const keyMap of list) {
            for (const key of Object.values(keyMap)) {
                key.fill(0);
            }
        }
    }
    else {
        // Fallback to global keys if no tenant-specific keys are registered
        const globalList = tenantKeys.get('global');
        if (globalList) {
            for (const keyMap of globalList) {
                for (const key of Object.values(keyMap)) {
                    key.fill(0);
                }
            }
        }
    }
    // Zeroize cache and ephemeral master key
    for (const [cacheKey, entry] of secureKeyCache.entries()) {
        try {
            const parsed = JSON.parse(cacheKey);
            if (Array.isArray(parsed) && parsed[0] === tId) {
                entry.wrappedKey.fill(0);
                secureKeyCache.delete(cacheKey);
            }
        }
        catch {
            // fallback
        }
    }
    if (tId === 'global') {
        ephemeralMasterKey.fill(0);
        if (breakGlassEmergencyKey) {
            breakGlassEmergencyKey.fill(0);
        }
        for (const key of tenantBreakGlassEmergencyKeys.values()) {
            key.fill(0);
        }
        tenantBreakGlassEmergencyKeys.clear();
        tenantBreakGlassActive.clear();
    }
    if (onFailClosedCallback) {
        try {
            onFailClosedCallback();
        }
        catch {
            // prevent user callback crash from blocking zeroization
        }
    }
    throw (0, errors_1.dbGuardError)(`Vollcrypt DbGuard: Decryption rate limit exceeded. Fail-Closed mode triggered for tenant "${tId}". Keys zeroized.`);
}
/**
 * Consumes one tenant-scoped decryption allowance and enforces the configured policy.
 */
function checkRateLimit(options) {
    const context = exports.dbGuardContextStore.getStore();
    const tId = context?.tenantId || 'global';
    const coordinator = options?.coordinator;
    let coordinatedFailClosed = false;
    if (coordinator) {
        try {
            coordinatedFailClosed = coordinator.isFailClosed(tId);
        }
        catch {
            if (options?.coordinatorFailureMode !== 'local_fallback') {
                triggerFailClosed(options?.onFailClosed, tId, coordinator);
            }
        }
    }
    if (tenantFailClosed.get(tId) || coordinatedFailClosed) {
        triggerFailClosed(options?.onFailClosed, tId, coordinator);
    }
    if (context?.bypassRateLimit) {
        return;
    }
    const limit = context?.maxDecryptionsPerSecond || options?.maxDecryptionsPerSecond || 500;
    const mode = context?.rateLimiterMode || options?.mode || 'fail_closed';
    if (mode === 'disabled') {
        return;
    }
    const now = Date.now();
    let count;
    let exceeded;
    if (coordinator) {
        try {
            const decision = coordinator.consume(tId, now, limit);
            count = decision.count;
            exceeded = decision.exceeded;
        }
        catch {
            if (options?.coordinatorFailureMode !== 'local_fallback') {
                triggerFailClosed(options?.onFailClosed, tId, coordinator);
            }
            const state = consumeLocalRateLimit(tId, now, limit);
            count = state.count;
            exceeded = state.exceeded;
        }
    }
    else {
        const state = consumeLocalRateLimit(tId, now, limit);
        count = state.count;
        exceeded = state.exceeded;
    }
    if (exceeded) {
        if (mode === 'fail_closed') {
            triggerFailClosed(options?.onFailClosed, tId, coordinator);
        }
        console.warn('Vollcrypt Warning: Decryption rate limit exceeded for tenant "' +
            tId +
            '". ' +
            count +
            ' decryptions in the current window (limit: ' +
            limit +
            ').');
    }
}
/**
 * Applies the configured anti-scraping page-size policy before bulk decryption.
 */
function checkPageSize(count, options) {
    const context = exports.dbGuardContextStore.getStore();
    const tId = context?.tenantId || 'global';
    let coordinatedFailClosed = false;
    if (options?.coordinator) {
        try {
            coordinatedFailClosed = options.coordinator.isFailClosed(tId);
        }
        catch {
            if (options.coordinatorFailureMode !== 'local_fallback') {
                triggerFailClosed(options.onFailClosed, tId, options.coordinator);
            }
        }
    }
    if (tenantFailClosed.get(tId) || coordinatedFailClosed) {
        triggerFailClosed(options?.onFailClosed, tId, options?.coordinator);
    }
    const maxPageSize = context?.maxPageSize !== undefined
        ? context.maxPageSize
        : (options?.maxPageSize !== undefined ? options.maxPageSize : 250);
    const behavior = context?.onPageSizeExceeded
        ? context.onPageSizeExceeded
        : (options?.onPageSizeExceeded || 'warn');
    if (count > maxPageSize) {
        if (behavior === 'error') {
            throw (0, errors_1.dbGuardError)(`Vollcrypt DbGuard: Query returned ${count} records, which exceeds the max allowed page size of ${maxPageSize}. Decryption blocked to prevent rate limit execution.`);
        }
        else if (behavior === 'warn') {
            console.warn(`Vollcrypt Warning: Query returned ${count} records, which exceeds the recommended page size limit of ${maxPageSize}. This may trigger the decryption rate limiter.`);
            return 'warn';
        }
        else if (behavior === 'bypass') {
            return 'bypass';
        }
    }
    return 'ok';
}
/**
 * Returns the current tenant-scoped fail-closed state.
 */
function getFailClosedStatus(tenantId) {
    const tId = tenantId || exports.dbGuardContextStore.getStore()?.tenantId || 'global';
    return tenantFailClosed.get(tId) || false;
}
function resetFailClosedStatusForTesting() {
    tenantFailClosed.clear();
    tenantRateLimitStates.clear();
    tenantKeys.clear();
}
const AUDIT_GENESIS_HASH = '0'.repeat(64);
let lastLogHash = AUDIT_GENESIS_HASH;
let auditLogPath;
let auditIntegrityKey;
let onAuditLogCallback;
let auditWriteQueue = Promise.resolve();
function serializeAuditEntry(entry) {
    return JSON.stringify([
        entry.timestamp,
        entry.userId ?? null,
        entry.role ?? null,
        entry.model,
        entry.field,
        entry.recordId ?? null,
        entry.action,
        entry.prevHash
    ]);
}
function computeAuditMac(entry, integrityKey) {
    return crypto
        .createHmac('sha256', integrityKey)
        .update(serializeAuditEntry(entry))
        .digest('hex');
}
/**
 * Verifies the cryptographic hash chain of serialized decryption audit entries.
 */
function verifyAuditLogEntries(entries, integrityKey) {
    if (!Buffer.isBuffer(integrityKey) || integrityKey.length < 32)
        return false;
    let expectedPrevHash = AUDIT_GENESIS_HASH;
    for (const entry of entries) {
        if (entry.prevHash !== expectedPrevHash ||
            typeof entry.hash !== 'string' ||
            !/^[0-9a-f]{64}$/i.test(entry.hash)) {
            return false;
        }
        const unsigned = {
            timestamp: entry.timestamp,
            userId: entry.userId,
            role: entry.role,
            model: entry.model,
            field: entry.field,
            recordId: entry.recordId,
            action: entry.action,
            prevHash: entry.prevHash
        };
        const expectedMac = Buffer.from(computeAuditMac(unsigned, integrityKey), 'hex');
        const actualMac = Buffer.from(entry.hash, 'hex');
        if (expectedMac.length !== actualMac.length ||
            !crypto.timingSafeEqual(expectedMac, actualMac)) {
            return false;
        }
        expectedPrevHash = entry.hash;
    }
    return true;
}
/**
 * Configures hash-chained audit persistence and an optional observer callback.
 */
function configureAuditLogger(options) {
    if (!options) {
        resetAuditLoggerForTesting();
        return;
    }
    if (!Buffer.isBuffer(options.integrityKey) || options.integrityKey.length < 32) {
        throw (0, errors_1.dbGuardError)('Vollcrypt DbGuard: Audit integrity key must be at least 32 bytes.');
    }
    if (auditIntegrityKey)
        auditIntegrityKey.fill(0);
    auditIntegrityKey = Buffer.from(options.integrityKey);
    auditLogPath = options.path;
    onAuditLogCallback = options.onAuditLog;
    lastLogHash = AUDIT_GENESIS_HASH;
    if (!auditLogPath || !fs.existsSync(auditLogPath))
        return;
    let entries;
    try {
        const content = fs.readFileSync(auditLogPath, 'utf8').trim();
        entries = content
            ? content.split('\n').map((line) => JSON.parse(line))
            : [];
    }
    catch (error) {
        throw (0, errors_1.dbGuardError)('Vollcrypt DbGuard: Audit log could not be parsed; refusing to continue.', { cause: error });
    }
    if (!verifyAuditLogEntries(entries, auditIntegrityKey)) {
        throw (0, errors_1.dbGuardError)('Vollcrypt DbGuard: Audit log integrity verification failed; refusing to continue.');
    }
    if (entries.length > 0) {
        lastLogHash = entries[entries.length - 1].hash;
    }
}
function resetAuditLoggerForTesting() {
    lastLogHash = AUDIT_GENESIS_HASH;
    auditLogPath = undefined;
    if (auditIntegrityKey)
        auditIntegrityKey.fill(0);
    auditIntegrityKey = undefined;
    onAuditLogCallback = undefined;
    auditWriteQueue = Promise.resolve();
}
/**
 * Appends one hash-chained decryption event without exposing plaintext.
 */
function logDecryption(model, field, recordId) {
    if (!auditIntegrityKey)
        return;
    const context = exports.dbGuardContextStore.getStore();
    const entry = {
        timestamp: new Date().toISOString(),
        userId: context?.userId,
        role: context?.role,
        model,
        field,
        recordId: recordId ? String(recordId) : undefined,
        action: 'decrypt',
        prevHash: lastLogHash
    };
    const hash = computeAuditMac(entry, auditIntegrityKey);
    const fullEntry = { ...entry, hash };
    lastLogHash = hash;
    if (onAuditLogCallback) {
        try {
            onAuditLogCallback(fullEntry);
        }
        catch {
            // Audit callbacks are observers and cannot change decryption behavior.
        }
    }
    if (auditLogPath) {
        const line = JSON.stringify(fullEntry) + '\n';
        const currentPath = auditLogPath;
        auditWriteQueue = auditWriteQueue.then(() => {
            return fs.promises.appendFile(currentPath, line, 'utf8').catch(() => { });
        });
    }
}
/**
 * Enforces RBAC, masking, rate limits, fail-closed state, and audit logging around decryption.
 */
function decryptWithSecurity(stored, decryptRawFn, modelName, fieldName, recordId, options) {
    if (typeof stored !== 'string' || !stored.startsWith('VOLLVALT:')) {
        // Dual-read fallback: if the value is not encrypted, return as is.
        return stored;
    }
    const fieldKey = `${modelName}.${fieldName}`;
    // 1. Check if Crypto-RBAC is configured
    if (options?.cryptoRbac) {
        const context = exports.dbGuardContextStore.getStore();
        const role = context?.role;
        const roleConfig = role ? options.cryptoRbac.roles[role] : undefined;
        const isAuthorized = roleConfig?.decrypt.includes(fieldKey) || false;
        if (!isAuthorized) {
            // Unauthorized. Check for masking rules
            const maskRule = roleConfig?.mask?.[fieldKey];
            if (maskRule !== undefined) {
                if (typeof maskRule === 'string' && maskRule !== 'credit_card' && maskRule !== 'email' && maskRule !== 'tc_no') {
                    // Static mask bypasses decryption completely
                    return maskRule;
                }
                // Dynamic mask requires internal decryption
                checkRateLimit(options.rateLimiter);
                const plaintext = decryptRawFn(stored);
                const masked = maskValue(plaintext, maskRule);
                logDecryption(modelName, fieldName, recordId);
                return masked;
            }
            // No mask defined for unauthorized access -> block decryption
            throw (0, errors_1.dbGuardError)(`Vollcrypt DbGuard: Role "${role || 'GUEST'}" is not authorized to decrypt field "${fieldKey}".`);
        }
    }
    else if (!options?.allowUnrestrictedDecrypt) {
        const context = exports.dbGuardContextStore.getStore();
        const role = context?.role || 'GUEST';
        if (role !== 'OWNER') {
            throw (0, errors_1.dbGuardError)(`Vollcrypt DbGuard: Crypto-RBAC is not configured. Refusing unrestricted decrypt for role "${role}" on field "${fieldKey}".`);
        }
    }
    // 2. Authorized or explicitly unrestricted: proceed with normal decryption
    checkRateLimit(options?.rateLimiter);
    const result = decryptRawFn(stored);
    logDecryption(modelName, fieldName, recordId);
    return result;
}
exports.VERSION_ALGORITHMS = {
    '1': '1',
    '2': '1'
};
exports.CRYPTO_ALGORITHMS = {
    '1': {
        encrypt: (plaintext, key) => encryptAesGcmPadded(key, plaintext, null),
        decrypt: (ciphertext, key) => decryptAesGcmPadded(key, ciphertext, null),
    }
};
/**
 * Parses and validates the bounded, versioned VOLLVALT ciphertext envelope.
 */
function parseCiphertext(stored) {
    if (typeof stored !== 'string') {
        throw (0, errors_1.dbGuardError)('Vollcrypt DbGuard: Ciphertext must be a string.');
    }
    if (stored.length > exports.MAX_CIPHERTEXT_STRING_LENGTH) {
        throw (0, errors_1.dbGuardError)('Vollcrypt DbGuard: Ciphertext exceeds the maximum supported field size.');
    }
    if (/[\x00-\x1f\x7f]/.test(stored)) {
        throw (0, errors_1.dbGuardError)('Vollcrypt DbGuard: Ciphertext contains forbidden control characters.');
    }
    if (!stored.startsWith('VOLLVALT:'))
        return null;
    const content = stored.slice('VOLLVALT:'.length);
    if (!content.startsWith('v')) {
        throw (0, errors_1.dbGuardError)('Vollcrypt DbGuard: Legacy unversioned ciphertexts are deprecated and unsupported.');
    }
    const colon = content.indexOf(':');
    if (colon === -1) {
        throw (0, errors_1.dbGuardError)('Vollcrypt DbGuard: Malformed ciphertext format.');
    }
    const versionPart = content.slice(1, colon);
    const base64Part = content.slice(colon + 1);
    if (!/^[1-9][0-9]{0,5}$/.test(versionPart)) {
        throw (0, errors_1.dbGuardError)('Vollcrypt DbGuard: Malformed ciphertext version.');
    }
    const algoId = exports.VERSION_ALGORITHMS[versionPart];
    if (!algoId) {
        throw (0, errors_1.dbGuardError)('Vollcrypt DbGuard: Deprecated or unsupported encryption version "v' + versionPart + '".');
    }
    if (base64Part.length === 0 ||
        base64Part.length % 4 !== 0 ||
        !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(base64Part)) {
        throw (0, errors_1.dbGuardError)('Vollcrypt DbGuard: Ciphertext payload is not canonical Base64.');
    }
    return { algoId, version: versionPart, base64Data: base64Part };
}
/**
 * Computes a keyed deterministic equality index.
 *
 * Equal plaintexts in the same column produce equal indexes and therefore leak
 * frequency information. Callers must explicitly acknowledge that tradeoff.
 */
/**
 * Validates explicit frequency-leakage consent and root-salt strength.
 */
function validateBlindIndexConfiguration(rootSalt, allowFrequencyLeakage) {
    if (!Buffer.isBuffer(rootSalt) || rootSalt.length < 32) {
        throw (0, errors_1.dbGuardError)('Vollcrypt DbGuard: Blind-index rootSalt must be at least 32 bytes.');
    }
    if (allowFrequencyLeakage !== true) {
        throw (0, errors_1.dbGuardError)('Vollcrypt DbGuard: Deterministic blind indexes leak equality frequency. Set allowFrequencyLeakage: true only after accepting this risk.');
    }
}
/**
 * Computes a domain-separated deterministic blind index for an approved field.
 */
function computeBlindIndex(value, rootSalt, columnName, allowFrequencyLeakage) {
    if (value === null || value === undefined)
        return value;
    validateBlindIndexConfiguration(rootSalt, allowFrequencyLeakage);
    const plaintext = typeof value === 'string' ? value : JSON.stringify(value);
    const columnNameBuf = Buffer.from(columnName, 'utf8');
    const derivedColumnKey = deriveHkdf(rootSalt, null, columnNameBuf, 32);
    const plaintextBuf = Buffer.from(plaintext, 'utf8');
    try {
        const blindIndex = deriveHkdf(derivedColumnKey, null, plaintextBuf, 32);
        return blindIndex.toString('hex');
    }
    finally {
        plaintextBuf.fill(0);
        derivedColumnKey.fill(0);
    }
}
/**
 * Serializes and encrypts one bounded field value with an explicit supported key version.
 */
function encryptValue(val, key, version) {
    if (val === null || val === undefined)
        return val;
    if (!/^[1-9][0-9]{0,5}$/.test(version)) {
        throw (0, errors_1.dbGuardError)('Vollcrypt DbGuard: Invalid encryption version "' + version + '".');
    }
    const algoId = exports.VERSION_ALGORITHMS[version];
    const encryptor = algoId ? exports.CRYPTO_ALGORITHMS[algoId] : undefined;
    if (!encryptor) {
        throw (0, errors_1.dbGuardError)('Vollcrypt DbGuard: Unsupported encryption version "v' + version + '".');
    }
    const context = exports.dbGuardContextStore.getStore();
    const tId = context?.tenantId || 'global';
    if (key.every(b => b === 0) || getFailClosedStatus(tId)) {
        throw (0, errors_1.dbGuardError)('Vollcrypt DbGuard: Fail-Closed mode is active for tenant "' + tId + '". Encryption blocked.');
    }
    const plaintextBuf = Buffer.isBuffer(val)
        ? Buffer.from(val)
        : Buffer.from(typeof val === 'string' ? val : JSON.stringify(val), 'utf8');
    try {
        if (plaintextBuf.length > exports.MAX_PLAINTEXT_BYTES) {
            throw (0, errors_1.dbGuardError)('Vollcrypt DbGuard: Plaintext exceeds the maximum supported field size.');
        }
        const encrypted = encryptor.encrypt(plaintextBuf, key);
        return 'VOLLVALT:v' + version + ':' + encrypted.toString('base64');
    }
    finally {
        plaintextBuf.fill(0);
    }
}
/**
 * Decrypts directly to a mutable Buffer and avoids creating an immutable V8 plaintext string.
 * The caller owns the returned buffer and must zeroize it with fill(0) after use.
 */
/**
 * Decrypts one field into a mutable Buffer so callers can zeroize plaintext.
 */
function decryptBufferValue(stored, keys) {
    const parsed = parseCiphertext(stored);
    if (!parsed) {
        throw (0, errors_1.dbGuardError)('Vollcrypt DbGuard: decryptBufferValue accepts encrypted values only.');
    }
    const { algoId, version, base64Data } = parsed;
    const key = keys[version];
    if (!key) {
        throw (0, errors_1.dbGuardError)('Decryption key version "' + version + '" not found in registered keys');
    }
    if (key.every(b => b === 0)) {
        throw (0, errors_1.dbGuardError)('Vollcrypt DbGuard: Decryption blocked. Key version "' + version + '" is zeroized due to a Fail-Closed event.');
    }
    const encryptedBuf = Buffer.from(base64Data, 'base64');
    try {
        const decryptor = exports.CRYPTO_ALGORITHMS[algoId];
        if (!decryptor) {
            throw (0, errors_1.dbGuardError)('Unsupported decryption algorithm ID "' + algoId + '"');
        }
        return decryptor.decrypt(encryptedBuf, key);
    }
    catch (err) {
        throw (0, errors_1.dbGuardError)('Failed to decrypt field value: ' + err.message);
    }
    finally {
        encryptedBuf.fill(0);
    }
}
/**
 * Decrypts one field and restores its serialized JavaScript value.
 */
function decryptValue(stored, keys) {
    if (typeof stored !== 'string')
        return stored;
    if (!stored.startsWith('VOLLVALT:'))
        return stored;
    const decrypted = decryptBufferValue(stored, keys);
    try {
        // Compatibility API: V8 strings cannot provide deterministic zeroization.
        const plaintext = decrypted.toString('utf8');
        try {
            return JSON.parse(plaintext);
        }
        catch {
            return plaintext;
        }
    }
    finally {
        decrypted.fill(0);
    }
}
/**
 * Rewrites supported encrypted-field equality filters to blind-index columns.
 */
function rewriteQueryWhere(where, fields, rootSalt, modelName, allowFrequencyLeakage) {
    if (!where || typeof where !== 'object')
        return;
    for (const field of fields) {
        if (where[field] !== undefined) {
            const val = where[field];
            const bidxField = `${field}_bidx`;
            if (typeof val === 'string' || typeof val === 'number' || typeof val === 'boolean') {
                where[bidxField] = computeBlindIndex(val, rootSalt, `${modelName}.${field}`, allowFrequencyLeakage);
                delete where[field];
            }
            else if (val && typeof val === 'object') {
                if (val.equals !== undefined) {
                    where[bidxField] = {
                        equals: computeBlindIndex(val.equals, rootSalt, `${modelName}.${field}`, allowFrequencyLeakage),
                    };
                    delete where[field];
                }
            }
        }
    }
    // Recurse into compound logical operators
    const operators = ['AND', 'OR', 'NOT'];
    for (const op of operators) {
        if (Array.isArray(where[op])) {
            where[op].forEach((item) => rewriteQueryWhere(item, fields, rootSalt, modelName, allowFrequencyLeakage));
        }
        else if (where[op] && typeof where[op] === 'object') {
            rewriteQueryWhere(where[op], fields, rootSalt, modelName, allowFrequencyLeakage);
        }
    }
}
/**
 * Adds blind-index companion fields before an ORM write.
 */
function addBlindIndexes(data, fields, rootSalt, modelName, allowFrequencyLeakage) {
    if (!data || typeof data !== 'object')
        return;
    if (Array.isArray(data)) {
        data.forEach((item) => addBlindIndexes(item, fields, rootSalt, modelName, allowFrequencyLeakage));
        return;
    }
    for (const field of fields) {
        if (data[field] !== undefined && data[field] !== null) {
            const bidxField = `${field}_bidx`;
            data[bidxField] = computeBlindIndex(data[field], rootSalt, `${modelName}.${field}`, allowFrequencyLeakage);
        }
    }
}
