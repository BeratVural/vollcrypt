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
exports.CRYPTO_ALGORITHMS = exports.VERSION_ALGORITHMS = exports.dbGuardContextStore = void 0;
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
exports.configureAuditLogger = configureAuditLogger;
exports.resetAuditLoggerForTesting = resetAuditLoggerForTesting;
exports.logDecryption = logDecryption;
exports.decryptWithSecurity = decryptWithSecurity;
exports.parseCiphertext = parseCiphertext;
const async_hooks_1 = require("async_hooks");
const crypto = __importStar(require("crypto"));
const fs = __importStar(require("fs"));
const KEY_WRAP_IV = Buffer.from('A6A6A6A6A6A6A6A6', 'hex');
function wrapKey(kek, keyToWrap) {
    if (kek.length !== 32) {
        throw new Error('KEK must be exactly 32 bytes');
    }
    const cipher = crypto.createCipheriv('id-aes256-wrap', kek, KEY_WRAP_IV);
    return Buffer.concat([cipher.update(keyToWrap), cipher.final()]);
}
function unwrapKey(kek, wrappedKey) {
    if (kek.length !== 32) {
        throw new Error('KEK must be exactly 32 bytes');
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
        throw new Error('Padded message too short');
    }
    const len = padded.readUInt32BE(0);
    if (len > padded.length - 4) {
        throw new Error('Invalid padded message length');
    }
    return padded.subarray(4, 4 + len);
}
function encryptAesGcmPadded(key, plaintext, aad = null) {
    const padded = padMessageWithLen(plaintext);
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    if (aad) {
        cipher.setAAD(aad);
    }
    const ciphertext = Buffer.concat([cipher.update(padded), cipher.final()]);
    const tag = cipher.getAuthTag();
    return Buffer.concat([iv, ciphertext, tag]);
}
function decryptAesGcmPadded(key, encryptedData, aad = null) {
    const iv = encryptedData.subarray(0, 12);
    const tag = encryptedData.subarray(encryptedData.length - 16);
    const ciphertext = encryptedData.subarray(12, encryptedData.length - 16);
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(tag);
    if (aad) {
        decipher.setAAD(aad);
    }
    const padded = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    return unpadMessageWithLen(padded);
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
    const pkBytes = publicKey.export({ type: 'spki', format: 'der' }).subarray(12);
    const skBytes = privateKey.export({ type: 'pkcs8', format: 'der' }).subarray(16);
    return [skBytes, pkBytes];
}
function signMessage(secretKey, message) {
    const pkcs8Header = Buffer.from('302e020100300506032b657004220420', 'hex');
    const privateKeyObj = crypto.createPrivateKey({
        key: Buffer.concat([pkcs8Header, secretKey]),
        format: 'der',
        type: 'pkcs8'
    });
    return crypto.sign(null, message, privateKeyObj);
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
let decryptCount = 0;
let windowStart = Date.now();
let isFailClosed = false;
const globalKeysToZeroize = [];
// Ephemeral Master Key generated randomly on startup
let ephemeralMasterKey = crypto.randomBytes(32);
const secureKeyCache = new Map();
function getCachedKey(tenantId, version) {
    const cacheKey = `${tenantId || 'global'}:${version}`;
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
function setCachedKey(tenantId, version, plaintextKey, ttlMs = 120000) {
    const cacheKey = `${tenantId || 'global'}:${version}`;
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
    breakGlassThreshold = 0;
    breakGlassPublicKeys = [];
}
// Emergency Break-Glass variables
let breakGlassThreshold = 0;
let breakGlassPublicKeys = [];
let breakGlassEmergencyKey;
let isBreakGlassActiveFlag = false;
function configureBreakGlass(options) {
    breakGlassThreshold = options.threshold;
    breakGlassPublicKeys = options.publicKeys;
}
function deactivateBreakGlass() {
    isBreakGlassActiveFlag = false;
    if (breakGlassEmergencyKey) {
        breakGlassEmergencyKey.fill(0);
        breakGlassEmergencyKey = undefined;
    }
    logDecryption('SYSTEM', 'BREAK_GLASS_DEACTIVATED', undefined);
}
function isBreakGlassActive() {
    return isBreakGlassActiveFlag;
}
function getBreakGlassKey() {
    return breakGlassEmergencyKey;
}
function activateBreakGlass(signatures, emergencyBackupKey) {
    if (breakGlassThreshold <= 0 || breakGlassPublicKeys.length === 0) {
        throw new Error('Vollcrypt Security: Break-Glass protocol is not configured.');
    }
    if (signatures.length < breakGlassThreshold) {
        throw new Error(`Vollcrypt Security: Insufficient signatures. Required: ${breakGlassThreshold}, Provided: ${signatures.length}`);
    }
    const verifiedKeys = new Set();
    for (const sig of signatures) {
        if (!breakGlassPublicKeys.includes(sig.publicKey)) {
            throw new Error(`Vollcrypt Security: Public key ${sig.publicKey} is not in the authorized break-glass list.`);
        }
        if (verifiedKeys.has(sig.publicKey)) {
            throw new Error(`Vollcrypt Security: Duplicate signature from public key ${sig.publicKey}.`);
        }
        if (Math.abs(Date.now() - sig.timestamp) > 15 * 60 * 1000) {
            throw new Error(`Vollcrypt Security: Signature timestamp ${sig.timestamp} is outside the allowed 15-minute window.`);
        }
        const message = `break-glass-activate|${sig.timestamp}`;
        const pubKeyBuf = Buffer.from(sig.publicKey, 'hex');
        const msgBuf = Buffer.from(message, 'utf8');
        const sigBuf = Buffer.from(sig.signature, 'hex');
        const isValid = verifySignature(pubKeyBuf, msgBuf, sigBuf);
        if (!isValid) {
            throw new Error(`Vollcrypt Security: Invalid signature for public key ${sig.publicKey}.`);
        }
        verifiedKeys.add(sig.publicKey);
    }
    breakGlassEmergencyKey = Buffer.from(emergencyBackupKey);
    isBreakGlassActiveFlag = true;
    logDecryption('SYSTEM', 'BREAK_GLASS_ACTIVATED', undefined);
}
function registerKeysForZeroization(keys) {
    if (!globalKeysToZeroize.includes(keys)) {
        globalKeysToZeroize.push(keys);
    }
}
function triggerFailClosed(onFailClosedCallback) {
    isFailClosed = true;
    // Zeroize all registered keys immediately in memory
    for (const keyMap of globalKeysToZeroize) {
        for (const key of Object.values(keyMap)) {
            key.fill(0);
        }
    }
    // Zeroize cache and ephemeral master key
    for (const entry of secureKeyCache.values()) {
        entry.wrappedKey.fill(0);
    }
    secureKeyCache.clear();
    ephemeralMasterKey.fill(0);
    if (breakGlassEmergencyKey) {
        breakGlassEmergencyKey.fill(0);
    }
    if (onFailClosedCallback) {
        try {
            onFailClosedCallback();
        }
        catch {
            // prevent user callback crash from blocking zeroization
        }
    }
    throw new Error('Vollcrypt Security: Decryption rate limit exceeded. Fail-Closed mode triggered. Keys zeroized.');
}
function checkRateLimit(options) {
    if (isFailClosed) {
        throw new Error('Vollcrypt Security: Fail-Closed mode is active. Decryption blocked.');
    }
    const context = exports.dbGuardContextStore.getStore();
    if (context?.bypassRateLimit) {
        return; // Rate limit check bypassed for this request context
    }
    const limit = context?.maxDecryptionsPerSecond || options?.maxDecryptionsPerSecond || 500;
    const mode = context?.rateLimiterMode || options?.mode || 'fail_closed';
    const now = Date.now();
    if (context) {
        if (context.windowStart === undefined || context.decryptCount === undefined) {
            context.windowStart = now;
            context.decryptCount = 0;
        }
        if (now - context.windowStart > 1000) {
            context.decryptCount = 0;
            context.windowStart = now;
        }
        context.decryptCount++;
        if (context.decryptCount > limit) {
            if (mode === 'fail_closed') {
                triggerFailClosed(options?.onFailClosed);
            }
            else if (mode === 'warn') {
                console.warn(`Vollcrypt Warning: Decryption rate limit exceeded. ${context.decryptCount} decryptions in the current window (limit: ${limit}).`);
            }
        }
    }
    else {
        if (now - windowStart > 1000) {
            decryptCount = 0;
            windowStart = now;
        }
        decryptCount++;
        if (decryptCount > limit) {
            if (mode === 'fail_closed') {
                triggerFailClosed(options?.onFailClosed);
            }
            else if (mode === 'warn') {
                console.warn(`Vollcrypt Warning: Decryption rate limit exceeded. ${decryptCount} decryptions in the current window (limit: ${limit}).`);
            }
        }
    }
}
function checkPageSize(count, options) {
    if (isFailClosed) {
        throw new Error('Vollcrypt Security: Fail-Closed mode is active. Decryption blocked.');
    }
    const context = exports.dbGuardContextStore.getStore();
    const maxPageSize = context?.maxPageSize !== undefined
        ? context.maxPageSize
        : (options?.maxPageSize !== undefined ? options.maxPageSize : 250);
    const behavior = context?.onPageSizeExceeded
        ? context.onPageSizeExceeded
        : (options?.onPageSizeExceeded || 'warn');
    if (count > maxPageSize) {
        if (behavior === 'error') {
            throw new Error(`Vollcrypt Security: Query returned ${count} records, which exceeds the max allowed page size of ${maxPageSize}. Decryption blocked to prevent rate limit execution.`);
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
function getFailClosedStatus() {
    return isFailClosed;
}
function resetFailClosedStatusForTesting() {
    isFailClosed = false;
    decryptCount = 0;
    windowStart = Date.now();
}
let lastLogHash = '0'.repeat(64);
let auditLogPath;
let onAuditLogCallback;
function configureAuditLogger(options) {
    if (options?.path) {
        auditLogPath = options.path;
        try {
            if (fs.existsSync(auditLogPath)) {
                const content = fs.readFileSync(auditLogPath, 'utf8').trim();
                if (content) {
                    const lines = content.split('\n');
                    const lastLine = lines[lines.length - 1];
                    if (lastLine) {
                        const entry = JSON.parse(lastLine);
                        if (entry && entry.hash) {
                            lastLogHash = entry.hash;
                        }
                    }
                }
            }
        }
        catch {
            // fallback to genesis hash on error
        }
    }
    if (options?.onAuditLog)
        onAuditLogCallback = options.onAuditLog;
}
function resetAuditLoggerForTesting() {
    lastLogHash = '0'.repeat(64);
    auditLogPath = undefined;
    onAuditLogCallback = undefined;
}
function logDecryption(model, field, recordId) {
    const context = exports.dbGuardContextStore.getStore();
    const timestamp = new Date().toISOString();
    const entry = {
        timestamp,
        userId: context?.userId,
        role: context?.role,
        model,
        field,
        recordId: recordId ? String(recordId) : undefined,
        action: 'decrypt',
        prevHash: lastLogHash
    };
    const payload = `${entry.timestamp}|${entry.userId || ''}|${entry.role || ''}|${entry.model}|${entry.field}|${entry.recordId || ''}|${entry.action}|${entry.prevHash}`;
    const hash = crypto.createHash('sha256').update(payload).digest('hex');
    const fullEntry = { ...entry, hash };
    lastLogHash = hash;
    if (onAuditLogCallback) {
        try {
            onAuditLogCallback(fullEntry);
        }
        catch {
            // prevent callback errors from stopping application flow
        }
    }
    if (auditLogPath) {
        try {
            fs.appendFileSync(auditLogPath, JSON.stringify(fullEntry) + '\n', 'utf8');
        }
        catch {
            // prevent filesystem errors from throwing
        }
    }
}
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
            throw new Error(`Vollcrypt Security: Role "${role || 'GUEST'}" is not authorized to decrypt field "${fieldKey}".`);
        }
    }
    // 2. Authorized or RBAC disabled: proceed with normal decryption
    checkRateLimit(options?.rateLimiter);
    const result = decryptRawFn(stored);
    logDecryption(modelName, fieldName, recordId);
    return result;
}
exports.VERSION_ALGORITHMS = {
    '1': '1'
};
exports.CRYPTO_ALGORITHMS = {
    '1': {
        encrypt: (plaintext, key) => encryptAesGcmPadded(key, plaintext, null),
        decrypt: (ciphertext, key) => decryptAesGcmPadded(key, ciphertext, null),
    }
};
function parseCiphertext(stored) {
    if (!stored.startsWith('VOLLVALT:'))
        return null;
    const content = stored.slice('VOLLVALT:'.length);
    if (content.startsWith('v')) {
        const colon = content.indexOf(':');
        if (colon === -1)
            return null;
        const versionPart = content.slice(1, colon);
        const base64Part = content.slice(colon + 1);
        const algoId = exports.VERSION_ALGORITHMS[versionPart] || '1';
        return { algoId, version: versionPart, base64Data: base64Part };
    }
    return null;
}
