import { AsyncLocalStorage } from 'async_hooks';
import * as crypto from 'crypto';
import * as fs from 'fs';
const KEY_WRAP_IV = Buffer.from('A6A6A6A6A6A6A6A6', 'hex');

export function wrapKey(kek: Buffer, keyToWrap: Buffer): Buffer {
  if (kek.length !== 32) {
    throw new Error('KEK must be exactly 32 bytes');
  }
  const cipher = crypto.createCipheriv('id-aes256-wrap', kek, KEY_WRAP_IV);
  return Buffer.concat([cipher.update(keyToWrap), cipher.final()]);
}

export function unwrapKey(kek: Buffer, wrappedKey: Buffer): Buffer {
  if (kek.length !== 32) {
    throw new Error('KEK must be exactly 32 bytes');
  }
  const decipher = crypto.createDecipheriv('id-aes256-wrap', kek, KEY_WRAP_IV);
  return Buffer.concat([decipher.update(wrappedKey), decipher.final()]);
}

export function calculatePadding(contentLen: number): Buffer {
  const sizes = [64, 128, 256, 512, 1024, 2048];
  const minPadding = 2;
  let target = sizes.find(s => s >= contentLen + minPadding);
  if (target === undefined) {
    const remainder = (contentLen + minPadding) % 1024;
    if (remainder === 0) {
      target = contentLen + minPadding;
    } else {
      target = contentLen + minPadding + (1024 - remainder);
    }
  }
  const paddingLen = target - contentLen;
  return crypto.randomBytes(paddingLen);
}

export function padMessageWithLen(content: Buffer): Buffer {
  const lenBytes = Buffer.alloc(4);
  lenBytes.writeUInt32BE(content.length, 0);
  const baseLen = 4 + content.length;
  const paddingBytes = calculatePadding(baseLen);
  return Buffer.concat([lenBytes, content, paddingBytes]);
}

export function unpadMessageWithLen(padded: Buffer): Buffer {
  if (padded.length < 4) {
    throw new Error('Padded message too short');
  }
  const len = padded.readUInt32BE(0);
  if (len > padded.length - 4) {
    throw new Error('Invalid padded message length');
  }
  return padded.subarray(4, 4 + len);
}

export function encryptAesGcmPadded(key: Buffer, plaintext: Buffer, aad: Buffer | null = null): Buffer {
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

export function decryptAesGcmPadded(key: Buffer, encryptedData: Buffer, aad: Buffer | null = null): Buffer {
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

export function verifySignature(publicKey: Buffer, message: Buffer, signature: Buffer): boolean {
  try {
    const spkiHeader = Buffer.from('302a300506032b6570032100', 'hex');
    const pubKey = crypto.createPublicKey({
      key: Buffer.concat([spkiHeader, publicKey]),
      format: 'der',
      type: 'spki'
    });
    return crypto.verify(null, message, pubKey, signature);
  } catch (err) {
    return false;
  }
}

export function deriveHkdf(ikm: Buffer, salt: Buffer | null, info: Buffer | null, keyLen: number): Buffer {
  return Buffer.from(
    crypto.hkdfSync(
      'sha256',
      ikm,
      salt || Buffer.alloc(0),
      info || Buffer.alloc(0),
      keyLen
    )
  );
}

export function generateEd25519Keypair(): [Buffer, Buffer] {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const pkBytes = publicKey.export({ type: 'spki', format: 'der' }).subarray(12);
  const skBytes = privateKey.export({ type: 'pkcs8', format: 'der' }).subarray(16);
  return [skBytes, pkBytes];
}

export function signMessage(secretKey: Buffer, message: Buffer): Buffer {
  const pkcs8Header = Buffer.from('302e020100300506032b657004220420', 'hex');
  const privateKeyObj = crypto.createPrivateKey({
    key: Buffer.concat([pkcs8Header, secretKey]),
    format: 'der',
    type: 'pkcs8'
  });
  return crypto.sign(null, message, privateKeyObj);
}

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

// 1. Request Context Store (AsyncLocalStorage)
export const dbGuardContextStore = new AsyncLocalStorage<UserContext>();

// 2. Dynamic Data Masking (DDM)
export function maskValue(val: any, rule: 'credit_card' | 'email' | 'tc_no' | ((v: any) => any) | string): any {
  if (val === null || val === undefined) return val;
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

// 3. Decryption Rate Limiter (Anti-Scraping)
export interface RateLimiterOptions {
  maxDecryptionsPerSecond?: number;
  onFailClosed?: () => void;
  mode?: 'fail_closed' | 'warn' | 'disabled';
  maxPageSize?: number;
  onPageSizeExceeded?: 'warn' | 'error' | 'bypass';
}



// Ephemeral Master Key generated randomly on startup
let ephemeralMasterKey = crypto.randomBytes(32);

const tenantFailClosed = new Map<string, boolean>();
const tenantKeys = new Map<string, Record<string, Buffer>[]>();

interface RateLimitState {
  decryptCount: number;
  windowStart: number;
}
const tenantRateLimitStates = new Map<string, RateLimitState>();

// Cache store mapping `${tenantId || 'global'}:${version}` to wrapped DEK and expiration
interface CacheEntry {
  wrappedKey: Buffer;
  expiresAt: number;
}
const secureKeyCache = new Map<string, CacheEntry>();

export function getCachedKey(tenantId: string | undefined, version: string): Buffer | undefined {
  const cacheKey = JSON.stringify([tenantId || 'global', version]);
  const entry = secureKeyCache.get(cacheKey);
  if (!entry) return undefined;
  if (Date.now() > entry.expiresAt) {
    entry.wrappedKey.fill(0);
    secureKeyCache.delete(cacheKey);
    return undefined;
  }
  try {
    return unwrapKey(ephemeralMasterKey, entry.wrappedKey);
  } catch {
    return undefined;
  }
}

export function setCachedKey(tenantId: string | undefined, version: string, plaintextKey: Buffer, ttlMs: number = 120000) {
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

export function resetSecureKeyCacheForTesting() {
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
let breakGlassPublicKeys: string[] = [];
let breakGlassEmergencyKey: Buffer | undefined;
let isBreakGlassActiveFlag = false;

export function configureBreakGlass(options: { threshold: number; publicKeys: string[] }) {
  breakGlassThreshold = options.threshold;
  breakGlassPublicKeys = options.publicKeys;
}

export function deactivateBreakGlass() {
  isBreakGlassActiveFlag = false;
  if (breakGlassEmergencyKey) {
    breakGlassEmergencyKey.fill(0);
    breakGlassEmergencyKey = undefined;
  }
  logDecryption('SYSTEM', 'BREAK_GLASS_DEACTIVATED', undefined);
}

export function isBreakGlassActive(): boolean {
  return isBreakGlassActiveFlag;
}

export function getBreakGlassKey(): Buffer | undefined {
  return breakGlassEmergencyKey;
}

export function activateBreakGlass(
  signatures: { publicKey: string; signature: string; timestamp: number }[],
  emergencyBackupKey: Buffer
) {
  if (breakGlassThreshold <= 0 || breakGlassPublicKeys.length === 0) {
    throw new Error('Vollcrypt Security: Break-Glass protocol is not configured.');
  }
  if (signatures.length < breakGlassThreshold) {
    throw new Error(`Vollcrypt Security: Insufficient signatures. Required: ${breakGlassThreshold}, Provided: ${signatures.length}`);
  }

  const verifiedKeys = new Set<string>();

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

export function registerKeysForZeroization(keys: Record<string, Buffer>, tenantId?: string) {
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

export function triggerFailClosed(onFailClosedCallback?: () => void, tenantId?: string) {
  const tId = tenantId || dbGuardContextStore.getStore()?.tenantId || 'global';
  tenantFailClosed.set(tId, true);
  
  // Zeroize all registered keys immediately in memory for this tenant
  const list = tenantKeys.get(tId);
  if (list && list.length > 0) {
    for (const keyMap of list) {
      for (const key of Object.values(keyMap)) {
        key.fill(0);
      }
    }
  } else {
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
    } catch {
      // fallback
    }
  }
  
  if (tId === 'global') {
    ephemeralMasterKey.fill(0);
    if (breakGlassEmergencyKey) {
      breakGlassEmergencyKey.fill(0);
    }
  }
  
  if (onFailClosedCallback) {
    try {
      onFailClosedCallback();
    } catch {
      // prevent user callback crash from blocking zeroization
    }
  }
  throw new Error(`Vollcrypt Security: Decryption rate limit exceeded. Fail-Closed mode triggered for tenant "${tId}". Keys zeroized.`);
}

export function checkRateLimit(options?: RateLimiterOptions) {
  const context = dbGuardContextStore.getStore();
  const tId = context?.tenantId || 'global';

  if (tenantFailClosed.get(tId)) {
    throw new Error(`Vollcrypt Security: Fail-Closed mode is active for tenant "${tId}". Decryption blocked.`);
  }

  if (context?.bypassRateLimit) {
    return; // Rate limit check bypassed for this request context
  }

  const limit = context?.maxDecryptionsPerSecond || options?.maxDecryptionsPerSecond || 500;
  const mode = context?.rateLimiterMode || options?.mode || 'fail_closed';
  const now = Date.now();

  let state = tenantRateLimitStates.get(tId);
  if (!state) {
    state = { decryptCount: 0, windowStart: now };
    tenantRateLimitStates.set(tId, state);
  }

  if (now - state.windowStart > 1000) {
    state.decryptCount = 0;
    state.windowStart = now;
  }

  state.decryptCount++;
  if (state.decryptCount > limit) {
    if (mode === 'fail_closed') {
      triggerFailClosed(options?.onFailClosed, tId);
    } else if (mode === 'warn') {
      console.warn(`Vollcrypt Warning: Decryption rate limit exceeded for tenant "${tId}". ${state.decryptCount} decryptions in the current window (limit: ${limit}).`);
    }
  }
}

export function checkPageSize(
  count: number,
  options?: RateLimiterOptions
): 'ok' | 'warn' | 'bypass' | 'error' {
  const context = dbGuardContextStore.getStore();
  const tId = context?.tenantId || 'global';

  if (tenantFailClosed.get(tId)) {
    throw new Error(`Vollcrypt Security: Fail-Closed mode is active for tenant "${tId}". Decryption blocked.`);
  }

  const maxPageSize = context?.maxPageSize !== undefined 
    ? context.maxPageSize 
    : (options?.maxPageSize !== undefined ? options.maxPageSize : 250);

  const behavior = context?.onPageSizeExceeded 
    ? context.onPageSizeExceeded 
    : (options?.onPageSizeExceeded || 'warn');

  if (count > maxPageSize) {
    if (behavior === 'error') {
      throw new Error(`Vollcrypt Security: Query returned ${count} records, which exceeds the max allowed page size of ${maxPageSize}. Decryption blocked to prevent rate limit execution.`);
    } else if (behavior === 'warn') {
      console.warn(`Vollcrypt Warning: Query returned ${count} records, which exceeds the recommended page size limit of ${maxPageSize}. This may trigger the decryption rate limiter.`);
      return 'warn';
    } else if (behavior === 'bypass') {
      return 'bypass';
    }
  }

  return 'ok';
}

export function getFailClosedStatus(tenantId?: string): boolean {
  const tId = tenantId || dbGuardContextStore.getStore()?.tenantId || 'global';
  return tenantFailClosed.get(tId) || false;
}

export function resetFailClosedStatusForTesting() {
  tenantFailClosed.clear();
  tenantRateLimitStates.clear();
  tenantKeys.clear();
}

// 4. Cryptographic Audit Logging
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

let lastLogHash = '0'.repeat(64);
let auditLogPath: string | undefined;
let onAuditLogCallback: ((entry: AuditLogEntry) => void) | undefined;
let auditWriteQueue = Promise.resolve();

export function configureAuditLogger(options?: {
  path?: string;
  onAuditLog?: (entry: AuditLogEntry) => void;
}) {
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
    } catch {
      // fallback to genesis hash on error
    }
  }
  if (options?.onAuditLog) onAuditLogCallback = options.onAuditLog;
}

export function resetAuditLoggerForTesting() {
  lastLogHash = '0'.repeat(64);
  auditLogPath = undefined;
  onAuditLogCallback = undefined;
  auditWriteQueue = Promise.resolve();
}

export function logDecryption(model: string, field: string, recordId?: string) {
  const context = dbGuardContextStore.getStore();
  const timestamp = new Date().toISOString();
  
  const entry: Omit<AuditLogEntry, 'hash'> = {
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
  const fullEntry: AuditLogEntry = { ...entry, hash };

  lastLogHash = hash;

  if (onAuditLogCallback) {
    try {
      onAuditLogCallback(fullEntry);
    } catch {
      // prevent callback errors from stopping application flow
    }
  }

  if (auditLogPath) {
    const line = JSON.stringify(fullEntry) + '\n';
    const currentPath = auditLogPath;
    auditWriteQueue = auditWriteQueue.then(() => {
      return fs.promises.appendFile(currentPath, line, 'utf8').catch(() => {});
    });
  }
}

export function decryptWithSecurity(
  stored: any,
  decryptRawFn: (val: string) => any,
  modelName: string,
  fieldName: string,
  recordId: string | undefined,
  options?: {
    cryptoRbac?: {
      roles: Record<string, {
        decrypt: string[];
        mask?: Record<string, 'credit_card' | 'email' | 'tc_no' | ((v: any) => any) | string>;
      }>;
    };
    rateLimiter?: RateLimiterOptions;
  }
): any {
  if (typeof stored !== 'string' || !stored.startsWith('VOLLVALT:')) {
    // Dual-read fallback: if the value is not encrypted, return as is.
    return stored;
  }

  const fieldKey = `${modelName}.${fieldName}`;

  // 1. Check if Crypto-RBAC is configured
  if (options?.cryptoRbac) {
    const context = dbGuardContextStore.getStore();
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

export const VERSION_ALGORITHMS: Record<string, string> = {
  '1': '1',
  '2': '1'
};

export const CRYPTO_ALGORITHMS: Record<string, {
  encrypt: (plaintext: Buffer, key: Buffer) => Buffer;
  decrypt: (ciphertext: Buffer, key: Buffer) => Buffer;
}> = {
  '1': {
    encrypt: (plaintext, key) => encryptAesGcmPadded(key, plaintext, null),
    decrypt: (ciphertext, key) => decryptAesGcmPadded(key, ciphertext, null),
  }
};

export function parseCiphertext(stored: string): { algoId: string; version: string; base64Data: string } | null {
  if (!stored.startsWith('VOLLVALT:')) return null;
  const content = stored.slice('VOLLVALT:'.length);

  if (content.startsWith('v')) {
    const colon = content.indexOf(':');
    if (colon === -1) {
      throw new Error("Vollcrypt Security: Malformed ciphertext format.");
    }
    const versionPart = content.slice(1, colon);
    const base64Part = content.slice(colon + 1);
    const algoId = VERSION_ALGORITHMS[versionPart];
    if (!algoId) {
      throw new Error(`Vollcrypt Security: Deprecated or unsupported encryption version "v${versionPart}".`);
    }
    return { algoId, version: versionPart, base64Data: base64Part };
  }

  throw new Error("Vollcrypt Security: Legacy unversioned ciphertexts are deprecated and unsupported.");
}

/**
 * Computes a hardened, frequency-resistant blind index for a database field.
 */
export function computeBlindIndex(value: any, rootSalt: Buffer, columnName: string): string {
  if (value === null || value === undefined) return value;
  
  const plaintext = typeof value === 'string' ? value : JSON.stringify(value);
  const columnNameBuf = Buffer.from(columnName, 'utf8');

  // 1. Derive column-specific key using HKDF-SHA256
  const derivedColumnKey = deriveHkdf(rootSalt, null, columnNameBuf, 32);

  try {
    // 2. Compute the final blind index using the derived column key
    const plaintextBuf = Buffer.from(plaintext, 'utf8');
    const blindIndex = deriveHkdf(derivedColumnKey, null, plaintextBuf, 32);
    return blindIndex.toString('hex');
  } finally {
    // 3. RAM Security: Zeroize the derived key immediately (Anti-Core Dump)
    derivedColumnKey.fill(0);
  }
}

export function encryptValue(val: any, key: Buffer, version: string): string {
  if (val === null || val === undefined) return val;
  const context = dbGuardContextStore.getStore();
  const tId = context?.tenantId || 'global';
  if (key.every(b => b === 0) || getFailClosedStatus(tId)) {
    throw new Error(`Vollcrypt Security: Fail-Closed mode is active for tenant "${tId}". Encryption blocked.`);
  }
  const plaintext = typeof val === 'string' ? val : JSON.stringify(val);
  const plaintextBuf = Buffer.from(plaintext, 'utf8');
  
  const encrypted = CRYPTO_ALGORITHMS['1'].encrypt(plaintextBuf, key);
  
  // RAM Security: Zeroize the plaintext buffer immediately
  plaintextBuf.fill(0);
  
  return `VOLLVALT:v${version}:${encrypted.toString('base64')}`;
}

export function decryptValue(stored: any, keys: Record<string, Buffer>): any {
  if (typeof stored !== 'string') {
    return stored;
  }
  
  const parsed = parseCiphertext(stored);
  if (!parsed) {
    return stored;
  }

  const { algoId, version, base64Data } = parsed;

  const key = keys[version];
  if (!key) {
    throw new Error(`Decryption key version "${version}" not found in registered keys`);
  }

  if (key.every(b => b === 0)) {
    throw new Error(`Vollcrypt Security: Decryption blocked. Key version "${version}" is zeroized due to a Fail-Closed event.`);
  }

  try {
    const encryptedBuf = Buffer.from(base64Data, 'base64');
    const decryptor = CRYPTO_ALGORITHMS[algoId];
    if (!decryptor) {
      throw new Error(`Unsupported decryption algorithm ID "${algoId}"`);
    }
    const decrypted = decryptor.decrypt(encryptedBuf, key);
    const plaintext = decrypted.toString('utf8');
    
    // RAM Security: Zeroize the decrypted buffer
    decrypted.fill(0);

    try {
      return JSON.parse(plaintext);
    } catch {
      return plaintext;
    }
  } catch (err) {
    throw new Error(`Failed to decrypt field value: ${(err as Error).message}`);
  }
}

export function rewriteQueryWhere(where: any, fields: string[], rootSalt: Buffer, modelName: string) {
  if (!where || typeof where !== 'object') return;

  for (const field of fields) {
    if (where[field] !== undefined) {
      const val = where[field];
      const bidxField = `${field}_bidx`;

      if (typeof val === 'string' || typeof val === 'number' || typeof val === 'boolean') {
        where[bidxField] = computeBlindIndex(val, rootSalt, `${modelName}.${field}`);
        delete where[field];
      } else if (val && typeof val === 'object') {
        if (val.equals !== undefined) {
          where[bidxField] = {
            equals: computeBlindIndex(val.equals, rootSalt, `${modelName}.${field}`),
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
      where[op].forEach((item: any) => rewriteQueryWhere(item, fields, rootSalt, modelName));
    } else if (where[op] && typeof where[op] === 'object') {
      rewriteQueryWhere(where[op], fields, rootSalt, modelName);
    }
  }
}

export function addBlindIndexes(data: any, fields: string[], rootSalt: Buffer, modelName: string) {
  if (!data || typeof data !== 'object') return;

  if (Array.isArray(data)) {
    data.forEach((item) => addBlindIndexes(item, fields, rootSalt, modelName));
    return;
  }

  for (const field of fields) {
    if (data[field] !== undefined && data[field] !== null) {
      const bidxField = `${field}_bidx`;
      data[bidxField] = computeBlindIndex(data[field], rootSalt, `${modelName}.${field}`);
    }
  }
}
