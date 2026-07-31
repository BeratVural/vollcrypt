import { AsyncLocalStorage } from 'async_hooks';
import * as crypto from 'crypto';
import * as fs from 'fs';
const KEY_WRAP_IV = Buffer.from('A6A6A6A6A6A6A6A6', 'hex');
export const MAX_CIPHERTEXT_STRING_LENGTH = 8 * 1024 * 1024;
export const MAX_PLAINTEXT_BYTES = 6 * 1024 * 1024;

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
  if (plaintext.length > MAX_PLAINTEXT_BYTES) {
    throw new Error('Plaintext exceeds the maximum supported field size');
  }

  const padded = padMessageWithLen(plaintext);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  if (aad) cipher.setAAD(aad);

  let updateChunk: Buffer | undefined;
  let finalChunk: Buffer | undefined;
  try {
    updateChunk = cipher.update(padded);
    finalChunk = cipher.final();
    const tag = cipher.getAuthTag();
    return Buffer.concat([iv, updateChunk, finalChunk, tag]);
  } finally {
    padded.fill(0);
    updateChunk?.fill(0);
    finalChunk?.fill(0);
  }
}

export function decryptAesGcmPadded(key: Buffer, encryptedData: Buffer, aad: Buffer | null = null): Buffer {
  if (encryptedData.length < 28 || encryptedData.length > MAX_CIPHERTEXT_STRING_LENGTH) {
    throw new Error('Ciphertext length is outside the supported field bounds');
  }

  const iv = encryptedData.subarray(0, 12);
  const tag = encryptedData.subarray(encryptedData.length - 16);
  const ciphertext = encryptedData.subarray(12, encryptedData.length - 16);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  if (aad) decipher.setAAD(aad);

  let updateChunk: Buffer | undefined;
  let finalChunk: Buffer | undefined;
  let padded: Buffer | undefined;
  try {
    updateChunk = decipher.update(ciphertext);
    finalChunk = decipher.final();
    padded = Buffer.concat([updateChunk, finalChunk]);
    return Buffer.from(unpadMessageWithLen(padded));
  } finally {
    updateChunk?.fill(0);
    finalChunk?.fill(0);
    padded?.fill(0);
  }
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
  const publicDer = publicKey.export({ type: 'spki', format: 'der' });
  const privateDer = privateKey.export({ type: 'pkcs8', format: 'der' });
  try {
    return [
      Buffer.from(privateDer.subarray(16)),
      Buffer.from(publicDer.subarray(12))
    ];
  } finally {
    privateDer.fill(0);
  }
}

export function signMessage(secretKey: Buffer, message: Buffer): Buffer {
  if (!Buffer.isBuffer(secretKey) || secretKey.length !== 32) {
    throw new Error('Ed25519 secret key must be a 32-byte Buffer');
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
  } finally {
    privateDer.fill(0);
  }
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

// Cache store maps the structured tenant/version tuple to a wrapped DEK and expiration.
interface CacheEntry {
  wrappedKey: Buffer;
  expiresAt: number;
}
const secureKeyCache = new Map<string, CacheEntry>();
export const DEFAULT_KEY_CACHE_TTL_MS = 120_000;

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

export function setCachedKey(
  tenantId: string | undefined,
  version: string,
  plaintextKey: Buffer,
  ttlMs: number = DEFAULT_KEY_CACHE_TTL_MS
) {
  if (!Number.isSafeInteger(ttlMs) || ttlMs <= 0) {
    throw new Error('Key cache TTL must be a positive integer in milliseconds');
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

export function invalidateCachedKeys(tenantId: string | undefined, version?: string): number {
  const normalizedTenant = tenantId || 'global';
  let invalidated = 0;
  for (const [cacheKey, entry] of secureKeyCache.entries()) {
    try {
      const parsed = JSON.parse(cacheKey);
      if (
        Array.isArray(parsed) &&
        parsed[0] === normalizedTenant &&
        (version === undefined || parsed[1] === version)
      ) {
        entry.wrappedKey.fill(0);
        secureKeyCache.delete(cacheKey);
        invalidated++;
      }
    } catch {
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
let breakGlassPublicKeys: string[] = [];
let breakGlassEmergencyKey: Buffer | undefined;
let isBreakGlassActiveFlag = false;
const tenantBreakGlassEmergencyKeys = new Map<string, Buffer>();
const tenantBreakGlassActive = new Set<string>();

export function configureBreakGlass(options: { threshold: number; publicKeys: string[] }) {
  breakGlassThreshold = options.threshold;
  breakGlassPublicKeys = options.publicKeys;
}

export function deactivateBreakGlass(tenantId?: string) {
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

export function isBreakGlassActive(tenantId?: string): boolean {
  if (tenantId) return tenantBreakGlassActive.has(tenantId);
  return isBreakGlassActiveFlag;
}

export function getBreakGlassKey(tenantId?: string): Buffer | undefined {
  if (tenantId) return tenantBreakGlassEmergencyKeys.get(tenantId);
  return breakGlassEmergencyKey;
}

export function activateBreakGlass(
  signatures: { publicKey: string; signature: string; timestamp: number }[],
  emergencyBackupKey: Buffer,
  tenantId?: string
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

  if (tenantId) {
    const existing = tenantBreakGlassEmergencyKeys.get(tenantId);
    if (existing) existing.fill(0);
    tenantBreakGlassEmergencyKeys.set(tenantId, Buffer.from(emergencyBackupKey));
    tenantBreakGlassActive.add(tenantId);
    logDecryption('SYSTEM', `BREAK_GLASS_ACTIVATED:${tenantId}`, undefined);
    return;
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
    for (const key of tenantBreakGlassEmergencyKeys.values()) {
      key.fill(0);
    }
    tenantBreakGlassEmergencyKeys.clear();
    tenantBreakGlassActive.clear();
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

type UnsignedAuditLogEntry = Omit<AuditLogEntry, 'hash'>;

const AUDIT_GENESIS_HASH = '0'.repeat(64);
let lastLogHash = AUDIT_GENESIS_HASH;
let auditLogPath: string | undefined;
let auditIntegrityKey: Buffer | undefined;
let onAuditLogCallback: ((entry: AuditLogEntry) => void) | undefined;
let auditWriteQueue = Promise.resolve();

function serializeAuditEntry(entry: UnsignedAuditLogEntry): string {
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

function computeAuditMac(entry: UnsignedAuditLogEntry, integrityKey: Buffer): string {
  return crypto
    .createHmac('sha256', integrityKey)
    .update(serializeAuditEntry(entry))
    .digest('hex');
}

export function verifyAuditLogEntries(
  entries: readonly AuditLogEntry[],
  integrityKey: Buffer
): boolean {
  if (!Buffer.isBuffer(integrityKey) || integrityKey.length < 32) return false;

  let expectedPrevHash = AUDIT_GENESIS_HASH;
  for (const entry of entries) {
    if (
      entry.prevHash !== expectedPrevHash ||
      typeof entry.hash !== 'string' ||
      !/^[0-9a-f]{64}$/i.test(entry.hash)
    ) {
      return false;
    }

    const unsigned: UnsignedAuditLogEntry = {
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
    if (
      expectedMac.length !== actualMac.length ||
      !crypto.timingSafeEqual(expectedMac, actualMac)
    ) {
      return false;
    }
    expectedPrevHash = entry.hash;
  }

  return true;
}

export function configureAuditLogger(options?: {
  integrityKey: Buffer;
  path?: string;
  onAuditLog?: (entry: AuditLogEntry) => void;
}) {
  if (!options) {
    resetAuditLoggerForTesting();
    return;
  }
  if (!Buffer.isBuffer(options.integrityKey) || options.integrityKey.length < 32) {
    throw new Error('Vollcrypt Security: Audit integrity key must be at least 32 bytes.');
  }

  if (auditIntegrityKey) auditIntegrityKey.fill(0);
  auditIntegrityKey = Buffer.from(options.integrityKey);
  auditLogPath = options.path;
  onAuditLogCallback = options.onAuditLog;
  lastLogHash = AUDIT_GENESIS_HASH;

  if (!auditLogPath || !fs.existsSync(auditLogPath)) return;

  let entries: AuditLogEntry[];
  try {
    const content = fs.readFileSync(auditLogPath, 'utf8').trim();
    entries = content
      ? content.split('\n').map((line) => JSON.parse(line) as AuditLogEntry)
      : [];
  } catch (error) {
    throw new Error(
      'Vollcrypt Security: Audit log could not be parsed; refusing to continue.',
      { cause: error }
    );
  }

  if (!verifyAuditLogEntries(entries, auditIntegrityKey)) {
    throw new Error(
      'Vollcrypt Security: Audit log integrity verification failed; refusing to continue.'
    );
  }
  if (entries.length > 0) {
    lastLogHash = entries[entries.length - 1].hash;
  }
}

export function resetAuditLoggerForTesting() {
  lastLogHash = AUDIT_GENESIS_HASH;
  auditLogPath = undefined;
  if (auditIntegrityKey) auditIntegrityKey.fill(0);
  auditIntegrityKey = undefined;
  onAuditLogCallback = undefined;
  auditWriteQueue = Promise.resolve();
}

export function logDecryption(model: string, field: string, recordId?: string) {
  if (!auditIntegrityKey) return;

  const context = dbGuardContextStore.getStore();
  const entry: UnsignedAuditLogEntry = {
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
  const fullEntry: AuditLogEntry = { ...entry, hash };
  lastLogHash = hash;

  if (onAuditLogCallback) {
    try {
      onAuditLogCallback(fullEntry);
    } catch {
      // Audit callbacks are observers and cannot change decryption behavior.
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
    allowUnrestrictedDecrypt?: boolean;
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
  } else if (!options?.allowUnrestrictedDecrypt) {
    const context = dbGuardContextStore.getStore();
    const role = context?.role || 'GUEST';
    if (role !== 'OWNER') {
      throw new Error(`Vollcrypt Security: Crypto-RBAC is not configured. Refusing unrestricted decrypt for role "${role}" on field "${fieldKey}".`);
    }
  }

  // 2. Authorized or explicitly unrestricted: proceed with normal decryption
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
  if (typeof stored !== 'string') {
    throw new Error('Vollcrypt Security: Ciphertext must be a string.');
  }
  if (stored.length > MAX_CIPHERTEXT_STRING_LENGTH) {
    throw new Error('Vollcrypt Security: Ciphertext exceeds the maximum supported field size.');
  }
  if (/[\x00-\x1f\x7f]/.test(stored)) {
    throw new Error('Vollcrypt Security: Ciphertext contains forbidden control characters.');
  }
  if (!stored.startsWith('VOLLVALT:')) return null;

  const content = stored.slice('VOLLVALT:'.length);
  if (!content.startsWith('v')) {
    throw new Error('Vollcrypt Security: Legacy unversioned ciphertexts are deprecated and unsupported.');
  }

  const colon = content.indexOf(':');
  if (colon === -1) {
    throw new Error('Vollcrypt Security: Malformed ciphertext format.');
  }

  const versionPart = content.slice(1, colon);
  const base64Part = content.slice(colon + 1);
  if (!/^[1-9][0-9]{0,5}$/.test(versionPart)) {
    throw new Error('Vollcrypt Security: Malformed ciphertext version.');
  }

  const algoId = VERSION_ALGORITHMS[versionPart];
  if (!algoId) {
    throw new Error('Vollcrypt Security: Deprecated or unsupported encryption version "v' + versionPart + '".');
  }

  if (
    base64Part.length === 0 ||
    base64Part.length % 4 !== 0 ||
    !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(base64Part)
  ) {
    throw new Error('Vollcrypt Security: Ciphertext payload is not canonical Base64.');
  }

  return { algoId, version: versionPart, base64Data: base64Part };
}
/**
 * Computes a keyed deterministic equality index.
 *
 * Equal plaintexts in the same column produce equal indexes and therefore leak
 * frequency information. Callers must explicitly acknowledge that tradeoff.
 */
export function validateBlindIndexConfiguration(
  rootSalt: Buffer,
  allowFrequencyLeakage: true
): void {
  if (!Buffer.isBuffer(rootSalt) || rootSalt.length < 32) {
    throw new Error('Vollcrypt Security: Blind-index rootSalt must be at least 32 bytes.');
  }
  if (allowFrequencyLeakage !== true) {
    throw new Error(
      'Vollcrypt Security: Deterministic blind indexes leak equality frequency. Set allowFrequencyLeakage: true only after accepting this risk.'
    );
  }
}

export function computeBlindIndex(
  value: any,
  rootSalt: Buffer,
  columnName: string,
  allowFrequencyLeakage: true
): string {
  if (value === null || value === undefined) return value;
  validateBlindIndexConfiguration(rootSalt, allowFrequencyLeakage);

  const plaintext = typeof value === 'string' ? value : JSON.stringify(value);
  const columnNameBuf = Buffer.from(columnName, 'utf8');
  const derivedColumnKey = deriveHkdf(rootSalt, null, columnNameBuf, 32);
  const plaintextBuf = Buffer.from(plaintext, 'utf8');

  try {
    const blindIndex = deriveHkdf(derivedColumnKey, null, plaintextBuf, 32);
    return blindIndex.toString('hex');
  } finally {
    plaintextBuf.fill(0);
    derivedColumnKey.fill(0);
  }
}
export function encryptValue(val: any, key: Buffer, version: string): string {
  if (val === null || val === undefined) return val;
  const context = dbGuardContextStore.getStore();
  const tId = context?.tenantId || 'global';
  if (key.every(b => b === 0) || getFailClosedStatus(tId)) {
    throw new Error('Vollcrypt Security: Fail-Closed mode is active for tenant "' + tId + '". Encryption blocked.');
  }

  const plaintextBuf = Buffer.isBuffer(val)
    ? Buffer.from(val)
    : Buffer.from(typeof val === 'string' ? val : JSON.stringify(val), 'utf8');

  try {
    if (plaintextBuf.length > MAX_PLAINTEXT_BYTES) {
      throw new Error('Vollcrypt Security: Plaintext exceeds the maximum supported field size.');
    }
    const encrypted = CRYPTO_ALGORITHMS['1'].encrypt(plaintextBuf, key);
    return 'VOLLVALT:v' + version + ':' + encrypted.toString('base64');
  } finally {
    plaintextBuf.fill(0);
  }
}

/**
 * Decrypts directly to a mutable Buffer and avoids creating an immutable V8 plaintext string.
 * The caller owns the returned buffer and must zeroize it with fill(0) after use.
 */
export function decryptBufferValue(stored: string, keys: Record<string, Buffer>): Buffer {
  const parsed = parseCiphertext(stored);
  if (!parsed) {
    throw new Error('Vollcrypt Security: decryptBufferValue accepts encrypted values only.');
  }

  const { algoId, version, base64Data } = parsed;
  const key = keys[version];
  if (!key) {
    throw new Error('Decryption key version "' + version + '" not found in registered keys');
  }
  if (key.every(b => b === 0)) {
    throw new Error('Vollcrypt Security: Decryption blocked. Key version "' + version + '" is zeroized due to a Fail-Closed event.');
  }

  const encryptedBuf = Buffer.from(base64Data, 'base64');
  try {
    const decryptor = CRYPTO_ALGORITHMS[algoId];
    if (!decryptor) {
      throw new Error('Unsupported decryption algorithm ID "' + algoId + '"');
    }
    return decryptor.decrypt(encryptedBuf, key);
  } catch (err) {
    throw new Error('Failed to decrypt field value: ' + (err as Error).message);
  } finally {
    encryptedBuf.fill(0);
  }
}

export function decryptValue(stored: any, keys: Record<string, Buffer>): any {
  if (typeof stored !== 'string') return stored;
  if (!stored.startsWith('VOLLVALT:')) return stored;

  const decrypted = decryptBufferValue(stored, keys);
  try {
    // Compatibility API: V8 strings cannot provide deterministic zeroization.
    const plaintext = decrypted.toString('utf8');
    try {
      return JSON.parse(plaintext);
    } catch {
      return plaintext;
    }
  } finally {
    decrypted.fill(0);
  }
}
export function rewriteQueryWhere(where: any, fields: string[], rootSalt: Buffer, modelName: string, allowFrequencyLeakage: true) {
  if (!where || typeof where !== 'object') return;

  for (const field of fields) {
    if (where[field] !== undefined) {
      const val = where[field];
      const bidxField = `${field}_bidx`;

      if (typeof val === 'string' || typeof val === 'number' || typeof val === 'boolean') {
        where[bidxField] = computeBlindIndex(val, rootSalt, `${modelName}.${field}`, allowFrequencyLeakage);
        delete where[field];
      } else if (val && typeof val === 'object') {
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
      where[op].forEach((item: any) => rewriteQueryWhere(item, fields, rootSalt, modelName, allowFrequencyLeakage));
    } else if (where[op] && typeof where[op] === 'object') {
      rewriteQueryWhere(where[op], fields, rootSalt, modelName, allowFrequencyLeakage);
    }
  }
}

export function addBlindIndexes(data: any, fields: string[], rootSalt: Buffer, modelName: string, allowFrequencyLeakage: true) {
  if (!data || typeof data !== 'object') return;

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
