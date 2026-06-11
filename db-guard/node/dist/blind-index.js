"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.computeBlindIndex = computeBlindIndex;
const security_1 = require("./security");
/**
 * Computes a hardened, frequency-resistant blind index for a database field.
 *
 * Uses HKDF-SHA256 to derive a unique column key from the root salt,
 * preventing cross-column frequency analysis. Zeroizes intermediate keys immediately.
 */
function computeBlindIndex(value, rootSalt, columnName) {
    if (value === null || value === undefined)
        return value;
    const plaintext = typeof value === 'string' ? value : JSON.stringify(value);
    const columnNameBuf = Buffer.from(columnName, 'utf8');
    // 1. Derive column-specific key using HKDF-SHA256
    const derivedColumnKey = (0, security_1.deriveHkdf)(rootSalt, null, columnNameBuf, 32);
    // 2. Compute the final blind index using the derived column key
    const plaintextBuf = Buffer.from(plaintext, 'utf8');
    const blindIndex = (0, security_1.deriveHkdf)(derivedColumnKey, null, plaintextBuf, 32);
    // 3. RAM Security: Zeroize the derived key immediately (Anti-Core Dump)
    derivedColumnKey.fill(0);
    return blindIndex.toString('hex');
}
