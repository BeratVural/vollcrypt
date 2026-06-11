/**
 * Computes a hardened, frequency-resistant blind index for a database field.
 *
 * Uses HKDF-SHA256 to derive a unique column key from the root salt,
 * preventing cross-column frequency analysis. Zeroizes intermediate keys immediately.
 */
export declare function computeBlindIndex(value: any, rootSalt: Buffer, columnName: string): string;
