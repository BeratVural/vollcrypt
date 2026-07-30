/**
 * Reconstructs a DEK from single-process XOR key-split shares.
 * This is an n-of-n compatibility helper; it requires every share and provides no threshold guarantee.
 */
export declare function reconstructKeyFromXorShares(shares: Buffer[]): Buffer;
