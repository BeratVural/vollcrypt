/**
 * Reconstructs a 256-bit DEK from every share in a single-process XOR key split.
 * This is n-of-n compatibility behavior, not threshold sharing or MPC.
 */
export declare function reconstructKeyFromXorShares(shares: readonly Buffer[], expectedShareCount: number): Buffer;
