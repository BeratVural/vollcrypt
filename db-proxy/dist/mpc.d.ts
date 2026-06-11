/**
 * Reconstructs the original 32-byte Data Encryption Key (DEK)
 * using a threshold XOR-based secret sharing scheme.
 */
export declare function reconstructKeyMpc(shares: Buffer[]): Buffer;
