"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.reconstructKeyMpc = reconstructKeyMpc;
/**
 * Reconstructs the original 32-byte Data Encryption Key (DEK)
 * using a threshold XOR-based secret sharing scheme.
 */
function reconstructKeyMpc(shares) {
    if (shares.length < 2) {
        throw new Error('MPC key reconstruction requires at least 2 shares');
    }
    const length = shares[0].length;
    // Assert all shares are of identical length
    for (const share of shares) {
        if (share.length !== length) {
            throw new Error('All MPC key shares must have identical lengths');
        }
    }
    const reconstructed = Buffer.alloc(length);
    for (let i = 0; i < length; i++) {
        let xorValue = 0;
        for (const share of shares) {
            xorValue ^= share[i];
        }
        reconstructed[i] = xorValue;
    }
    return reconstructed;
}
