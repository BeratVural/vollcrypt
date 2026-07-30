"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.reconstructKeyFromXorShares = reconstructKeyFromXorShares;
/**
 * Reconstructs a DEK from single-process XOR key-split shares.
 * This is an n-of-n compatibility helper; it requires every share and provides no threshold guarantee.
 */
function reconstructKeyFromXorShares(shares) {
    if (shares.length < 2) {
        throw new Error('XOR key-split reconstruction requires at least 2 shares');
    }
    const length = shares[0].length;
    // Assert all shares are of identical length
    for (const share of shares) {
        if (share.length !== length) {
            throw new Error('All XOR key-split shares must have identical lengths');
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
