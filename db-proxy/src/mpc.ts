/**
 * Reconstructs a 256-bit DEK from every share in a single-process XOR key split.
 * This is n-of-n compatibility behavior, not threshold sharing or MPC.
 */
export function reconstructKeyFromXorShares(
  shares: readonly Buffer[],
  expectedShareCount: number
): Buffer {
  if (!Number.isSafeInteger(expectedShareCount) || expectedShareCount < 2) {
    throw new Error('XOR key-split expectedShareCount must be an integer of at least 2');
  }
  if (shares.length !== expectedShareCount) {
    throw new Error(
      'XOR key-split requires exactly ' + expectedShareCount + ' shares; received ' + shares.length
    );
  }

  for (const share of shares) {
    if (!Buffer.isBuffer(share) || share.length !== 32) {
      throw new Error('Every XOR key-split share must be a 32-byte Buffer');
    }
  }

  const reconstructed = Buffer.alloc(32);
  for (let i = 0; i < reconstructed.length; i++) {
    for (const share of shares) {
      reconstructed[i] ^= share[i];
    }
  }

  return reconstructed;
}
