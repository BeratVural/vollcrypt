import { dbGuardError } from './errors';
export type DbGuardKeyInput = Buffer | Record<string, Buffer>;

export interface NormalizedDbGuardKeys {
  keys: Record<string, Buffer>;
  activeVersion: string;
  activeKey: Buffer;
}

/**
 * Clones and validates an adapter keyring, returning its selected active key.
 */
export function normalizeKeys(
  input: DbGuardKeyInput,
  requestedActiveVersion?: string
): NormalizedDbGuardKeys {
  const keys: Record<string, Buffer> = {};
  if (Buffer.isBuffer(input)) {
    keys['1'] = Buffer.from(input);
  } else {
    for (const [version, key] of Object.entries(input)) {
      if (!version || !Buffer.isBuffer(key)) {
        throw dbGuardError('Vollcrypt DbGuard: key versions must map to Buffer values');
      }
      keys[version] = Buffer.from(key);
    }
  }

  const versions = Object.keys(keys);
  if (versions.length === 0) {
    throw dbGuardError('Vollcrypt DbGuard: at least one encryption key is required');
  }
  for (const [version, key] of Object.entries(keys)) {
    if (key.length !== 32) {
      throw dbGuardError(
        'Vollcrypt DbGuard: encryption key version "' + version + '" must be exactly 32 bytes'
      );
    }
  }

  const activeVersion = requestedActiveVersion ?? (Buffer.isBuffer(input) ? '1' : versions[0]);
  const activeKey = keys[activeVersion];
  if (!activeKey) {
    throw dbGuardError(
      'Vollcrypt DbGuard: active encryption key version "' +
        activeVersion +
        '" is not present in the key map'
    );
  }

  return { keys, activeVersion, activeKey };
}
