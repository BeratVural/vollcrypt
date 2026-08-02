export type DbGuardKeyInput = Buffer | Record<string, Buffer>;
export interface NormalizedDbGuardKeys {
    keys: Record<string, Buffer>;
    activeVersion: string;
    activeKey: Buffer;
}
/**
 * Clones and validates an adapter keyring, returning its selected active key.
 */
export declare function normalizeKeys(input: DbGuardKeyInput, requestedActiveVersion?: string): NormalizedDbGuardKeys;
