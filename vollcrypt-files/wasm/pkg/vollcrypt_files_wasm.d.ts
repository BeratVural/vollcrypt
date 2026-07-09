/* tslint:disable */
/* eslint-disable */

export class GroupManifest {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    addMember(new_member_id: Uint8Array, new_member_pk: any, current_gk: Uint8Array, _admin_pk: Uint8Array, admin_sk: Uint8Array, _timestamp: number): void;
    currentGkVersion(): number;
    currentMembers(): any;
    findMemberWrap(member_id: Uint8Array): any;
    findMemberWrapForVersion(member_id: Uint8Array, gk_version: number): any;
    static genesis(group_id: Uint8Array, initial_gk: Uint8Array, founder_member_id: Uint8Array, founder_recipient_pk: any, founder_ed25519_pk: Uint8Array, founder_ed25519_sk: Uint8Array, _timestamp: number): GroupManifest;
    isVersionShredded(gk_version: number): boolean;
    static parse(bytes: Uint8Array): GroupManifest;
    removeMember(removed_member_id: Uint8Array, _admin_pk: Uint8Array, admin_sk: Uint8Array, _timestamp: number): void;
    rotateGroupKey(new_gk: Uint8Array, _admin_pk: Uint8Array, admin_sk: Uint8Array, timestamp: number): number;
    shredGroupKey(version_to_shred: number, reason: string, _admin_pk: Uint8Array, admin_sk: Uint8Array, timestamp: number): void;
    verify(): void;
    write(): Uint8Array;
}

export class HeaderClass {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    static parse(bytes: Uint8Array): any;
    static write(header: any): Uint8Array;
}

export class KeyLog {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    static create(authority_pubkey: Uint8Array): KeyLog;
    deviceWasActiveAt(device_id: Uint8Array, timestamp: number): boolean;
    lookupByEntryHash(hash: Uint8Array): any;
    static parse(bytes: Uint8Array): KeyLog;
    registerDevice(user_id: Uint8Array, device_id: Uint8Array, device_pk: Uint8Array, human_label: string, authority_sk: Uint8Array, timestamp: number): Uint8Array;
    revokeDevice(device_id: Uint8Array, authority_sk: Uint8Array, timestamp: number): void;
    userForDevice(device_id: Uint8Array): any;
    verify(): void;
    write(): Uint8Array;
}

export class WasmBufferPool {
    free(): void;
    [Symbol.dispose](): void;
    constructor(chunk_size: number, pool_size: number);
    rent(): WasmPooledBuffer;
    returnBuffer(buffer: WasmPooledBuffer): void;
}

export class WasmPooledBuffer {
    free(): void;
    [Symbol.dispose](): void;
    ciphertextPtr(): number;
    dataPtr(): number;
    getCiphertext(len: number): Uint8Array;
    getEnvelope(len: number): Uint8Array;
    getIndex(): number;
    getIv(): Uint8Array;
    getPlaintext(len: number): Uint8Array;
    constructor(chunk_size: number);
    plaintextPtr(): number;
    setIndex(index: number): void;
    setIv(iv: Uint8Array): void;
    tagPtr(len: number): number;
}

export function chunkLeafHash(envelope: any): Uint8Array;

export function cryptoShredHeader(header_bytes: Uint8Array): Uint8Array;

export function decodeShare(s: string): any;

export function decryptChunk(dek: Uint8Array, file_id: Uint8Array, chunk_index: number, envelope: any): Uint8Array;

export function decryptFilePipelinedAsync(ciphertext: Uint8Array, dek: Uint8Array, policy: any): Promise<any>;

export function ed25519KeypairGenerate(): any;

export function ed25519Sign(sk: Uint8Array, message: Uint8Array): Uint8Array;

export function ed25519Verify(pk: Uint8Array, message: Uint8Array, signature: Uint8Array): boolean;

export function encodeShare(share: any): string;

export function encryptChunk(dek: Uint8Array, file_id: Uint8Array, chunk_index: number, plaintext: Uint8Array): any;

export function encryptFilePipelinedAsync(plaintext: Uint8Array, dek: Uint8Array, file_id: Uint8Array, chunk_size: number, wraps: any, mode_val: number, sign_info_val: any, write_mode_val: any): Promise<any>;

export function generateDek(): Uint8Array;

export function generateFileId(): Uint8Array;

export function generateGk(): Uint8Array;

export function generateRecipientKeypair(): any;

export function generateSalt(): Uint8Array;

export function getWasmMemoryView(ptr: number, len: number): Uint8Array;

export function hybridKeypairGenerate(): any;

export function hybridSign(sk: Uint8Array, pk: Uint8Array, domain: string, context: Uint8Array, payload: Uint8Array): Uint8Array;

export function hybridVerify(pk: Uint8Array, domain: string, context: Uint8Array, payload: Uint8Array, signature: Uint8Array): boolean;

export function inspectSealedContainer(container_bytes: Uint8Array): any;

export function isSealed(header_obj: any): boolean;

export function merkleProof(leaves: any, leaf_index: number): any;

export function merkleRoot(leaves: any): Uint8Array;

export function resolveSender(header: any, key_log: KeyLog, sealed_gk?: Uint8Array | null): any;

export function rewrapDekInHeader(header_bytes: Uint8Array, old_gk: Uint8Array, new_gk: Uint8Array, new_gk_version: number): any;

export function sealContainer(container_bytes: Uint8Array, options: any): Uint8Array;

export function signHeaderPlain(header: any, signer_pk: Uint8Array, signer_sk: Uint8Array, key_log_id: Uint8Array, timestamp: number): any;

export function signHeaderSealed(header: any, signer_pk: Uint8Array, signer_sk: Uint8Array, key_log_id: Uint8Array, timestamp: number, sealed_group_id: Uint8Array, sealed_gk_version: number, sealed_gk: Uint8Array): any;

export function unwrapDekWithGroupKey(wrap: any, gk: Uint8Array): Uint8Array;

export function unwrapDekWithPassword(wrap: any, password: string): Uint8Array;

export function unwrapDekWithThresholdShares(wrap: any, file_id: Uint8Array, shares: any, cipher_suite_id: number): Uint8Array;

export function unwrapKeyWithRecipientKey(wrap: any, recipient_sk: any): Uint8Array;

export function verifyContainer(container_bytes: Uint8Array, policy: any): string;

export function verifyHeaderSignaturePlain(header: any): Uint8Array;

export function verifyHeaderSignatureSealed(header: any, sealed_gk: Uint8Array, key_log: KeyLog): Uint8Array;

export function verifyMerkleProof(leaf: Uint8Array, leaf_index: number, total_leaves: number, proof: any, expected_root: Uint8Array): boolean;

export function wrapDekForGroup(dek: Uint8Array, group_id: Uint8Array, gk_version: number, gk: Uint8Array): any;

export function wrapDekWithPassword(dek: Uint8Array, password: string, kdf: any): any;

export function wrapDekWithThreshold(dek: Uint8Array, file_id: Uint8Array, t: number, n: number, cipher_suite_id: number): any;

export function wrapKeyToRecipient(key: Uint8Array, recipient_id: Uint8Array, gk_version: number, recipient_pk: any): any;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly __wbg_groupmanifest_free: (a: number, b: number) => void;
    readonly __wbg_headerclass_free: (a: number, b: number) => void;
    readonly __wbg_keylog_free: (a: number, b: number) => void;
    readonly __wbg_wasmbufferpool_free: (a: number, b: number) => void;
    readonly __wbg_wasmpooledbuffer_free: (a: number, b: number) => void;
    readonly chunkLeafHash: (a: any) => [number, number, number, number];
    readonly cryptoShredHeader: (a: number, b: number) => [number, number, number, number];
    readonly decodeShare: (a: number, b: number) => [number, number, number];
    readonly decryptChunk: (a: number, b: number, c: number, d: number, e: number, f: any) => [number, number, number, number];
    readonly decryptFilePipelinedAsync: (a: number, b: number, c: number, d: number, e: any) => any;
    readonly ed25519KeypairGenerate: () => [number, number, number];
    readonly ed25519Sign: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly ed25519Verify: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number];
    readonly encodeShare: (a: any) => [number, number, number, number];
    readonly encryptChunk: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => [number, number, number];
    readonly encryptFilePipelinedAsync: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: any, i: number, j: any, k: any) => any;
    readonly generateDek: () => [number, number];
    readonly generateFileId: () => [number, number];
    readonly generateGk: () => [number, number];
    readonly generateRecipientKeypair: () => [number, number, number];
    readonly generateSalt: () => [number, number];
    readonly getWasmMemoryView: (a: number, b: number) => any;
    readonly groupmanifest_addMember: (a: number, b: number, c: number, d: any, e: number, f: number, g: number, h: number, i: number, j: number, k: number) => [number, number];
    readonly groupmanifest_currentGkVersion: (a: number) => number;
    readonly groupmanifest_currentMembers: (a: number) => [number, number, number];
    readonly groupmanifest_findMemberWrap: (a: number, b: number, c: number) => [number, number, number];
    readonly groupmanifest_findMemberWrapForVersion: (a: number, b: number, c: number, d: number) => [number, number, number];
    readonly groupmanifest_genesis: (a: number, b: number, c: number, d: number, e: number, f: number, g: any, h: number, i: number, j: number, k: number, l: number) => [number, number, number];
    readonly groupmanifest_isVersionShredded: (a: number, b: number) => number;
    readonly groupmanifest_parse: (a: number, b: number) => [number, number, number];
    readonly groupmanifest_removeMember: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => [number, number];
    readonly groupmanifest_rotateGroupKey: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => [number, number, number];
    readonly groupmanifest_shredGroupKey: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number) => [number, number];
    readonly groupmanifest_verify: (a: number) => [number, number];
    readonly groupmanifest_write: (a: number) => [number, number];
    readonly headerclass_parse: (a: number, b: number) => [number, number, number];
    readonly headerclass_write: (a: any) => [number, number, number, number];
    readonly hybridKeypairGenerate: () => [number, number, number];
    readonly hybridSign: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number) => [number, number, number, number];
    readonly hybridVerify: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number) => [number, number, number];
    readonly inspectSealedContainer: (a: number, b: number) => [number, number, number];
    readonly isSealed: (a: any) => [number, number, number];
    readonly keylog_create: (a: number, b: number) => [number, number, number];
    readonly keylog_deviceWasActiveAt: (a: number, b: number, c: number, d: number) => [number, number, number];
    readonly keylog_lookupByEntryHash: (a: number, b: number, c: number) => [number, number, number];
    readonly keylog_parse: (a: number, b: number) => [number, number, number];
    readonly keylog_registerDevice: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number, l: number) => [number, number, number, number];
    readonly keylog_revokeDevice: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number];
    readonly keylog_userForDevice: (a: number, b: number, c: number) => [number, number, number];
    readonly keylog_verify: (a: number) => [number, number];
    readonly keylog_write: (a: number) => [number, number];
    readonly merkleProof: (a: any, b: number) => [number, number, number];
    readonly merkleRoot: (a: any) => [number, number, number, number];
    readonly resolveSender: (a: any, b: number, c: number, d: number) => [number, number, number];
    readonly rewrapDekInHeader: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => [number, number, number];
    readonly sealContainer: (a: number, b: number, c: any) => [number, number, number, number];
    readonly signHeaderPlain: (a: any, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => [number, number, number];
    readonly signHeaderSealed: (a: any, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number, l: number, m: number) => [number, number, number];
    readonly unwrapDekWithGroupKey: (a: any, b: number, c: number) => [number, number, number, number];
    readonly unwrapDekWithPassword: (a: any, b: number, c: number) => [number, number, number, number];
    readonly unwrapDekWithThresholdShares: (a: any, b: number, c: number, d: any, e: number) => [number, number, number, number];
    readonly unwrapKeyWithRecipientKey: (a: any, b: any) => [number, number, number, number];
    readonly verifyContainer: (a: number, b: number, c: any) => [number, number, number, number];
    readonly verifyHeaderSignaturePlain: (a: any) => [number, number, number, number];
    readonly verifyHeaderSignatureSealed: (a: any, b: number, c: number, d: number) => [number, number, number, number];
    readonly verifyMerkleProof: (a: number, b: number, c: number, d: number, e: any, f: number, g: number) => [number, number, number];
    readonly wasmbufferpool_new: (a: number, b: number) => number;
    readonly wasmbufferpool_rent: (a: number) => number;
    readonly wasmbufferpool_returnBuffer: (a: number, b: number) => void;
    readonly wasmpooledbuffer_ciphertextPtr: (a: number) => number;
    readonly wasmpooledbuffer_dataPtr: (a: number) => number;
    readonly wasmpooledbuffer_getCiphertext: (a: number, b: number) => [number, number];
    readonly wasmpooledbuffer_getEnvelope: (a: number, b: number) => [number, number];
    readonly wasmpooledbuffer_getIndex: (a: number) => number;
    readonly wasmpooledbuffer_getIv: (a: number) => [number, number];
    readonly wasmpooledbuffer_getPlaintext: (a: number, b: number) => [number, number];
    readonly wasmpooledbuffer_new: (a: number) => number;
    readonly wasmpooledbuffer_plaintextPtr: (a: number) => number;
    readonly wasmpooledbuffer_setIndex: (a: number, b: number) => void;
    readonly wasmpooledbuffer_setIv: (a: number, b: number, c: number) => void;
    readonly wasmpooledbuffer_tagPtr: (a: number, b: number) => number;
    readonly wrapDekForGroup: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => [number, number, number];
    readonly wrapDekWithPassword: (a: number, b: number, c: number, d: number, e: any) => [number, number, number];
    readonly wrapDekWithThreshold: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => [number, number, number];
    readonly wrapKeyToRecipient: (a: number, b: number, c: number, d: number, e: number, f: any) => [number, number, number];
    readonly wasm_bindgen__convert__closures_____invoke__h5359ba2451a7ff25: (a: number, b: number, c: any) => [number, number];
    readonly wasm_bindgen__convert__closures_____invoke__h340851764cb2bc00: (a: number, b: number, c: any, d: any) => void;
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
    readonly __wbindgen_exn_store: (a: number) => void;
    readonly __externref_table_alloc: () => number;
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __wbindgen_destroy_closure: (a: number, b: number) => void;
    readonly __externref_table_dealloc: (a: number) => void;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
