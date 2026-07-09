/* tslint:disable */
/* eslint-disable */

export class AuthenticatedKemResult {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    free(): void;
    readonly ciphertext: Uint8Array;
    /**
     * WARNING: shared_secret should only be used in SRK derivation,
     * and should not be used as an encryption key directly.
     */
    readonly shared_secret: Uint8Array;
}

export class Ed25519KeyPairObj {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    sign(message: Uint8Array): Uint8Array;
    readonly public_key: Uint8Array;
    readonly secret_key: Uint8Array;
}

export class HybridKemResult {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    readonly ml_kem_ciphertext: Uint8Array;
    readonly shared_key: Uint8Array;
}

export class MlKemEncapsulationResult {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    readonly ciphertext: Uint8Array;
    readonly shared_secret: Uint8Array;
}

export class MlKemKeyPairObj {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    readonly decapsulation_key: Uint8Array;
    readonly encapsulation_key: Uint8Array;
}

export class RatchetKeyPairObj {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    /**
     * Computes SRK ratchet using this key pair.
     * secret_key never crosses the WASM boundary.
     */
    compute_ratchet(current_srk: Uint8Array, their_ratchet_pub: Uint8Array, chat_id: Uint8Array, ratchet_step: number): Uint8Array;
    readonly public_key: Uint8Array;
}

export class UnpackedEnvelope {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    window_index: number;
    readonly aad_hash: Uint8Array;
    readonly encrypted_blob: Uint8Array;
}

export class UnsealResult {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    free(): void;
    readonly content: Uint8Array;
    readonly sender_id: Uint8Array;
}

/**
 * Verification code result (for WASM)
 */
export class VerificationCodeResult {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    readonly emoji_formatted: string;
    readonly fingerprint: Uint8Array;
    readonly numeric_digits: string;
    readonly numeric_formatted: string;
}

export class X25519KeyPairObj {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    readonly public: Uint8Array;
    readonly secret: Uint8Array;
}

export function authenticated_kem_decapsulate(our_x25519_sk: Uint8Array, sender_x25519_pub: Uint8Array, our_mlkem_dk: Uint8Array, authenticated_ciphertext: Uint8Array, sender_identity_pk: Uint8Array): Uint8Array;

export function authenticated_kem_encapsulate(our_x25519_sk: Uint8Array, recipient_x25519_pub: Uint8Array, recipient_mlkem_pub: Uint8Array, sender_identity_sk: Uint8Array): AuthenticatedKemResult;

export function compute_fingerprint(key_a: Uint8Array, key_b: Uint8Array, conversation_id: Uint8Array): Uint8Array;

export function decrypt_aes_gcm(key: Uint8Array, ciphertext: Uint8Array, aad?: Uint8Array | null): Uint8Array;

export function decrypt_aes_gcm_chunked(key: Uint8Array, ciphertext: Uint8Array, aad?: Uint8Array | null): Uint8Array;

export function decrypt_aes_gcm_chunked_padded(key: Uint8Array, ciphertext: Uint8Array, aad?: Uint8Array | null): Uint8Array;

export function decrypt_aes_gcm_padded(key: Uint8Array, ciphertext: Uint8Array, aad?: Uint8Array | null): Uint8Array;

export function derive_hkdf(ikm: Uint8Array, salt: Uint8Array | null | undefined, info: Uint8Array | null | undefined, key_len: number): Uint8Array;

export function derive_pbkdf2(password: Uint8Array, salt: Uint8Array, iterations: number, key_len: number): Uint8Array;

export function derive_srk(dek: Uint8Array, chat_id: Uint8Array): Uint8Array;

export function derive_window_key(srk: Uint8Array, window_index: number): Uint8Array;

export function ecdh_shared_secret(our_secret: Uint8Array, their_public: Uint8Array): Uint8Array;

export function encrypt_aes_gcm(key: Uint8Array, plaintext: Uint8Array, aad?: Uint8Array | null): Uint8Array;

export function encrypt_aes_gcm_chunked(key: Uint8Array, plaintext: Uint8Array, aad: Uint8Array | null | undefined, chunk_size: number): Uint8Array;

export function encrypt_aes_gcm_chunked_padded(key: Uint8Array, plaintext: Uint8Array, aad: Uint8Array | null | undefined, chunk_size: number): Uint8Array;

export function encrypt_aes_gcm_padded(key: Uint8Array, plaintext: Uint8Array, aad?: Uint8Array | null): Uint8Array;

export function generate_ed25519_keypair(): Ed25519KeyPairObj;

export function generate_mnemonic(): string;

export function generate_ratchet_keypair(): RatchetKeyPairObj;

export function generate_verification_code(key_a: Uint8Array, key_b: Uint8Array, conversation_id: Uint8Array): VerificationCodeResult;

export function generate_x25519_keypair(): X25519KeyPairObj;

export function hybrid_kem_decapsulate(x25519_our_secret: Uint8Array, x25519_their_public: Uint8Array, ml_kem_dk: Uint8Array, ml_kem_ct: Uint8Array): Uint8Array;

export function hybrid_kem_encapsulate(x25519_our_secret: Uint8Array, x25519_their_public: Uint8Array, ml_kem_ek: Uint8Array): HybridKemResult;

export function init_logger(): void;

export function key_log_compute_entry_hash(entry_json: string): Uint8Array;

export function key_log_create_entry(user_id: Uint8Array, public_key: Uint8Array, timestamp: number, prev_entry_hash: Uint8Array, action: number, signing_key: Uint8Array): string;

export function key_log_current_key(entries_json: string, user_id: Uint8Array): Uint8Array;

export function key_log_key_at_timestamp(entries_json: string, user_id: Uint8Array, timestamp: number): Uint8Array;

export function key_log_verify_chain(entries_json: string): boolean;

export function ml_kem_decapsulate(decapsulation_key: Uint8Array, ciphertext: Uint8Array): Uint8Array;

export function ml_kem_encapsulate(encapsulation_key: Uint8Array): MlKemEncapsulationResult;

export function ml_kem_keygen(): MlKemKeyPairObj;

export function mnemonic_to_seed(phrase: string, password?: string | null): Uint8Array;

export function pack_envelope(window_index: number, aad_hash: Uint8Array, encrypted_blob: Uint8Array): Uint8Array;

export function pad_message(content: Uint8Array): Uint8Array;

export function registry_add_device(registry_json: string, device_id: string, name: string, added_at: number, public_key: string): string;

export function registry_empty(): string;

export function registry_get_active_devices(registry_json: string): string;

export function registry_revoke_device(registry_json: string, device_id: string): string;

export function seal_message(recipient_x25519_pub: Uint8Array, sender_id: Uint8Array, content: Uint8Array): Uint8Array;

export function should_ratchet(message_count: number, window_changed: boolean, messages_per_ratchet: number, ratchet_on_new_window: boolean): boolean;

export function sign_message(secret_key: Uint8Array, message: Uint8Array): Uint8Array;

export function transcript_compute_message_hash(message_id: Uint8Array, sender_id: Uint8Array, timestamp: number, ciphertext: Uint8Array): Uint8Array;

export function transcript_new(session_id: Uint8Array): Uint8Array;

export function transcript_update(chain_state: Uint8Array, message_hash: Uint8Array): Uint8Array;

export function transcript_verify_sync(hash_a: Uint8Array, hash_b: Uint8Array): boolean;

export function unpack_envelope(envelope: Uint8Array): UnpackedEnvelope;

export function unseal_message(sealed_packet: Uint8Array, our_x25519_sk: Uint8Array): UnsealResult;

export function unwrap_key(kek: Uint8Array, wrapped_key: Uint8Array): Uint8Array;

export function verify_fingerprints_match(fingerprint_a: Uint8Array, fingerprint_b: Uint8Array): boolean;

export function verify_signature(public_key: Uint8Array, message: Uint8Array, signature: Uint8Array): boolean;

export function wrap_key(kek: Uint8Array, key_to_wrap: Uint8Array): Uint8Array;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly __wbg_authenticatedkemresult_free: (a: number, b: number) => void;
    readonly __wbg_ed25519keypairobj_free: (a: number, b: number) => void;
    readonly __wbg_get_unpackedenvelope_window_index: (a: number) => number;
    readonly __wbg_set_unpackedenvelope_window_index: (a: number, b: number) => void;
    readonly __wbg_unpackedenvelope_free: (a: number, b: number) => void;
    readonly __wbg_unsealresult_free: (a: number, b: number) => void;
    readonly __wbg_verificationcoderesult_free: (a: number, b: number) => void;
    readonly authenticated_kem_decapsulate: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number) => [number, number, number];
    readonly authenticated_kem_encapsulate: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => [number, number, number];
    readonly authenticatedkemresult_ciphertext: (a: number) => [number, number];
    readonly authenticatedkemresult_free: (a: number) => void;
    readonly authenticatedkemresult_shared_secret: (a: number) => [number, number];
    readonly compute_fingerprint: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
    readonly decrypt_aes_gcm: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number];
    readonly decrypt_aes_gcm_chunked: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number];
    readonly decrypt_aes_gcm_chunked_padded: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number];
    readonly decrypt_aes_gcm_padded: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number];
    readonly derive_hkdf: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => [number, number, number];
    readonly derive_pbkdf2: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number];
    readonly derive_srk: (a: number, b: number, c: number, d: number) => [number, number, number];
    readonly derive_window_key: (a: number, b: number, c: number) => [number, number, number];
    readonly ecdh_shared_secret: (a: number, b: number, c: number, d: number) => [number, number, number];
    readonly ed25519keypairobj_public_key: (a: number) => [number, number];
    readonly ed25519keypairobj_secret_key: (a: number) => [number, number];
    readonly ed25519keypairobj_sign: (a: number, b: number, c: number) => [number, number, number, number];
    readonly encrypt_aes_gcm: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
    readonly encrypt_aes_gcm_chunked: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => [number, number, number, number];
    readonly encrypt_aes_gcm_chunked_padded: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => [number, number, number, number];
    readonly encrypt_aes_gcm_padded: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
    readonly generate_ed25519_keypair: () => number;
    readonly generate_mnemonic: () => [number, number];
    readonly generate_ratchet_keypair: () => [number, number, number];
    readonly generate_verification_code: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number];
    readonly generate_x25519_keypair: () => number;
    readonly hybrid_kem_decapsulate: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => [number, number, number];
    readonly hybrid_kem_encapsulate: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number];
    readonly init_logger: () => void;
    readonly key_log_compute_entry_hash: (a: number, b: number) => [number, number, number, number];
    readonly key_log_create_entry: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number) => [number, number, number, number];
    readonly key_log_current_key: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly key_log_key_at_timestamp: (a: number, b: number, c: number, d: number, e: number) => [number, number, number, number];
    readonly key_log_verify_chain: (a: number, b: number) => [number, number, number];
    readonly ml_kem_decapsulate: (a: number, b: number, c: number, d: number) => [number, number, number];
    readonly ml_kem_encapsulate: (a: number, b: number) => [number, number, number];
    readonly ml_kem_keygen: () => number;
    readonly mnemonic_to_seed: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly pack_envelope: (a: number, b: number, c: number, d: number, e: number) => [number, number, number, number];
    readonly pad_message: (a: number, b: number) => [number, number];
    readonly ratchetkeypairobj_compute_ratchet: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => [number, number, number, number];
    readonly registry_add_device: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number) => [number, number, number, number];
    readonly registry_empty: () => [number, number];
    readonly registry_get_active_devices: (a: number, b: number) => [number, number, number, number];
    readonly registry_revoke_device: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly seal_message: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
    readonly should_ratchet: (a: number, b: number, c: number, d: number) => number;
    readonly sign_message: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly transcript_compute_message_hash: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => [number, number];
    readonly transcript_new: (a: number, b: number) => [number, number];
    readonly transcript_update: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly transcript_verify_sync: (a: number, b: number, c: number, d: number) => number;
    readonly unpack_envelope: (a: number, b: number) => [number, number, number];
    readonly unpackedenvelope_aad_hash: (a: number) => [number, number];
    readonly unpackedenvelope_encrypted_blob: (a: number) => [number, number];
    readonly unseal_message: (a: number, b: number, c: number, d: number) => [number, number, number];
    readonly unsealresult_content: (a: number) => [number, number];
    readonly unsealresult_free: (a: number) => void;
    readonly unsealresult_sender_id: (a: number) => [number, number];
    readonly unwrap_key: (a: number, b: number, c: number, d: number) => [number, number, number];
    readonly verificationcoderesult_emoji_formatted: (a: number) => [number, number];
    readonly verificationcoderesult_fingerprint: (a: number) => [number, number];
    readonly verificationcoderesult_numeric_digits: (a: number) => [number, number];
    readonly verificationcoderesult_numeric_formatted: (a: number) => [number, number];
    readonly verify_fingerprints_match: (a: number, b: number, c: number, d: number) => [number, number, number];
    readonly verify_signature: (a: number, b: number, c: number, d: number, e: number, f: number) => number;
    readonly wrap_key: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly __wbg_mlkemencapsulationresult_free: (a: number, b: number) => void;
    readonly hybridkemresult_ml_kem_ciphertext: (a: number) => [number, number];
    readonly hybridkemresult_shared_key: (a: number) => [number, number];
    readonly mlkemencapsulationresult_ciphertext: (a: number) => [number, number];
    readonly mlkemencapsulationresult_shared_secret: (a: number) => [number, number];
    readonly mlkemkeypairobj_decapsulation_key: (a: number) => [number, number];
    readonly mlkemkeypairobj_encapsulation_key: (a: number) => [number, number];
    readonly ratchetkeypairobj_public_key: (a: number) => [number, number];
    readonly x25519keypairobj_public: (a: number) => [number, number];
    readonly x25519keypairobj_secret: (a: number) => [number, number];
    readonly __wbg_hybridkemresult_free: (a: number, b: number) => void;
    readonly __wbg_mlkemkeypairobj_free: (a: number, b: number) => void;
    readonly __wbg_ratchetkeypairobj_free: (a: number, b: number) => void;
    readonly __wbg_x25519keypairobj_free: (a: number, b: number) => void;
    readonly __wbindgen_exn_store: (a: number) => void;
    readonly __externref_table_alloc: () => number;
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
    readonly __externref_table_dealloc: (a: number) => void;
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
