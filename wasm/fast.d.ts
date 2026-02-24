export { default } from "./pkg/wasm"
export * from "./pkg/wasm"

export declare function encryptAesGcmWeb(
  key: CryptoKey | Uint8Array,
  plaintext: Uint8Array,
  aad?: Uint8Array | null
): Promise<Uint8Array>

export declare function decryptAesGcmWeb(
  key: CryptoKey | Uint8Array,
  ciphertext: Uint8Array,
  aad?: Uint8Array | null
): Promise<Uint8Array>

export declare function encryptAesGcmAuto(
  key: CryptoKey | Uint8Array,
  plaintext: Uint8Array,
  aad?: Uint8Array | null
): Promise<Uint8Array>

export declare function decryptAesGcmAuto(
  key: CryptoKey | Uint8Array,
  ciphertext: Uint8Array,
  aad?: Uint8Array | null
): Promise<Uint8Array>

export declare function encryptAesGcmChunkedWeb(
  key: CryptoKey | Uint8Array,
  plaintext: Uint8Array,
  aad: Uint8Array | null | undefined,
  chunkSize: number
): Promise<Uint8Array>

export declare function decryptAesGcmChunkedWeb(
  key: CryptoKey | Uint8Array,
  ciphertext: Uint8Array,
  aad: Uint8Array | null | undefined
): Promise<Uint8Array>

export declare function encryptAesGcmChunkedAuto(
  key: CryptoKey | Uint8Array,
  plaintext: Uint8Array,
  aad: Uint8Array | null | undefined,
  chunkSize: number
): Promise<Uint8Array>

export declare function decryptAesGcmChunkedAuto(
  key: CryptoKey | Uint8Array,
  ciphertext: Uint8Array,
  aad: Uint8Array | null | undefined
): Promise<Uint8Array>
