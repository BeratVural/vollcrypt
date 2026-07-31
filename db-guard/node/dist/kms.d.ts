export interface KmsProvider {
    decrypt(ciphertext: Buffer): Promise<Buffer>;
}
/**
 * Resolves a KMS/HSM-wrapped blind-index root salt.
 *
 * The caller owns the returned mutable buffer and must zeroize it when the
 * adapter is disposed.
 */
export declare function resolveBlindIndexRootSalt(provider: KmsProvider, wrappedRootSalt: Buffer): Promise<Buffer>;
export interface AwsKmsCredentialIdentity {
    accessKeyId: string;
    secretAccessKey: string;
    sessionToken?: string;
}
export interface AwsKmsProviderConfig {
    region: string;
    keyId?: string;
    credentials?: AwsKmsCredentialIdentity | (() => Promise<AwsKmsCredentialIdentity>);
}
export interface GcpKmsClientOptions {
    projectId?: string;
    keyFilename?: string;
    apiEndpoint?: string;
    credentials?: {
        client_email?: string;
        private_key?: string;
    };
}
export interface GcpKmsProviderConfig {
    keyName: string;
    clientOptions?: GcpKmsClientOptions;
}
export declare class AwsKmsProvider implements KmsProvider {
    private config;
    constructor(config: AwsKmsProviderConfig);
    decrypt(ciphertext: Buffer): Promise<Buffer>;
}
export declare class GcpKmsProvider implements KmsProvider {
    private config;
    constructor(config: GcpKmsProviderConfig);
    decrypt(ciphertext: Buffer): Promise<Buffer>;
}
export declare class VaultKmsProvider implements KmsProvider {
    private config;
    constructor(config: {
        url: string;
        token: string;
        keyName: string;
    });
    decrypt(ciphertext: Buffer): Promise<Buffer>;
}
/**
 * Local Envelope Decryption wrapper using AES-256-Key-Wrap (AES-KW)
 */
export declare function unwrapDekLocal(wrappedDek: Buffer, unwrappedKek: Buffer): Buffer;
/**
 * On-Premises HSM Provider using the standard PKCS#11 protocol
 */
export declare class Pkcs11KmsProvider implements KmsProvider {
    private config;
    constructor(config: {
        libraryPath: string;
        pin: string;
        slotId?: number;
        keyId: string;
    });
    decrypt(ciphertext: Buffer): Promise<Buffer>;
}
export interface DbGuardKeysOptions {
    key?: Buffer | Record<string, Buffer>;
    kms?: {
        provider: KmsProvider;
        wrappedKey: Buffer | Record<string, Buffer>;
        wrappedKek?: Buffer | Record<string, Buffer>;
        activeKeyVersion?: string;
    };
}
export declare function resolveKeys(options: DbGuardKeysOptions): Promise<Record<string, Buffer>>;
