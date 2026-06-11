export interface KmsProvider {
    decrypt(ciphertext: Buffer): Promise<Buffer>;
}
export declare class AwsKmsProvider implements KmsProvider {
    private config;
    constructor(config: {
        region: string;
        keyId?: string;
        credentials?: any;
    });
    decrypt(ciphertext: Buffer): Promise<Buffer>;
}
export declare class GcpKmsProvider implements KmsProvider {
    private config;
    constructor(config: {
        keyName: string;
        clientOptions?: any;
    });
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
