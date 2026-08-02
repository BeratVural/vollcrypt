import { dbGuardError } from './errors';
import { unwrapKey } from './security';

export interface KmsProvider {
  decrypt(ciphertext: Buffer): Promise<Buffer>;
}

/**
 * Resolves a KMS/HSM-wrapped blind-index root salt.
 *
 * The caller owns the returned mutable buffer and must zeroize it when the
 * adapter is disposed.
 */
export async function resolveBlindIndexRootSalt(
  provider: KmsProvider,
  wrappedRootSalt: Buffer
): Promise<Buffer> {
  if (!Buffer.isBuffer(wrappedRootSalt) || wrappedRootSalt.length === 0) {
    throw dbGuardError('Wrapped blind-index root salt must be a non-empty Buffer');
  }

  const rootSalt = await provider.decrypt(wrappedRootSalt);
  if (!Buffer.isBuffer(rootSalt)) {
    throw dbGuardError('KMS provider returned a non-Buffer blind-index root salt');
  }
  if (rootSalt.length < 32) {
    rootSalt.fill(0);
    throw dbGuardError('Decrypted blind-index root salt must be at least 32 bytes');
  }
  return rootSalt;
}

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

export class AwsKmsProvider implements KmsProvider {
  constructor(private config: AwsKmsProviderConfig) {}

  async decrypt(ciphertext: Buffer): Promise<Buffer> {
    try {
      const { KMSClient, DecryptCommand } = require('@aws-sdk/client-kms');
      const client = new KMSClient(this.config);
      const command = new DecryptCommand({
        CiphertextBlob: ciphertext,
        KeyId: this.config.keyId,
      });
      const res = await client.send(command);
      if (!res.Plaintext) {
        throw dbGuardError('AWS KMS returned empty plaintext');
      }
      return Buffer.from(res.Plaintext);
    } catch (err) {
      throw dbGuardError(`AWS KMS decryption failed: ${(err as Error).message}`);
    }
  }
}

export class GcpKmsProvider implements KmsProvider {
  constructor(private config: GcpKmsProviderConfig) {}

  async decrypt(ciphertext: Buffer): Promise<Buffer> {
    try {
      const { KeyManagementServiceClient } = require('@google-cloud/kms');
      const client = new KeyManagementServiceClient(this.config.clientOptions);
      const [res] = await client.decrypt({
        name: this.config.keyName,
        ciphertext: ciphertext,
      });
      if (!res.plaintext) {
        throw dbGuardError('GCP KMS returned empty plaintext');
      }
      return Buffer.from(res.plaintext);
    } catch (err) {
      throw dbGuardError(`GCP KMS decryption failed: ${(err as Error).message}`);
    }
  }
}

export class VaultKmsProvider implements KmsProvider {
  constructor(private config: { url: string; token: string; keyName: string }) {}

  async decrypt(ciphertext: Buffer): Promise<Buffer> {
    try {
      const vault = require('node-vault')({
        endpoint: this.config.url,
        token: this.config.token,
      });
      
      // Decrypt using Transit engine api
      const payload = ciphertext.toString('utf8');
      const res = await vault.customOp({
        method: 'POST',
        path: `/v1/transit/decrypt/${this.config.keyName}`,
        data: { ciphertext: payload },
      });

      if (!res.data || !res.data.plaintext) {
        throw dbGuardError('HashiCorp Vault returned empty plaintext');
      }

      return Buffer.from(res.data.plaintext, 'base64');
    } catch (err) {
      throw dbGuardError(`HashiCorp Vault decryption failed: ${(err as Error).message}`);
    }
  }
}

/**
 * Local Envelope Decryption wrapper using AES-256-Key-Wrap (AES-KW)
 */
export function unwrapDekLocal(wrappedDek: Buffer, unwrappedKek: Buffer): Buffer {
  try {
    return unwrapKey(unwrappedKek, wrappedDek);
  } catch (err) {
    throw dbGuardError(`Local AES-KW DEK unwrap failed: ${(err as Error).message}`);
  }
}

export type Pkcs11PinProvider = () => Buffer;

export interface Pkcs11KmsProviderConfig {
  libraryPath: string;
  /**
   * Returns a fresh mutable PIN buffer for one login attempt.
   * The provider zeroizes the returned buffer immediately after C_Login.
   */
  pin: Pkcs11PinProvider;
  slotId?: number;
  keyId: string; // Hex string of the AES key ID in the HSM
}

/**
 * On-Premises HSM Provider using the standard PKCS#11 protocol.
 */
export class Pkcs11KmsProvider implements KmsProvider {
  constructor(private config: Pkcs11KmsProviderConfig) {}

  async decrypt(ciphertext: Buffer): Promise<Buffer> {
    try {
      // Lazy load pkcs11js
      const pkcs11js = require('pkcs11js');
      const pkcs11 = new pkcs11js.PKCS11();
      
      pkcs11.load(this.config.libraryPath);
      try {
        pkcs11.C_Initialize();
      } catch (e: any) {
        if (!e.message?.includes('CRYPTOKI_ALREADY_INITIALIZED') && e.code !== 0x00000191 && e.code !== 401) {
          throw e;
        }
      }
      
      const slots = pkcs11.C_GetSlotList(true);
      const slotIndex = this.config.slotId !== undefined ? this.config.slotId : 0;
      if (!slots || slots.length <= slotIndex) {
        throw dbGuardError(`PKCS#11 slot index ${slotIndex} not found or slot list is empty.`);
      }
      
      const session = pkcs11.C_OpenSession(slots[slotIndex], pkcs11js.CKF_SERIAL_SESSION | pkcs11js.CKF_RW_SESSION);
      const pin = this.config.pin();
      if (!Buffer.isBuffer(pin) || pin.length === 0) {
        throw dbGuardError('PKCS#11 PIN provider must return a non-empty Buffer.');
      }
      try {
        pkcs11.C_Login(session, pkcs11js.CKU_USER, pin.toString('utf8'));
      } finally {
        pin.fill(0);
      }
      
      try {
        const keyIdBuf = Buffer.from(this.config.keyId, 'hex');
        pkcs11.C_FindObjectsInit(session, [
          { type: pkcs11js.CKA_CLASS, value: pkcs11js.CKO_SECRET_KEY },
          { type: pkcs11js.CKA_ID, value: keyIdBuf }
        ]);
        
        const objects = pkcs11.C_FindObjects(session, 1);
        pkcs11.C_FindObjectsFinal(session);
        
        if (!objects || objects.length === 0) {
          throw dbGuardError(`Secret key with ID ${this.config.keyId} not found in HSM.`);
        }
        
        const keyHandle = objects[0];
        
        if (!pkcs11js.CKM_AES_KEY_WRAP_PAD) {
          throw dbGuardError('PKCS#11 module does not expose CKM_AES_KEY_WRAP_PAD; refusing unauthenticated CBC unwrap.');
        }

        pkcs11.C_DecryptInit(session, {
          mechanism: pkcs11js.CKM_AES_KEY_WRAP_PAD
        }, keyHandle);
        
        const decrypted = pkcs11.C_Decrypt(session, ciphertext, Buffer.alloc(ciphertext.length));
        return Buffer.from(decrypted as any);
      } finally {
        pkcs11.C_Logout(session);
        pkcs11.C_CloseSession(session);
      }
    } catch (err) {
      throw dbGuardError(`PKCS#11 HSM decryption failed: ${(err as Error).message}`);
    }
  }
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

export async function resolveKeys(options: DbGuardKeysOptions): Promise<Record<string, Buffer>> {
  let rawKeys: Record<string, Buffer> = {};

  if (options.key) {
    if (Buffer.isBuffer(options.key)) {
      rawKeys = { '1': options.key };
    } else {
      rawKeys = { ...options.key };
    }
  } else if (options.kms) {
    const { provider, wrappedKey, wrappedKek } = options.kms;
    if (Buffer.isBuffer(wrappedKey)) {
      if (wrappedKek && Buffer.isBuffer(wrappedKek)) {
        const unwrappedKek = await provider.decrypt(wrappedKek);
        const dek = unwrapDekLocal(wrappedKey, unwrappedKek);
        unwrappedKek.fill(0); // RAM Security: zeroize KEK immediately
        rawKeys = { '1': dek };
      } else {
        const key = await provider.decrypt(wrappedKey);
        rawKeys = { '1': key };
      }
    } else {
      for (const [ver, wrapped] of Object.entries(wrappedKey)) {
        if (wrappedKek) {
          const wKek = Buffer.isBuffer(wrappedKek) ? wrappedKek : (wrappedKek as Record<string, Buffer>)[ver];
          if (wKek) {
            const unwrappedKek = await provider.decrypt(wKek);
            const dek = unwrapDekLocal(wrapped, unwrappedKek);
            unwrappedKek.fill(0); // RAM Security: zeroize KEK immediately
            rawKeys[ver] = dek;
          } else {
            rawKeys[ver] = await provider.decrypt(wrapped);
          }
        } else {
          rawKeys[ver] = await provider.decrypt(wrapped);
        }
      }
    }
  } else {
    throw dbGuardError("Either 'key' or 'kms' configuration must be provided.");
  }

  return rawKeys;
}
