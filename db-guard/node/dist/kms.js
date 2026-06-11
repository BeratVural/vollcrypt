"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Pkcs11KmsProvider = exports.VaultKmsProvider = exports.GcpKmsProvider = exports.AwsKmsProvider = void 0;
exports.unwrapDekLocal = unwrapDekLocal;
const security_1 = require("./security");
class AwsKmsProvider {
    config;
    constructor(config) {
        this.config = config;
    }
    async decrypt(ciphertext) {
        try {
            const { KMSClient, DecryptCommand } = require('@aws-sdk/client-kms');
            const client = new KMSClient(this.config);
            const command = new DecryptCommand({
                CiphertextBlob: ciphertext,
                KeyId: this.config.keyId,
            });
            const res = await client.send(command);
            if (!res.Plaintext) {
                throw new Error('AWS KMS returned empty plaintext');
            }
            return Buffer.from(res.Plaintext);
        }
        catch (err) {
            throw new Error(`AWS KMS decryption failed: ${err.message}`);
        }
    }
}
exports.AwsKmsProvider = AwsKmsProvider;
class GcpKmsProvider {
    config;
    constructor(config) {
        this.config = config;
    }
    async decrypt(ciphertext) {
        try {
            const { KeyManagementServiceClient } = require('@google-cloud/kms');
            const client = new KeyManagementServiceClient(this.config.clientOptions);
            const [res] = await client.decrypt({
                name: this.config.keyName,
                ciphertext: ciphertext,
            });
            if (!res.plaintext) {
                throw new Error('GCP KMS returned empty plaintext');
            }
            return Buffer.from(res.plaintext);
        }
        catch (err) {
            throw new Error(`GCP KMS decryption failed: ${err.message}`);
        }
    }
}
exports.GcpKmsProvider = GcpKmsProvider;
class VaultKmsProvider {
    config;
    constructor(config) {
        this.config = config;
    }
    async decrypt(ciphertext) {
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
                throw new Error('HashiCorp Vault returned empty plaintext');
            }
            return Buffer.from(res.data.plaintext, 'base64');
        }
        catch (err) {
            throw new Error(`HashiCorp Vault decryption failed: ${err.message}`);
        }
    }
}
exports.VaultKmsProvider = VaultKmsProvider;
/**
 * Local Envelope Decryption wrapper using AES-256-Key-Wrap (AES-KW)
 */
function unwrapDekLocal(wrappedDek, unwrappedKek) {
    try {
        return (0, security_1.unwrapKey)(unwrappedKek, wrappedDek);
    }
    catch (err) {
        throw new Error(`Local AES-KW DEK unwrap failed: ${err.message}`);
    }
}
/**
 * On-Premises HSM Provider using the standard PKCS#11 protocol
 */
class Pkcs11KmsProvider {
    config;
    constructor(config) {
        this.config = config;
    }
    async decrypt(ciphertext) {
        try {
            // Lazy load pkcs11js
            const pkcs11js = require('pkcs11js');
            const pkcs11 = new pkcs11js.PKCS11();
            pkcs11.load(this.config.libraryPath);
            pkcs11.C_Initialize();
            const slots = pkcs11.C_GetSlotList(true);
            const slotIndex = this.config.slotId !== undefined ? this.config.slotId : 0;
            if (!slots || slots.length <= slotIndex) {
                throw new Error(`PKCS#11 slot index ${slotIndex} not found or slot list is empty.`);
            }
            const session = pkcs11.C_OpenSession(slots[slotIndex], pkcs11js.CKF_SERIAL_SESSION | pkcs11js.CKF_RW_SESSION);
            pkcs11.C_Login(session, pkcs11js.CKU_USER, this.config.pin);
            try {
                const keyIdBuf = Buffer.from(this.config.keyId, 'hex');
                pkcs11.C_FindObjectsInit(session, [
                    { type: pkcs11js.CKA_CLASS, value: pkcs11js.CKO_SECRET_KEY },
                    { type: pkcs11js.CKA_ID, value: keyIdBuf }
                ]);
                const objects = pkcs11.C_FindObjects(session, 1);
                pkcs11.C_FindObjectsFinal(session);
                if (!objects || objects.length === 0) {
                    throw new Error(`Secret key with ID ${this.config.keyId} not found in HSM.`);
                }
                const keyHandle = objects[0];
                // Extract 16-byte IV for CKM_AES_CBC_PAD, otherwise fallback to zeros
                let iv = Buffer.alloc(16, 0);
                let actualCiphertext = ciphertext;
                if (ciphertext.length > 16) {
                    iv = ciphertext.subarray(0, 16);
                    actualCiphertext = ciphertext.subarray(16);
                }
                pkcs11.C_DecryptInit(session, {
                    mechanism: pkcs11js.CKM_AES_CBC_PAD,
                    parameter: iv
                }, keyHandle);
                const decrypted = pkcs11.C_Decrypt(session, actualCiphertext, Buffer.alloc(actualCiphertext.length + 16));
                return Buffer.from(decrypted);
            }
            finally {
                pkcs11.C_Logout(session);
                pkcs11.C_CloseSession(session);
                pkcs11.C_Finalize();
            }
        }
        catch (err) {
            throw new Error(`PKCS#11 HSM decryption failed: ${err.message}`);
        }
    }
}
exports.Pkcs11KmsProvider = Pkcs11KmsProvider;
