import { test, describe } from 'node:test';
import assert from 'node:assert';
import { wrapKey } from '../src/security';
import { AwsKmsProvider, GcpKmsProvider, VaultKmsProvider, unwrapDekLocal, Pkcs11KmsProvider } from '../src/kms';

const Module = require('module');
const originalLoad = Module._load;

describe('KMS Providers & Envelope Decryption', () => {
  const kek = Buffer.alloc(32, 11);
  const dek = Buffer.alloc(32, 22);

  test('local DEK unwrapping with AES-KW', () => {
    const wrappedDek = wrapKey(kek, dek);
    const unwrapped = unwrapDekLocal(wrappedDek, kek);
    assert.deepStrictEqual(unwrapped, dek);
  });

  test('AwsKmsProvider calls AWS SDK and returns decrypted bytes', async () => {
    Module._load = function (request: string, parent: any, isMain: boolean) {
      if (request === '@aws-sdk/client-kms') {
        return {
          KMSClient: class {
            send(command: any) {
              return Promise.resolve({
                Plaintext: Buffer.from('mock-aws-decrypted')
              });
            }
          },
          DecryptCommand: class {
            constructor(public input: any) {}
          }
        };
      }
      return originalLoad.apply(this, [request, parent, isMain]);
    };

    const provider = new AwsKmsProvider({ region: 'us-east-1' });
    const decrypted = await provider.decrypt(Buffer.from('ciphertext'));
    assert.strictEqual(decrypted.toString('utf8'), 'mock-aws-decrypted');

    Module._load = originalLoad;
  });

  test('GcpKmsProvider calls GCP SDK and returns decrypted bytes', async () => {
    Module._load = function (request: string, parent: any, isMain: boolean) {
      if (request === '@google-cloud/kms') {
        return {
          KeyManagementServiceClient: class {
            decrypt(payload: any) {
              return Promise.resolve([{
                plaintext: Buffer.from('mock-gcp-decrypted')
              }]);
            }
          }
        };
      }
      return originalLoad.apply(this, [request, parent, isMain]);
    };

    const provider = new GcpKmsProvider({ keyName: 'my-gcp-key' });
    const decrypted = await provider.decrypt(Buffer.from('ciphertext'));
    assert.strictEqual(decrypted.toString('utf8'), 'mock-gcp-decrypted');

    Module._load = originalLoad;
  });

  test('VaultKmsProvider calls node-vault API and returns decrypted bytes', async () => {
    Module._load = function (request: string, parent: any, isMain: boolean) {
      if (request === 'node-vault') {
        return function() {
          return {
            customOp(args: any) {
              assert.strictEqual(args.method, 'POST');
              assert.strictEqual(args.path, '/v1/transit/decrypt/my-vault-key');
              return Promise.resolve({
                data: {
                  plaintext: Buffer.from('mock-vault-decrypted').toString('base64')
                }
              });
            }
          };
        };
      }
      return originalLoad.apply(this, [request, parent, isMain]);
    };

    const provider = new VaultKmsProvider({
      url: 'http://localhost:8200',
      token: 'root-token',
      keyName: 'my-vault-key'
    });
    const decrypted = await provider.decrypt(Buffer.from('ciphertext'));
    assert.strictEqual(decrypted.toString('utf8'), 'mock-vault-decrypted');

    Module._load = originalLoad;
  });

  test('Pkcs11KmsProvider loads PKCS#11 library, logs in, finds key, and decrypts data', async () => {
    let initialized = false;
    let loggedIn = false;
    let sessionOpened = false;
    let decryptInitialized = false;

    Module._load = function (request: string, parent: any, isMain: boolean) {
      if (request === 'pkcs11js') {
        return {
          PKCS11: class {
            load(path: string) {
              assert.strictEqual(path, 'mock-hsm-lib.so');
            }
            C_Initialize() {
              initialized = true;
            }
            C_GetSlotList(tokenPresent: boolean) {
              assert.strictEqual(tokenPresent, true);
              return [10];
            }
            C_OpenSession(slot: number, flags: number) {
              assert.strictEqual(slot, 10);
              sessionOpened = true;
              return 99;
            }
            C_Login(session: number, userType: number, pin: string) {
              assert.strictEqual(session, 99);
              assert.strictEqual(pin, '123456');
              loggedIn = true;
            }
            C_FindObjectsInit(session: number, template: any[]) {
              assert.strictEqual(session, 99);
              assert.strictEqual(template.length, 2);
            }
            C_FindObjects(session: number, max: number) {
              return [101];
            }
            C_FindObjectsFinal(session: number) {}
            C_DecryptInit(session: number, mechanism: any, key: number) {
              assert.strictEqual(session, 99);
              assert.strictEqual(key, 101);
              assert.ok(mechanism.parameter);
              decryptInitialized = true;
            }
            C_Decrypt(session: number, ciphertext: Buffer, output: Buffer) {
              return Buffer.from('mock-hsm-decrypted');
            }
            C_Logout(session: number) {}
            C_CloseSession(session: number) {}
            C_Finalize() {}
          },
          CKF_SERIAL_SESSION: 1,
          CKF_RW_SESSION: 2,
          CKU_USER: 1,
          CKO_SECRET_KEY: 2,
          CKA_CLASS: 10,
          CKA_ID: 11,
          CKM_AES_CBC_PAD: 12
        };
      }
      return originalLoad.apply(this, [request, parent, isMain]);
    };

    const provider = new Pkcs11KmsProvider({
      libraryPath: 'mock-hsm-lib.so',
      pin: '123456',
      slotId: 0,
      keyId: '000102'
    });

    const mockCiphertext = Buffer.concat([Buffer.alloc(16, 9), Buffer.from('ciphertext-data')]);
    const decrypted = await provider.decrypt(mockCiphertext);

    assert.ok(initialized);
    assert.ok(sessionOpened);
    assert.ok(loggedIn);
    assert.ok(decryptInitialized);
    assert.strictEqual(decrypted.toString('utf8'), 'mock-hsm-decrypted');

    Module._load = originalLoad;
  });
});
