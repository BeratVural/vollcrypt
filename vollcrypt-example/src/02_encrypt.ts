// Çalıştır: npx ts-node src/02_encrypt.ts
import { encryptAesGcm, decryptAesGcm } from '@vollsign/crypto-node';
import crypto from 'crypto';

const key = crypto.randomBytes(32);
const plaintext = Buffer.from('Gizli Mesaj: Vollcrypt AES-256-GCM Testi');

// Opsiyonel: AAD (Additional Authenticated Data)
const aad = Buffer.from('Metadata, örneğin mesaj ID\'si');

console.log('--- Şifreleme Öncesi ---');
console.log('Plaintext:', plaintext.toString());

const ciphertext = encryptAesGcm(key, plaintext, aad);
console.log('\n--- Şifrelenmiş Hal ---');
console.log('Ciphertext (Hex):', ciphertext.toString('hex'));

const decrypted = decryptAesGcm(key, ciphertext, aad);
console.log('\n--- Çözülmüş Hal ---');
console.log('Decrypted:', decrypted.toString());
