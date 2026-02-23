// Çalıştır: npx ts-node src/07_sealed.ts
import { generateX25519Keypair, sealMessage, unsealMessage } from '@vollsign/crypto-node';
import crypto from 'crypto';

console.log('--- Sealed Sender (Gönderici Gizliliği) ---');

// Alıcı (Bob)
const [bobXSecret, bobXPublic] = generateX25519Keypair();

// Gönderici (Alice)
const aliceId = crypto.randomBytes(16);
const contentBuffer = Buffer.from('Sealed sender payload', 'utf8');

console.log('1. Alice Bob\'ın PublicKey\'i ile mesajı mühürlüyor...');
const sealedPacket = sealMessage(bobXPublic, aliceId, contentBuffer);

console.log('> Mühürlü Paket Uzunluğu:', sealedPacket.length, 'bytes');

console.log('\n2. Bob kendi PrivateKey\'i ile mührü açıyor...');
const [decryptedSenderId, decryptedContent] = unsealMessage(sealedPacket, bobXSecret);

console.log('> Sender ID:', decryptedSenderId.toString('hex'));
console.log('> İçerik:   ', decryptedContent.toString('utf8'));

console.log('\n3. Kimlik Doğrulama:');
console.log(decryptedSenderId.equals(aliceId) ? '✅ Sender Validated' : '❌ Sender Invalid');
