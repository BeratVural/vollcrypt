// Çalıştır: npx ts-node src/09_full_flow.ts
import {
    generateX25519Keypair,
    generateEd25519Keypair,
    mlKemKeygen,
    authenticatedKemEncapsulate,
    authenticatedKemDecapsulate,
    transcriptNew,
    transcriptComputeMessageHash,
    transcriptUpdate,
    sealMessage,
    unsealMessage,
    generateRatchetKeypair,
    ratchetSrk,
    keyLogCreateEntry
} from '@vollsign/crypto-node';

import crypto from 'crypto';

const GENESIS_HASH = Buffer.alloc(32, 0);

console.log('=== VOLLCRYPT TAM UÇTAN UCA (E2EE) AKIŞ SENARYOSU ===\n');

// 1. KİMLİK VE ŞİFRELEME ANAHTARLARININ ÜRETİLMESİ
console.log('1. Alice ve Bob anahtarlarını üretiyor...');
const [aliceEdSk, aliceEdPk] = generateEd25519Keypair();
const [aliceXSk, aliceXPk] = generateX25519Keypair();

const [bobEdSk, bobEdPk] = generateEd25519Keypair();
const [bobXSk, bobXPk] = generateX25519Keypair();
const [bobMlDk, bobMlEk] = mlKemKeygen(); // Bob'un Post-Quantum KEM anahtarları

console.log('   - Üretim Başarılı.');

// 2. AUTHENTICATED KEM (Alice -> Bob)
const [authCiphertext, sharedKeyAlice] = authenticatedKemEncapsulate(
    aliceXSk, bobXPk, bobMlEk, aliceEdSk
);

const sharedKeyBob = authenticatedKemDecapsulate(
    bobXSk, aliceXPk, bobMlDk, authCiphertext, aliceEdPk
);

if (!sharedKeyAlice.equals(sharedKeyBob)) throw new Error('KEM Failed!');
console.log('   - SRK başarıyla kuruldu (Alice ve Bob eşleşti).');

// 3. TRANSCRIPT HASH BAŞLANGICI
console.log('\n3. Transcript Hash (Sohbet Zinciri) başlatılıyor...');
const sessionId = crypto.randomBytes(32);
let aliceTranscript = transcriptNew(sessionId);
let bobTranscript = transcriptNew(sessionId);
console.log('   - Başlangıç Hash:', aliceTranscript.toString('hex').slice(0, 16) + '...');

// 4. ALICE MESAJ GÖNDERİYOR (SEALED SENDER)
console.log('\n4. Alice Bob\'a Sealed Sender ile mesaj mühürlüyor...');
const aliceUserId = crypto.randomBytes(16);
const plaintextMsg = Buffer.from('Merhaba Bob! Bu mesaj dışarıya karşı mühürlendi.', 'utf8');

const sealedMsg = sealMessage(bobXPk, aliceUserId, plaintextMsg);
console.log('   - Mühürlü Paket Uzunluğu:', sealedMsg.length);

// 5. TRANSCRIPT GÜNCELLEMESİ
console.log('\n5. Mesaj gönderimi sonrası Transcript Hash güncelleniyor...');
const msgId = crypto.randomBytes(16);
// Alice günceller
const msgHash = transcriptComputeMessageHash(msgId, aliceUserId, Date.now(), sealedMsg);
aliceTranscript = transcriptUpdate(aliceTranscript, msgHash);
// Bob günceller
bobTranscript = transcriptUpdate(bobTranscript, msgHash);

console.log('   - Güncel Hash:', bobTranscript.toString('hex').slice(0, 16) + '...');

// 6. BOB MESAJI AÇIYOR
console.log('\n6. Bob mühürlü paketi açıyor...');
const [openedSenderId, openedPlaintext] = unsealMessage(sealedMsg, bobXSk);
console.log('   - Çözülen İçerik:', openedPlaintext.toString('utf8'));
console.log('   - Gönderen Doğrulandı mı?', openedSenderId.equals(aliceUserId));

// 7. RATCHET ADIMI (PCS)
console.log('\n7. PCS Ratchet (Post-Compromise Security) Tetikleniyor...');
const chatId = crypto.randomBytes(16);
const [aliceRatchetSk, aliceRatchetPk] = generateRatchetKeypair();
const [bobRatchetSk, bobRatchetPk] = generateRatchetKeypair();

const nextSrkAlice = ratchetSrk(sharedKeyAlice, aliceRatchetSk, bobRatchetPk, chatId, 1, true);
const nextSrkBob = ratchetSrk(sharedKeyBob, bobRatchetSk, aliceRatchetPk, chatId, 1, false);
console.log('   - Yeni SRK Kuruldu mu?', nextSrkAlice.equals(nextSrkBob) ? '✅ YES' : '❌ NO');

// 8. KEY LOG (KEY TRANSPARENCY)
console.log('\n8. Key Transparency sistemine Bob\'un yeni anahtarı ekleniyor...');
const bobUserLogId = Buffer.from('bob_user_id');
const logEntryJson = keyLogCreateEntry(
    bobUserLogId,
    bobXPk,
    Math.floor(Date.now() / 1000),
    GENESIS_HASH,
    1, // 1 = Add
    bobEdSk
);

console.log('   - Log Başarıyla Üretildi (İmzalandı):');
console.log('    ', logEntryJson.slice(0, 100) + '...');

console.log('\n=== E2EE AKIŞI BAŞARIYLA TAMAMLANDI ===');
