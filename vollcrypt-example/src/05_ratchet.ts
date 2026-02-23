// Çalıştır: npx ts-node src/05_ratchet.ts
import { generateRatchetKeypair, ratchetSrk } from '@vollsign/crypto-node';
import crypto from 'crypto';

console.log('--- PCS Ratchet Test ---');

// Varsayım: Başlıca bir SRK (Session Root Key) KEM aracılığıyla kuruldu.
const initialSrk = crypto.randomBytes(32);
const chatId = crypto.randomBytes(16);

// Yeni Ratchet Anahtarları
const [aliceRatchetSk, aliceRatchetPk] = generateRatchetKeypair();
const [bobRatchetSk, bobRatchetPk] = generateRatchetKeypair();

console.log('Initial SRK:', initialSrk.toString('hex').slice(0, 16) + '...');

// Step 1: Ratchet Step 1 (Örneğin Alice tarafından)
console.log('\n> Ratchet Step 1');
const nextSrkAlice = ratchetSrk(initialSrk, aliceRatchetSk, bobRatchetPk, chatId, 1, true);
const nextSrkBob = ratchetSrk(initialSrk, bobRatchetSk, aliceRatchetPk, chatId, 1, false);

console.log('Alice\'s Next SRK:', nextSrkAlice.toString('hex').slice(0, 16) + '...');
console.log('Bob\'s Next SRK:  ', nextSrkBob.toString('hex').slice(0, 16) + '...');
console.log('Match?', nextSrkAlice.equals(nextSrkBob) ? '✅ YES' : '❌ NO');
