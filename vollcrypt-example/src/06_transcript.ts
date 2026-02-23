// Çalıştır: npx ts-node src/06_transcript.ts
import { 
    transcriptNew, 
    transcriptUpdate, 
    transcriptComputeMessageHash, 
    transcriptVerifySync 
} from '@vollsign/crypto-node';
import crypto from 'crypto';

console.log('--- Transcript Hashing (Konuşma Zinciri) ---');

// Yeni Konuşma
const sessionId = crypto.randomBytes(32);
let aliceState = transcriptNew(sessionId);
let bobState = transcriptNew(sessionId);

console.log('Initial Transcript Hash:', aliceState.toString('hex').slice(0, 16) + '...');

// 1. Mesaj Gönderimi (Alice -> Bob)
const messageId1 = crypto.randomBytes(16);
const aliceId = crypto.randomBytes(16);
const ciphertext1 = crypto.randomBytes(64);

const msgHash1 = transcriptComputeMessageHash(messageId1, aliceId, Date.now(), ciphertext1);

// Alice Kendi Hash Zincirini Günceller
aliceState = transcriptUpdate(aliceState, msgHash1);

// Bob Gelen Hash ile Kendini Günceller
bobState = transcriptUpdate(bobState, msgHash1);

console.log('Alice State after Msg 1:', aliceState.toString('hex').slice(0, 16) + '...');
console.log('Bob State after Msg 1:  ', bobState.toString('hex').slice(0, 16) + '...');

console.log('\nVerify Sync:', transcriptVerifySync(aliceState, bobState) ? '✅ SUCCESS' : '❌ FAILED');
