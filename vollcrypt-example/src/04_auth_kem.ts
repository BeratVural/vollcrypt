// Çalıştır: npx ts-node src/04_auth_kem.ts
import { 
    generateX25519Keypair, 
    generateEd25519Keypair,
    mlKemKeygen,
    authenticatedKemEncapsulate,
    authenticatedKemDecapsulate
} from '@vollsign/crypto-node';

console.log('--- Authenticated KEM ---');

// Bob (Alıcı)
const [bobXSecret, bobXPublic] = generateX25519Keypair();
const [bobMlDk, bobMlEk] = mlKemKeygen();

// Alice (Gönderici)
const [aliceXSecret, aliceXPublic] = generateX25519Keypair();
const [aliceEdSecret, aliceEdPublic] = generateEd25519Keypair(); // Identity Key

console.log('1. Alice Encapsulate yapıyor ve kimliğini (Ed25519) dahil ediyor...');

const [authCiphertext, sharedKey] = authenticatedKemEncapsulate(
    aliceXSecret,
    bobXPublic,
    bobMlEk,
    aliceEdSecret
);

console.log('> Shared Key (Alice):', sharedKey.toString('hex').slice(0, 16) + '...');
console.log('> Auth Ciphertext Len:', authCiphertext.length, 'bytes');

console.log('\n2. Bob Decapsulate yapıyor ve verify (Alice\'in kimliği) ediyor...');

const bobSharedKey = authenticatedKemDecapsulate(
    bobXSecret,
    aliceXPublic,
    bobMlDk,
    authCiphertext,
    aliceEdPublic
);

console.log('> Shared Key (Bob):  ', bobSharedKey.toString('hex').slice(0, 16) + '...');
console.log('\nKeys Match:', sharedKey.equals(bobSharedKey) ? '✅ YES' : '❌ NO');
