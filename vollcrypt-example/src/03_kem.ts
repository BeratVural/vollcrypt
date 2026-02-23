// Çalıştır: npx ts-node src/03_kem.ts
import { 
    generateX25519Keypair, 
    mlKemKeygen, 
    hybridKemEncapsulate, 
    hybridKemDecapsulate 
} from '@vollsign/crypto-node';

console.log('--- Hybrid KEM (X25519 + ML-KEM-768) ---');

// 1. Alıcı (Bob) anahtarlarını üretip Alice'e gönderir
const [bobXSecret, bobXPublic] = generateX25519Keypair();
const [bobMlDk, bobMlEk] = mlKemKeygen();
console.log('1. Bob anahtarları üretti (X25519 & ML-KEM).');

// 2. Gönderici (Alice) eigene X25519 üretir ve şifreler (Encapsulate)
const [aliceXSecret, aliceXPublic] = generateX25519Keypair();
const result = hybridKemEncapsulate(aliceXSecret, bobXPublic, bobMlEk);

console.log('2. Alice (Encapsulate) işlemi tamamlandı.');
console.log('> Alice Shared Key:', result.sharedKey.toString('hex').slice(0, 16) + '...');
console.log('> Ciphertext Length:', result.mlKemCiphertext.length, 'bytes');

// 3. Alıcı (Bob) gelen ciphertext kullanarak çözümler (Decapsulate)
const decapsulatedKey = hybridKemDecapsulate(bobXSecret, aliceXPublic, bobMlDk, result.mlKemCiphertext);

console.log('\n3. Bob (Decapsulate) işlemi tamamlandı.');
console.log('> Bob Shared Key:  ', decapsulatedKey.toString('hex').slice(0, 16) + '...');

console.log('\nKeys Match:', result.sharedKey.equals(decapsulatedKey) ? '✅ YES' : '❌ NO');
