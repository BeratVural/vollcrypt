// Çalıştır: npx ts-node src/01_keypair.ts
import { generateEd25519Keypair, generateX25519Keypair } from '@vollsign/crypto-node';

console.log('--- Ed25519 Keypair (İmza) ---');
const [edSecret, edPublic] = generateEd25519Keypair();
console.log('Secret:', edSecret.toString('hex').slice(0, 16) + '...');
console.log('Public:', edPublic.toString('hex'));

console.log('\n--- X25519 Keypair (Şifreleme) ---');
const [xSecret, xPublic] = generateX25519Keypair();
console.log('Secret:', xSecret.toString('hex').slice(0, 16) + '...');
console.log('Public:', xPublic.toString('hex'));
