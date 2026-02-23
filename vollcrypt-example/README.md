# Vollcrypt Example Project

Bu proje, `@vollsign/crypto-node` tabanlı Vollcrypt kriptografi kütüphanesinin özelliklerini ve tam döngü (E2EE) akışını test etmek ve örneklemek için oluşturulmuştur.

## Kurulum ve Çalıştırma

Önce klasördeki kütüphaneleri (Node binding dahil) yükleyin:

```bash
npm install
```

Tüm sistemi ve veri akışını görmek için `09_full_flow.ts` dosyasını çalıştırın:

```bash
npm start
```

_(Arka planda `ts-node src/09_full_flow.ts` komutunu çalıştırır)_

## Örnekler

Aşağıdaki komutlarla kütüphanenin sunduğu modülleri tekil olarak inceleyebilirsiniz:

1. Anahtar üretimi (Ed25519 & X25519):  
   `npx ts-node src/01_keypair.ts`

2. AES-256-GCM Şifreleme:  
   `npx ts-node src/02_encrypt.ts`

3. Hybrid KEM (Post-Quantum Güvenli Key Exchange):  
   `npx ts-node src/03_kem.ts`

4. Authenticated KEM:  
   `npx ts-node src/04_auth_kem.ts`

5. PCS Ratchet (İleri Düzey Güvenlik):  
   `npx ts-node src/05_ratchet.ts`

6. Transcript Hashing (Konuşma Bütünlüğü):  
   `npx ts-node src/06_transcript.ts`

7. Sealed Sender (Gönderici Gizliliği):  
   `npx ts-node src/07_sealed.ts`

8. Key Transparency Log:  
   `npx ts-node src/08_keylog.ts`

9. Uçtan Uca Tam Kriptografik Senaryo:  
   `npx ts-node src/09_full_flow.ts`
