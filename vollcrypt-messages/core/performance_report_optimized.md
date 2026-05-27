# Vollcrypt Core Performance and Resource Monitoring Report

This report presents the execution results of the Vollcrypt Messages cryptographic core benchmark suite, along with real-time hardware resource consumption tracked during the run.

## System Specifications
*   **Operating System (OS):** Microsoft Windows 11 Home
*   **Processor (CPU):** AMD Ryzen 5 7500F 6-Core Processor             
*   **System Memory (RAM):** 15.62 GB
*   **Graphics Controller (GPU):** NVIDIA GeForce GTX 1660 SUPER
*   **Disk Volumes:**
    *   C: () 465.1 GB total, 40.1 GB free
    *   D: (Yeni Birim) 931.5 GB total, 733.8 GB free

---

## Cryptographic Benchmarks

```text
Vollcrypt perf
CPU aes=true pclmulqdq=true
AES backend=ring
AES-GCM-RAW size=65536 bytes enc=9238.728750923872 MB/s dec=10219.264539969588 MB/s
AES-GCM-RAW size=1048576 bytes enc=9324.031058347457 MB/s dec=10175.087823726779 MB/s
AES-GCM-RAW size=16777216 bytes enc=6814.455163014544 MB/s dec=7829.51236818282 MB/s
AES-GCM size=1024 bytes enc=4629.743335760844 MB/s dec=6033.750386160024 MB/s
AES-GCM size=65536 bytes enc=8170.755031801291 MB/s dec=6152.7859814924195 MB/s
AES-GCM size=1048576 bytes enc=2940.2821210066063 MB/s dec=10270.894851713956 MB/s
AES-GCM size=16777216 bytes enc=4413.800469760237 MB/s dec=7205.843939434882 MB/s
AES-GCM-CHUNKED size=16777216 bytes chunk=1048576 bytes enc=5242.404716396861 MB/s dec=5857.673185768783 MB/s
AES-GCM-CHUNKED size=67108864 bytes chunk=1048576 bytes enc=4667.026483029545 MB/s dec=4630.148779702586 MB/s
HKDF ops/s=851788.7563884157
PBKDF2(600k) ops/s=11.656103090119185
ML-KEM encaps ops/s=8357.290900581667
ML-KEM decaps ops/s=6582.303477101812
ML-KEM match=200/200
Sealed Sender seal ops/s=16660.06
Sealed Sender unseal ops/s=22491.93
PCS Ratchet keygen ops/s=64686.40
PCS Ratchet step computation ops/s=21814.25
Key Verification Code generation ops/s=473126.42
Key Transparency Log verify chain (100 entries) ops/s=304.31
Ed25519 Sign (1KB) ops/s=28494.74
Ed25519 Verify (1KB) ops/s=30631.25
Ed25519 Sign (1MB) ops/s=414.84
Ed25519 Verify (1MB) ops/s=829.89
BIP-39 Mnemonic to Seed ops/s=1098.39
Multi-threaded scaling benchmark using 12 threads...
Multi-threaded Handshake Scaling (12 threads) aggregate ops/s=88248.92
Replay Store Lookup (Hit) avg_latency=91.64 ns
Replay Store Lookup (Miss) avg_latency=36.40 ns
Replay Store Insertion avg_latency=109.78 ns

```


### Compilation/Error Output
```text
   Compiling typenum v1.19.0
   Compiling cfg-if v1.0.4
   Compiling version_check v0.9.5
   Compiling proc-macro2 v1.0.106
   Compiling unicode-ident v1.0.24
   Compiling quote v1.0.44
   Compiling subtle v2.6.1
   Compiling cpufeatures v0.2.17
   Compiling semver v1.0.27
   Compiling zerocopy v0.8.39
   Compiling serde_core v1.0.228
   Compiling shlex v1.3.0
   Compiling getrandom v0.2.17
   Compiling find-msvc-tools v0.1.9
   Compiling serde v1.0.228
   Compiling arrayvec v0.7.6
   Compiling tinyvec_macros v0.1.1
   Compiling rand_core v0.6.4
   Compiling rustc_version v0.4.1
   Compiling generic-array v0.14.7
   Compiling opaque-debug v0.3.1
   Compiling zmij v1.0.21
   Compiling hex-conservative v0.2.2
   Compiling cc v1.2.56
   Compiling curve25519-dalek v4.1.3
   Compiling tinyvec v1.10.0
   Compiling signature v2.2.0
   Compiling keccak v0.1.6
   Compiling serde_json v1.0.149
   Compiling bitcoin_hashes v0.14.1
   Compiling ed25519 v2.2.3
   Compiling itoa v1.0.17
   Compiling untrusted v0.9.0
   Compiling memchr v2.8.0
   Compiling log v0.4.29
   Compiling unicode-normalization v0.1.25
   Compiling syn v2.0.117
   Compiling hybrid-array v0.2.3
   Compiling ring v0.17.14
   Compiling crypto-common v0.1.7
   Compiling block-buffer v0.10.4
   Compiling inout v0.1.4
   Compiling universal-hash v0.5.1
   Compiling aead v0.5.2
   Compiling digest v0.10.7
   Compiling cipher v0.4.4
   Compiling polyval v0.6.2
   Compiling ghash v0.5.1
   Compiling aes v0.8.4
   Compiling ctr v0.9.2
   Compiling hmac v0.12.1
   Compiling sha2 v0.10.9
   Compiling sha3 v0.10.8
   Compiling pbkdf2 v0.12.2
   Compiling hkdf v0.12.4
   Compiling aes-kw v0.2.1
   Compiling aes-gcm v0.10.3
   Compiling ppv-lite86 v0.2.21
   Compiling rand_chacha v0.3.1
   Compiling rand v0.8.5
   Compiling zeroize_derive v1.4.3
   Compiling curve25519-dalek-derive v0.1.1
   Compiling serde_derive v1.0.228
   Compiling zeroize v1.8.2
   Compiling kem v0.3.0-pre.0
   Compiling ml-kem v0.2.3
   Compiling x25519-dalek v2.0.1
   Compiling ed25519-dalek v2.2.0
   Compiling bip39 v2.2.2
   Compiling vollcrypt-core v0.1.0 (C:\Users\iTopya\Desktop\Project\vollcrypt\vollcrypt-messages\core)
    Finished `release` profile [optimized] target(s) in 14.30s
     Running `target\release\perf.exe`

```


---

## Resource Utilization Report
*   **Total Test Duration:** 20.67 seconds

| Resource / Metric | Minimum (Min) | Maximum (Max) | Average (Avg) |
| :--- | :---: | :---: | :---: |
| **System CPU Utilization** | 9% | 100% | 36.6% |
| **Memory Utilization (RAM)** | 36.4% | 40.3% | 37.9% |
| **Graphics Card Utilization (GPU)** | 4% | 6% | 5.1% |
| **Disk Read Speed** | 0 MB/s | 10.3 MB/s | 1.29 MB/s |
| **Disk Write Speed** | 0 MB/s | 49.29 MB/s | 6.94 MB/s |

*Note: Since cryptographic operations are entirely CPU-bound, GPU utilization is near zero as expected. Disk I/O remains minimal since encryption/decryption are processed entirely in memory, with disk operations limited to writing standard output logs.*