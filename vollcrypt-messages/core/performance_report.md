# Vollcrypt Core Performance and Resource Monitoring Report

This report presents the execution results of the Vollcrypt Messages cryptographic core benchmark suite, along with real-time hardware resource consumption tracked during the run.

## System Specifications
*   **Operating System (OS):** Microsoft Windows 11 Home
*   **Processor (CPU):** AMD Ryzen 5 7500F 6-Core Processor             
*   **System Memory (RAM):** 15.62 GB
*   **Graphics Controller (GPU):** NVIDIA GeForce GTX 1660 SUPER
*   **Disk Volumes:**
    *   C: () 465.1 GB total, 40.2 GB free
    *   D: (Yeni Birim) 931.5 GB total, 733.8 GB free

---

## Cryptographic Benchmarks

```text
Vollcrypt perf
CPU aes=true pclmulqdq=true
AES backend=aes-gcm
AES-GCM-RAW size=65536 bytes enc=299.62762279039606 MB/s dec=295.73962231920905 MB/s
AES-GCM-RAW size=1048576 bytes enc=292.45908150154634 MB/s dec=302.64917142601405 MB/s
AES-GCM-RAW size=16777216 bytes enc=292.3048465513737 MB/s dec=300.2530194663416 MB/s
AES-GCM size=1024 bytes enc=267.01053410852586 MB/s dec=278.31808595531237 MB/s
AES-GCM size=65536 bytes enc=240.62336352037258 MB/s dec=264.8456585440269 MB/s
AES-GCM size=1048576 bytes enc=254.26481682447218 MB/s dec=275.714134071512 MB/s
AES-GCM size=16777216 bytes enc=271.09224072410075 MB/s dec=293.07367982213356 MB/s
AES-GCM-CHUNKED size=16777216 bytes chunk=1048576 bytes enc=237.66230855259914 MB/s dec=259.2862562402909 MB/s
AES-GCM-CHUNKED size=67108864 bytes chunk=1048576 bytes enc=238.454721540373 MB/s dec=264.0987465213243 MB/s
HKDF ops/s=1222493.8875305625
PBKDF2(600k) ops/s=11.7199453428629
ML-KEM encaps ops/s=8955.197148665227
ML-KEM decaps ops/s=7104.1395821345095
ML-KEM match=200/200
Sealed Sender seal ops/s=15759.65
Sealed Sender unseal ops/s=21360.04
PCS Ratchet keygen ops/s=64150.27
PCS Ratchet step computation ops/s=21674.58
Key Verification Code generation ops/s=448772.61
Key Transparency Log verify chain (100 entries) ops/s=298.25

```


### Compilation/Error Output
```text
   Compiling vollcrypt-core v0.1.0 (C:\Users\iTopya\Desktop\Project\vollcrypt\vollcrypt-messages\core)
    Finished `release` profile [optimized] target(s) in 2.59s
     Running `target\release\perf.exe`

```


---

## Resource Utilization Report
*   **Total Test Duration:** 16.9 seconds

| Resource / Metric | Minimum (Min) | Maximum (Max) | Average (Avg) |
| :--- | :---: | :---: | :---: |
| **System CPU Utilization** | 7% | 18% | 13.2% |
| **Memory Utilization (RAM)** | 36.2% | 37.2% | 36.4% |
| **Graphics Card Utilization (GPU)** | 8% | 9% | 8.2% |
| **Disk Read Speed** | 0 MB/s | 0.06 MB/s | 0.01 MB/s |
| **Disk Write Speed** | 0 MB/s | 14.19 MB/s | 1.7 MB/s |

*Note: Since cryptographic operations are entirely CPU-bound, GPU utilization is near zero as expected. Disk I/O remains minimal since encryption/decryption are processed entirely in memory, with disk operations limited to writing standard output logs.*