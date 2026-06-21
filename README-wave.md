<div align="center">
  <h1>Vollcrypt Wave</h1>
  <p><strong>Tactical Radio COMSEC & TRANSEC Protocol for Military & Covert Communication</strong></p>
  
  <p>
    <a href="https://csrc.nist.gov/pubs/fips/203/final">
      <img src="https://img.shields.io/badge/PQC-FIPS%20203%20ML--KEM--768-8A2BE2" alt="FIPS 203">
    </a>
    <img src="https://img.shields.io/badge/TRANSEC-FHSS%20%26%20LSB%20Steganography-green.svg" alt="TRANSEC">
    <img src="https://img.shields.io/badge/Identity-Ephemeral%20Alias-orange.svg" alt="Ephemeral Alias">
  </p>
</div>

---

**Vollcrypt Wave** is a self-contained, independent military-grade cryptographic protocol designed specifically for tactical radio communications (HF, VHF, UHF bands). Operating under zero-trust, low-bandwidth, and high-noise environments, it combines robust Transmission Security (TRANSEC) and Communications Security (COMSEC) features to protect tactical nets against jamming, interception, and direction-finding metadata tracking.

Unlike `vollcrypt-messages`, **Vollcrypt Wave** is fully independent and implements its own standalone cryptographic flow to meet strict low-overhead and high-resilience requirements of tactical digital and software-defined radios (SDR).

---

## Key Features

1.  **Independent Cryptographic Core**: Self-contained cryptographic implementation utilizing modern primitives (`x25519-dalek`, `ml-kem`, `aes-gcm`, `hkdf`, `sha2`) without depending on external Vollcrypt modules.
2.  **Quantum-Resistant Hybrid Key Exchange**: Combines **ML-KEM-768** (FIPS 203) and **X25519** ECDH via HKDF-SHA256 to ensure that tactical networks resist both classical and future quantum-based decryption attacks.
3.  **Cryptographic Frequency Hopping (FHSS)**: Generates deterministic pseudo-random frequency hopping channels based on a shared **Word of Day (WOD)** and high-precision **Time of Day (TOD)**, mimicking white noise patterns.
4.  **Dynamic Ephemeral Aliasing**: Completely hides physical subscriber and radio IDs over-the-air. Radios dynamically derive call sign pseudonyms (aliases) using time-rotating HMAC keys, rendering traffic analysis by adversaries impossible.
5.  **Audio Steganography (LSB & Noise Masking)**: Permits embedding of low-bitrate data (e.g., GPS coordinates, tactical statuses, or text messages) directly inside digitized voice audio frames without degrading voice quality or raising suspicion.

---

## Architectural Workflow

```mermaid
sequenceDiagram
    participant Tx as Transmitter (Radio A)
    participant Rx as Receiver (Radio B)
    
    Note over Tx, Rx: Phase 1: Authentication & Hybrid Key Exchange (X25519 + ML-KEM-768)
    Tx->>Rx: Wave Packet: [Ephemeral PK (32B) + ML-KEM Ciphertext (1088B)]
    Note over Tx, Rx: Establish Session Key via HKDF-SHA256(ECDH + ML-KEM Secret)
    
    Note over Tx, Rx: Phase 2: Active Transmission
    Note over Tx: Calculate Ephemeral Callsign Alias: HMAC-SHA256(SessionKey, EpochTime)
    Note over Tx: Generate FHSS Hop Sequence: AES-CTR-DRBG(WOD, TOD)
    Note over Tx: Embed GPS in Audio Frame using LSB Steganography
    
    Tx->>Rx: Voice/Data Waveframe (Transmitted on Hopping Frequency)
    Note over Rx: Synchronize FHSS Hop & Decrypt Audio
    Note over Rx: Extract Steganographic GPS data & Validate Alias
```

---

## Directory Structure

*   `src/lib.rs`: Exposes the main modules and entry points for the protocol.
*   `src/fhss.rs`: Implements the cryptographic frequency hopping sequence generator based on TOD and WOD parameters.
*   `src/alias.rs`: Handles the generation and validation of ephemeral cryptographic aliases.
*   `src/stego.rs`: Provides audio steganography capabilities, embedding digital bits into voice frames.
*   `src/wave_packet.rs`: Defines the low-overhead, highly compact frame structure required for radio channels.

---

## Quick Start (Rust API)

### 1. Generating an Ephemeral Alias
```rust
use vollcrypt_wave::alias::EphemeralAlias;

let session_key = [0u8; 32];
let current_epoch_seconds = 1718974500u64;

// Generate transient callsig alias
let alias = EphemeralAlias::generate(&session_key, current_epoch_seconds);
println!("Current dynamic alias: {:?}", alias.to_u32());
```

### 2. Computing next Frequency Hop
```rust
use vollcrypt_wave::fhss::FhssGenerator;

let word_of_day = [0u8; 32];
let time_of_day_ms = 1718974500123u64;
let frequency_channels = 80; // Total 80 hopping channels

let mut fhss = FhssGenerator::new(word_of_day, frequency_channels);
let target_channel = fhss.next_hop(time_of_day_ms);
println!("Tune radio to channel: {}", target_channel);
```

### 3. Hiding Data inside Digitized Audio
```rust
use vollcrypt_wave::stego::AudioSteganographer;

let mut audio_samples: Vec<i16> = vec![0; 1000]; // Digitized voice stream
let secret_gps_data = b"39.9334-32.8597"; // Coordinates to hide

// Embed data
let bits_written = AudioSteganographer::embed(&mut audio_samples, secret_gps_data).unwrap();

// Extract data on receiver
let extracted_data = AudioSteganographer::extract(&audio_samples).unwrap();
assert_eq!(extracted_data, secret_gps_data);
```

---

## Security Specifications

| Layer | Primitive | Purpose |
| :--- | :--- | :--- |
| **COMSEC (KEM)** | ML-KEM-768 + X25519 | Quantum-resistant asymmetric key exchange |
| **COMSEC (Sym)** | AES-256-GCM | Encrypted payload integrity & confidentiality |
| **TRANSEC (FHSS)** | AES-128-CTR | Pseudo-random hop sequence generator |
| **TRANSEC (Stego)** | LSB Audio Encoder | Covert channel for GPS/metadata injection |
| **TRANSEC (Alias)** | HMAC-SHA256 | Prevents radio tracking & traffic correlation |

---

## Independent Publishing

The `vollcrypt-wave` crate is designed to be built, tested, and published completely independently of the rest of the workspace modules. 

To publish the crate to **crates.io** manually:
1. Navigate to the `vollcrypt-wave` directory:
   ```bash
   cd vollcrypt-wave
   ```
2. Verify formatting and compile the code:
   ```bash
   cargo fmt --check
   cargo clippy -- -D warnings
   ```
3. Run all unit tests to ensure stability:
   ```bash
   cargo test
   ```
4. Verify the package structure and generate the package file:
   ```bash
   cargo package
   ```
5. Publish the package:
   ```bash
   cargo publish
   ```


