---
layout: default
title: Vollcrypt Wave
---

<div align="center">
  <h1>Vollcrypt Wave</h1>
  <p><strong>Tactical Radio COMSEC & TRANSEC Protocol for Military & Covert Communication</strong></p>
  
  <p>
    <a href="https://csrc.nist.gov/pubs/fips/203/final">
      <img src="https://img.shields.io/badge/PQC-FIPS%20203%20ML--KEM--768-8A2BE2" alt="FIPS 203">
    </a>
    <img src="https://img.shields.io/badge/TRANSEC-Chaotic%20FHSS%20%26%20DSSS-green.svg" alt="TRANSEC">
    <img src="https://img.shields.io/badge/LPI%2FLPD-Doppler%20%26%20AGC%20Sync-blue.svg" alt="Doppler Sync">
    <img src="https://img.shields.io/badge/Resilience-Acoustic%20Fallback-yellow.svg" alt="Acoustic Fallback">
  </p>
</div>

---

**Vollcrypt Wave** is a self-contained, independent military-grade cryptographic protocol designed specifically for tactical radio communications (HF, VHF, UHF bands). Operating under zero-trust, low-bandwidth, and high-noise environments, it combines robust Transmission Security (TRANSEC) and Communications Security (COMSEC) features to protect tactical nets against jamming, interception, and direction-finding metadata tracking.

Unlike `vollcrypt-messages`, **Vollcrypt Wave** is fully independent and implements its own standalone cryptographic flow to meet strict low-overhead and high-resilience requirements of tactical digital and software-defined radios (SDR).

---

## Core Capabilities & Advanced Features

### 1. Cryptographic & Key Management Core
*   **Quantum-Resistant Hybrid KEM:** Combines **ML-KEM-768** (FIPS 203) and **X25519** ECDH via HKDF-SHA256 to ensure tactical networks resist both classical and future quantum-based decryption attacks.
*   **Side-Channel Attack Protection (Blinding & Masking):** Mitigates hardware power/EM analysis (SPA/DPA/EMA). Performs X25519 scalar blinding by mathematically splitting the secret key into random shares $(s-r)$ and $r$ on Edwards coordinates. Implements randomized decoy execution and microsecond-level timing jitter for ML-KEM-768 to disrupt power/EM trace alignments.
*   **Johnson-Nyquist Thermal Entropy Harvesting:** Simulates and samples thermodynamic microvolt-level thermal noise ($V_n$) from the transceiver's RF front-end resistor atomic fluctuations. Converts this physical quantum entropy into a 32-byte session salt fed directly into the HKDF-SHA256 root salt mechanism, yielding non-deterministic key materials independent of software PRNG states.
*   **Asymmetric Recipient Targeting (Wrap Table):** Encrypts messages with a one-time Data Encryption Key (DEK), wrapped individually with each recipient's public key (Hybrid KEM Envelope). Unauthorized nodes cannot decrypt the DEK, preventing data leakage if a node is captured.
*   **Perfect Forward Security (PCS) Ratchet:** Automatically evolves session keys using one-way HKDF ratcheting per message, protecting past communications even if current keys are compromised.
*   **"Split-Brain" Fork & Merge Reconciliation:** Resolves network partition state desynchronization. Nodes automatically spawn cryptographic sub-chain forks during isolation. Upon re-merging, they deterministically merge transcripts and derive matching keys using look-ahead historical ancestor states or multi-signature HQ consensus commands.

### 2. Advanced TRANSEC (Transmission Security)
*   **Deterministic Chaos Hopping (FHSS):** Replaces classic linear PRNGs with non-linear dynamical chaotic systems (**Logistic Map** or 4th-order Runge-Kutta solved **Lorenz Attractor**). Seeds are cryptographically derived from the Word of the Day (WOD) and microsecond-accurate network timestamps, generating hopping sequences indistinguishable from thermal white noise (LPI/LPD).
*   **Dynamic Ephemeral Aliasing:** Call signs and node IDs are masked over-the-air using time-rotating HMAC-SHA256 pseudonyms with clock-drift tolerance.
*   **Noise Floor Steganography (LSB & DSSS):** 
    *   *LSB Steganography:* Embeds coordinate data into the least significant bits of 16-bit PCM voice streams.
    *   *DSSS Spreading:* Spreads bits using a 256-chip pseudo-random code sequence, hiding transmissions deep under the channel noise floor.

### 3. Waveform Sync & RF Physics
*   **Kinematik Doppler Correction:** Calculates relative velocity ($\Delta v$) from phase drift in the packet preamble pilot tones. Dynamically offsets the local oscillator ($f_{\text{new\_rx}} = f_0 (1 + \Delta v / c)$) to compensate for Doppler shift at high speeds (e.g., jets, drones).
*   **Automatic Gain Control (AGC):** Automatically normalizes amplitude variations of received I/Q vectors, allowing robust PSK/QAM demodulation even under chaotic amplitude hopping.
*   **Time-Synchronized Carrier Hopping:** SDR-level time slotting that hops carrier frequencies while respecting physical synthesizer loop-lock constraints (PLL guard bands).
*   **Kaos Spectral Masking (RRC Pulse Shaping):** Bounds chaotic frequency/amplitude hopping transitions using a Root-Raised-Cosine (RRC) digital filter. Smooths signal transitions and suppresses out-of-band emissions by >15 dB, ensuring compliance with strict military spectrum masks and preserving Low Probability of Detection (LPD) security.

### 4. Zero-Overhead & Low Bandwidth Optimization
*   **Compact Frame Format:** Employs **Implicit Nonces** (derived locally from slot index and packet counter, sending 0 bytes over-the-air) and a truncated 64-bit AEAD verification tag. Reduces network header overhead by 62.5% (12 bytes vs. 32 bytes).
*   **4-bit ADPCM Voice Codec:** IMA ADPCM audio engine compressing 16-bit PCM voice streams 4:1 to fit narrow VHF channels.
*   **NACK-Only ARQ Transport:** Sliding-window packet delivery that stays completely silent on successful receptions, sending a NACK only when sequence gaps are detected, minimizing radio frequency footprint.

### 5. Tactical Resilience & Mesh Routing
*   **Co-site Interference / Colocation Blanking:** Regulates colocated transceivers (on the same vehicle or command structure) using a simulated hardware blanking bus. Prevents receiver LNA saturation by physically blanking reception during adjacent transmissions, using priority-based scheduling to resolve transmit collision scenarios and a receiver settling guard time to ensure safe recovery.
*   **Hybrid Forward Error Correction (FEC):** Concatenates systematic Reed-Solomon $RS(32, 28)$ outer coding (Peterson-Gorenstein-Zierler decoder) and Convolutional inner coding (Rate 1/2, K=3, Viterbi trellis decoding) with a Matrix Bit Interleaver to correct burst and random channel errors.
*   **Shannon Capacity & Galois Field Adaptation:** Computes real-time maximum theoretical channel capacity $C = B \log_2(1 + \text{SNR})$ using the Shannon-Hartley theorem, and dynamically adapts the Reed-Solomon parity size $P$ using the Berlekamp-Massey algorithm over $GF(2^8)$ to optimize overhead and error correction.
*   **Store-and-Forward (DTN) Mesh Routing:** Stores encrypted packets in a local queue if destination nodes are out of range, and forwards them automatically when neighbor tracking detects them.
*   **Acoustic Air-Gap Fallback:** If all RF channels are jammed, transceivers autonomously fall back to ultrasonic FSK acoustic modulation (19 kHz for 0, 21 kHz for 1 at 1200 Baud) using Goertzel spectral detection.

### 6. Anti-Tamper & Security Guardrails
*   **Over-the-Air Zeroization (OTAZ - Poison Pill):** Ed25519-signed remote commands that instantly crypto-shred local keys, write null-bytes to NVRAM registries, and permanently lock (brick) the transceiver.
*   **Tamper-Reactive Zeroization:** Hardware interrupt simulation (casing opened, JTAG connected) that wipes static BBRAM master keys, clears RAM, and shred-locks all cryptographic operations.
*   **Duress PIN & Dead-Man's Switch:**
    *   *Duress PIN:* Normalizes the device UI to deceive captors, but silently corrupts all data (XOR 0xAA) and transmits an emergency coordinate packet to HQ.
    *   *Dead-Man's Switch:* Auto-locks and clears active session keys if the operator fails to validate identity within a configurable time window.
*   **Wave-Control-Plane & M-of-N Consensus:** Protects high-impact command execution (e.g., initiating electronic attacks) under a secure control plane. Enforces Zaman Damgası Kontrolü (timestamp drift $|t_{\text{local}} - t_{\text{packet}}| \le \Delta t$), Sürüm Kontrolü (anti-rollback check on epoch version in NVRAM), and M-of-N Ed25519 signature consensus. Protects against firmware rollbacks via epoch tracking and Merkle Tree verification.

---

## Logical Crate Architecture

The `vollcrypt-wave` library is structured as a zero-dependency, `#![no_std]` Rust crate. The protocol logic is organized into the following logical modules:

*   **Key Derivation (`lib`)**: The library entry point coordinating hybrid key encapsulation (ML-KEM-768 + X25519) and session key schedule derivation.
*   **Hardware Abstraction Layer (`hal`)**: Decouples the cryptographic core from transceiver hardware, defining the `TransceiverHal`, `ClockHal`, and `AudioHal` traits.
*   **Chaotic Dynamics (`chaos`)**: Implements non-linear dynamical chaos generators (Logistic Map and Lorenz Attractors).
*   **Chaotic Jitter & Scheduling (`chaotic_burst`)**: Schedules micro-burst transmissions using a Chebyshev Polynomial Map to prevent RF pattern identification.
*   **Doppler Compensation (`doppler`)**: Estimates relative velocity from phase drift in pilot preambles and applies dynamic frequency offsets.
*   **Electronic Warfare (`electronic_attack`)**: Governs orthogonal spot jamming and look-ahead spectrum blanking during electronic attack operations.
*   **Hyperbolic Positioning (`tdoa`)**: Resolves target transmitter locations using a Gauss-Newton hyperbolic Time-Difference-of-Arrival (TDoA) solver.
*   **Coordinate Compression (`delta_grid`)**: Quantizes geographic coordinates into a 12-bit grid packed into a 24-bit compact transmission format.
*   **Homomorphic Routing (`spatial`)**: Wraps coordinates in spatial homomorphic envelopes to protect location privacy during mesh routing.
*   **Entropy Harvesting (`entropy`)**: Simulates and harvests thermodynamic Johnson-Nyquist thermal noise from the transceiver front-end to seed key generation.
*   **State Reconciliation (`reconciliation`)**: Manages sub-chain forking, historical look-ahead search, and deterministic state merges during network partition recovery.
*   **Colocation Blanking (`colocation`)**: Resolves vehicle co-site interference by scheduling a simulated physical blanking bus and settling guard times.
*   **Side-Channel Countermeasures (`side_channel`)**: Implements Edwards coordinate scalar blinding, ML-KEM decoy executions, and random timing jitter.
*   **Ad-hoc Trust (`adhoc`)**: Establishes initial peer trust networks via pre-shared trust pools and identity blinding.
*   **Dynamic Aliasing (`alias`)**: Periodically rotates call signs and node identifiers using time-sensitive HMAC-SHA256 tokens.
*   **Frequency Hopping (`fhss`)**: Generates deterministic hopping patterns for FHSS channels using the dynamic chaotic state.
*   **Steganography (`stego`)**: Conceals binary payloads within PCM audio streams (LSB) or under the noise floor using DSSS.
*   **Packet Formatting (`wave_packet`)**: Defines the binary serializers, `CompactWaveFrame`, and AEAD tag generation.
*   **Modulation Controls (`modulation`)**: Handles FSK/IQ digital modulators, carrier frequency transitions, and automatic gain control (AGC).
*   **Error Correction (`fec`)**: Implements systematic Reed-Solomon, convolutional Viterbi coding, and dynamic Shannon capacity adaptation.
*   **Clock Synchronization (`sync`)**: Maintains Time-of-Day (TOD) synchronization and handles GPS/atomic clock bypass logic.
*   **Audio Compression (`codec`)**: Compresses and decompresses 16-bit PCM voice streams to 4-bit IMA ADPCM to fit low-bandwidth channels.
*   **Mesh Routing (`routing`)**: Orchestrates store-and-forward mesh routing and Delay-Tolerant Networking (DTN) queues.
*   **Reliable Transport (`wave_tcp`)**: Implements sliding-window, NACK-only ARQ transport to minimize radio transmission footprints.
*   **Jitter Buffering (`ring_buffer`)**: Employs a lock-free Single-Producer Single-Consumer (SPSC) ring buffer for smooth audio playback.
*   **Electronic Counter-Countermeasures (`eccm`)**: Evaluates channel health, detects jamming anomalies, and triggers acoustic fallbacks.
*   **Acoustic Communication (`acoustic`)**: Implements ultrasonic FSK modulation and Goertzel spectral detection for acoustic air-gap fallbacks.
*   **Metadata Shielding (`onion` & `asym_onion`)**: Implements asymmetric Onion Routing and Sealed Sender metadata wrapping.
*   **Destination Masking (`multicast`)**: Employs Blind Cluster Multicast with No-ACK destination hiding.
*   **Mutual Handshake (`mutual`)**: Facilitates mutual blind handshakes using Single-use Reply Tokens (SURBs).
*   **Epidemic Gossip (`fountain` & `gossip`)**: Performs data dissemination using Luby Transform (LT) fountain codes and epidemic gossip flooding.
*   **Remote Zeroization (`otaz` & `revocation`)**: Executes over-the-air cryptographic zeroization and device revocation.
*   **Intrusion Defense (`duress` & `tamper`)**: Handles duress PIN codes, dead-man's auto-lock, and tamper hardware interrupt reactions.
*   **Role-Based Clearance (`recipient_target`)**: Controls envelope decryption based on asymmetric recipient wrap tables.
*   **Control Consensus (`otam`)**: Validates control updates and remote commands via M-of-N consensus signatures and epoch counters.

---

## Technical Specifications

| Layer / Mechanism | Primitive / Equation | Purpose |
| :--- | :--- | :--- |
| **COMSEC (Asymmetric)** | ML-KEM-768 + X25519 | Quantum-resistant hybrid KEM |
| **COMSEC (Ad-hoc)**     | PSTP + Blinding + ZK-PoK | Decentralized ad-hoc trust & mutual KEM handshake |
| **COMSEC (Symmetric)**  | AES-256-GCM / CTR | Authenticated payload encryption |
| **COMSEC (Side-Channel)** | Edwards Blinding & Decoy Jitter | Defends against SPA/DPA/EMA key leakage |
| **ENTROPY (KDF Salt)** | $\overline{V_n^2} = 4 k_B T R \Delta f$ | Johnson-Nyquist thermal noise root salt |
| **TRANSEC (Hopping)** | Lorenz Attractor / Logistic Map | Chaotic FHSS channel & amplitude hopping |
| **TRANSEC (Jitter)** | Chebyshev Map: $T_{n+1} = \cos(d \arccos T_n)$ | Chaotic micro-burst transmission scheduling |
| **TRANSEC (Covert)** | 256-Chip DSSS Spreading | Hides signal below noise floor (LPI/LPD) |
| **PHYSICAL (Sync)** | $\Delta v = \frac{\Delta \phi \cdot c}{2\pi \cdot \Delta t \cdot f_0}$ | Kinematic Doppler correction |
| **PHYSICAL (Masking)** | Root-Raised-Cosine (RRC) | Bounds chaotic spectrum within yasal mask B (LPD) |
| **PHYSICAL (AGC)** | $\text{RMS} = \sqrt{\frac{1}{N}\sum \mid s_i \mid^2}$ | Vector amplitude normalization |
| **RESILIENCE (FEC)** | PGZ RS(32, 28) + Viterbi (Rate 1/2) | Double-layer error correction |
| **INFO THEORY (FEC)**| $C = B \log_2(1 + \text{SNR})$ & $GF(2^8)$ BM | Shannon capacity & Galois adaptation ($P \in [2, 32]$) |
| **RESILIENCE (Acoustic)**| CPFSK (19k/21k Hz) + Goertzel | Ultrasonic communication fallback |
| **RESILIENCE (Sync)**   | SHA-256 + HKDF + Look-Ahead | Deterministic P2P & Master Fork-Merge reconciliation |
| **GUARDRAIL (OTAM)** | Ed25519 M-of-N Consensus | Prevent unauthorized control updates |
| **CONTROL PLANE (Wave)** | $\mid t_{\text{local}} - t_{\text{packet}} \mid \le \Delta t$ & Ed25519 M-of-N | Control-plane validation and anti-rollback |
| **PHYSICAL (Colocation)** | Blanking Bus + Priority | Co-site receiver blanking & preemption |
| **PHYSICAL (Localization)** | Gauss-Newton $2 \times 2$ Hyperbolic Solver | Passive TDoA transmitter coordinate lookup |
| **TRANSEC (Compression)** | Galois-grid 12-bit integer delta-packing | 24-bit compact coordinates transmission |
| **PHYSICAL (Attack)** | Orthogonal Phase Noise + Blanking | Spot jamming with look-ahead friendly bypass |
| **PHYSICAL (HAL)** | TransceiverHal + ClockHal + AudioHal | Hardware Abstraction Layer for transceiver drivers |

---

## Independent Publishing

The `vollcrypt-wave` crate is designed to be built, tested, and published completely independently:

```bash
cd vollcrypt-wave
cargo clippy --all-targets -- -D warnings
cargo test
cargo package
cargo publish
```
