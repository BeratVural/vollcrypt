# @vollcrypt/node

**Cross-platform, quantum-resistant cryptography engine for Node.js - Native Binding**

[![npm](https://img.shields.io/npm/v/@vollcrypt/node.svg)](https://www.npmjs.com/package/@vollcrypt/node)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://github.com/BeratVural/vollcrypt/blob/main/LICENSE)

This package provides the high-performance **native Node.js bindings** for the Vollcrypt cryptography engine. It is compiled directly from Rust using NAPI-RS, offering maximum performance and utilizing hardware-accelerated instructions (such as AES-NI) where available.

## Features

- **Blazing Fast:** Directly executes native machine code without the overhead of WebAssembly.
- **Quantum-Resistant:** Implements the NIST FIPS 203 (ML-KEM-768) standard combined with X25519 for hybrid key exchange.
- **Secure Defaults:** Provides AES-256-GCM, Ed25519, HKDF-SHA256, and post-compromise security ratchets out of the box.
- **Cross-Platform:** Pre-built native binaries are provided for Windows, macOS (Intel & Apple Silicon), and Linux (glibc & musl).

## Installation

```bash
npm install @vollcrypt/node
```

*Note: When you install this package, npm will automatically download the correct pre-compiled native binary for your operating system and CPU architecture.*

## Quick Start

```javascript
const vollcrypt = require('@vollcrypt/node');

// Generate an Ed25519 Identity Keypair
const identity = vollcrypt.generateEd25519Keypair();
console.log("Public Key:", Buffer.from(identity[1]).toString('hex'));

// Sign and Verify
const message = Buffer.from("Hello from Vollcrypt Native!");
const signature = vollcrypt.signMessage(identity[0], message);
const isValid = vollcrypt.verifySignature(identity[1], message, signature);

console.log("Signature Valid:", isValid); // true

// Hybrid Key Exchange (X25519)
const alice = vollcrypt.generateX25519Keypair();
const bob = vollcrypt.generateX25519Keypair();
const sharedSecret = vollcrypt.ecdhSharedSecret(alice[0], bob[1]);

console.log("Shared Secret Derived successfully.");
```

## Documentation

For full API documentation, architecture details, and the WebAssembly equivalent, please refer to the [Vollcrypt Main Repository](https://github.com/BeratVural/vollcrypt).

## License

This project is licensed under the **GNU General Public License v3.0**. 

For commercial use without the GPL copyleft requirement, please contact Berat Vural at [berat.vural.tr@gmail.com](mailto:berat.vural.tr@gmail.com).
