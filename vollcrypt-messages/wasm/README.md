# @vollcrypt/wasm

**Cross-platform, quantum-resistant cryptography engine - WebAssembly Binding**

[![npm](https://img.shields.io/npm/v/@vollcrypt/wasm.svg)](https://www.npmjs.com/package/@vollcrypt/wasm)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://github.com/BeratVural/vollcrypt/blob/main/LICENSE)

This package provides the **WebAssembly (WASM) bindings** for the Vollcrypt cryptography engine. It is compiled directly from Rust using `wasm-pack`, bringing robust, post-quantum cryptography straight to the user's browser or frontend application (React, Next.js, Vue, etc.) without relying on slow JavaScript cryptography implementations.

## Features

- **Universal:** Runs in any modern browser without native binary dependencies.
- **Quantum-Resistant:** Implements the NIST FIPS 203 (ML-KEM-768) standard combined with X25519 for hybrid key exchange.
- **Client-Side E2EE:** Perfect for End-to-End Encryption where keys never leave the user's device.
- **Secure Defaults:** Provides AES-256-GCM, Ed25519, HKDF-SHA256, and post-compromise security ratchets out of the box.

## Installation

```bash
npm install @vollcrypt/wasm
```

*Note: Since this is a WebAssembly module, you may need to configure your bundler (Webpack, Vite, Rollup) to handle `.wasm` files depending on your frontend setup.*

## Quick Start

```javascript
import * as vollcrypt from '@vollcrypt/wasm';

// Generate an Ed25519 Identity Keypair
const identity = vollcrypt.generate_ed25519_keypair();
console.log("Public Key:", Buffer.from(identity.public_key).toString('hex'));

// Sign and Verify
const message = new TextEncoder().encode("Hello from Vollcrypt WASM!");
const signature = vollcrypt.sign_message(identity.private_key, message);
const isValid = vollcrypt.verify_signature(identity.public_key, message, signature);

console.log("Signature Valid:", isValid); // true

// Hybrid Key Exchange (X25519)
const alice = vollcrypt.generate_x25519_keypair();
const bob = vollcrypt.generate_x25519_keypair();
const sharedSecret = vollcrypt.ecdh_shared_secret(alice.private_key, bob.public_key);

console.log("Shared Secret Derived successfully.");
```

## Documentation

For full API documentation, architecture details, and the high-performance Native Node.js equivalent, please refer to the [Vollcrypt Main Repository](https://github.com/BeratVural/vollcrypt).

## License

This project is licensed under the **GNU General Public License v3.0**. 

For commercial use without the GPL copyleft requirement, please contact Berat Vural at [berat.vural.tr@gmail.com](mailto:berat.vural.tr@gmail.com).
