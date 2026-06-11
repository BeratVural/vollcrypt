# db-guard

Application-level, field-level encryption integrations for ORMs (Prisma, Mongoose, Drizzle, TypeORM, Diesel, SeaORM) powered by FIPS-compliant cryptography.

`db-guard` secures sensitive database columns (SSN, credit card numbers, addresses, personal data) by encrypting them before they hit the database. It prevents data leakage from compromised database dumps, unauthorized database connections, or compromised database administrators (DBAs).

---

## Key Features

- **Multi-ORM Support**: Integrations for Node.js (Prisma, Mongoose, Drizzle, TypeORM) and Rust (Diesel, SeaORM).
- **Dynamic Multi-Tenant Routing**: Dynamically resolves distinct KMS keys or database configurations per request context using AsyncLocalStorage.
- **Secure Key Cache**: Protects memory from dumps using an ephemeral master key generated randomly at boot. Plaint-text DEKs are wrapped with AES-256-KW and cached with automated TTL eviction and zeroization.
- **Schema Evolution & Crypto-Agility**: Features backward-compatible prefixes for smooth algorithm transitions without database downtime.
- **M-of-N Break-Glass Protocol**: Emergency KMS bypass via threshold Ed25519 signature verification.
- **Compliance Scorecard CLI**: Built-in CLI scans configuration and outputs compliance scorecards for GDPR Article 32, KVKK Article 12, and PCI-DSS v4.0.
- **Supply Chain Security (SLSA Level 4)**: Build pipeline automatically compiles CycloneDX SBOM and SLSA Level 4 Provenance files, cryptographically signed with Ed25519.
- **FIPS 140-3 & Post-Quantum Hybrid Transition**: Conforms to FIPS 140-3 logical and physical boundaries with NIST FIPS 203 (ML-KEM) lattice-based algorithms registered for hybrid key exchange.
- **Hardened Blind Indexing**: Allows exact-match querying on encrypted columns via HKDF-SHA256 shadow columns, avoiding frequency analysis vulnerabilities.
- **RAM Security**: Aggressive memory zeroization (null-byte writing) for keys and plaintext buffers in memory.
- **Batch Migration CLI**: Built-in CLI tool to perform chunked shadow database migrations in the background.

---

## Installation

For Node.js (Prisma, Mongoose, Drizzle, TypeORM):
```bash
npm install @vollcrypt/db-guard
```

For Rust (Diesel, SeaORM):
```toml
# Cargo.toml
[dependencies]
vollcrypt-db-guard = { path = "db-guard/rust", features = ["sqlite", "sea-orm"] }
```

---

## Configuration & Usage

### 1. Prisma ORM (TypeScript)

Register `prismaDbGuard` extension on your client:

```typescript
import { PrismaClient } from '@prisma/client';
import { prismaDbGuard } from '@vollcrypt/db-guard';

const key = Buffer.from('your-secure-32-byte-encryption-key-here');

const basePrisma = new PrismaClient();
export const prisma = basePrisma.$extends(
  prismaDbGuard({
    key,
    models: {
      User: ['credit_card', 'ssn'],
    },
  })
);
```

### 2. Mongoose (TypeScript)

Register `mongooseDbGuard` as a schema plugin:

```typescript
import { Schema, model } from 'mongoose';
import { mongooseDbGuard } from '@vollcrypt/db-guard';

const key = Buffer.from('your-secure-32-byte-encryption-key-here');

const UserSchema = new Schema({
  name: String,
  credit_card: String,
});

UserSchema.plugin(mongooseDbGuard, {
  key,
  fields: ['credit_card'],
});

export const User = model('User', UserSchema);
```

### 3. Drizzle ORM (TypeScript)

Use the `createDrizzleGuard` factory to declare encrypted text columns:

```typescript
import { pgTable, serial } from 'drizzle-orm/pg-core';
import { createDrizzleGuard } from '@vollcrypt/db-guard';

const guard = createDrizzleGuard({
  key: Buffer.from('your-secure-32-byte-encryption-key-here'),
});

export const users = pgTable('users', {
  id: serial('id').primaryKey(),
  creditCard: guard.pgText('credit_card'), // Automatically encrypted/decrypted
});
```

### 4. TypeORM (TypeScript)

Define your entity subscribers using `createTypeOrmSubscriber`:

```typescript
import { DataSource } from 'typeorm';
import { createTypeOrmSubscriber } from '@vollcrypt/db-guard';

const key = Buffer.from('your-secure-32-byte-encryption-key-here');

const VollcryptSubscriber = createTypeOrmSubscriber({
  key,
  entities: {
    User: ['credit_card', 'ssn'],
  },
});

export const AppDataSource = new DataSource({
  subscribers: [VollcryptSubscriber],
});
```

### 5. Diesel (Rust)

Use `EncryptedString` in your schema and models:

```rust
use diesel::prelude::*;
use vollcrypt_db_guard::diesel_impl::EncryptedString;

#[derive(Queryable, Selectable, Insertable)]
#[diesel(table_name = users)]
pub struct User {
    pub id: i32,
    pub name: String,
    pub credit_card: EncryptedString,
}
```

### 6. SeaORM (Rust)

Use the SeaORM-compatible `EncryptedString` type wrapper:

```rust
use sea_orm::entity::prelude::*;
use vollcrypt_db_guard::seaorm_impl::EncryptedString;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "users")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    pub name: String,
    pub credit_card: EncryptedString,
}
```

Initialize your keys at application boot for Rust:
```rust
use vollcrypt_db_guard::{set_key, set_active_version};

fn main() {
    let key = [0u8; 32]; // Secure 32-byte key
    set_key("1", &key);
    set_active_version("1").unwrap();
}
```

---

## Cloud & On-Premises KMS Providers

`db-guard` supports multiple key management systems (KMS) and hardware security modules (HSM) to resolve keys dynamically for envelope encryption.

### 1. Node.js KMS Providers

We provide several KmsProvider implementations:

- **AwsKmsProvider**: Resolves keys using AWS KMS.
- **GcpKmsProvider**: Resolves keys using Google Cloud KMS.
- **VaultKmsProvider**: Resolves keys using HashiCorp Vault.
- **Pkcs11KmsProvider**: Interacts with physical or virtual HSMs (YubiHSM2, Thales, Nitrokey, SoftHSM2, etc.) using the standard PKCS#11 protocol.

#### Node.js PKCS#11 Configuration Example:
```typescript
import { Pkcs11KmsProvider } from '@vollcrypt/db-guard';

const kmsProvider = new Pkcs11KmsProvider({
  libraryPath: '/usr/local/lib/softhsm/libsofthsm2.so', // Path to vendor PKCS#11 library
  pin: '123456',                                      // Slot/Token PIN
  slotId: 0,                                          // Target Slot Index (optional, default: 0)
  keyId: '000102',                                    // Hex-encoded CKA_ID of the AES-256 key in HSM
});

// Decrypt wrapped key (DEK) inside HSM
const decryptedKey = await kmsProvider.decrypt(wrappedKeyBuffer);
```

### 2. Rust PKCS#11 Support

To use PKCS#11 in Rust, enable the `pkcs11` feature:
```toml
# Cargo.toml
[dependencies]
vollcrypt-db-guard = { path = "db-guard/rust", features = ["sqlite", "pkcs11"] }
```

You can then decrypt wrapped keys directly inside your HSM:
```rust
use vollcrypt_db_guard::pkcs11_impl::decrypt_with_hsm;

let decrypted = decrypt_with_hsm(
    "/usr/local/lib/softhsm/libsofthsm2.so", // Path to PKCS#11 module
    "123456",                               // PIN
    Some(0),                                // Slot ID
    "010203",                               // Hex CKA_ID
    &wrapped_data,                          // Ciphertext containing wrapped DEK
).unwrap();
```

---

## CLI Commands

The package includes a dual-purpose CLI tool for database migrations and compliance auditing.

### 1. Database Migrations (`migrate`)
Encrypts existing plaintext records in a live database using batch processing:

```bash
# Run PostgreSQL migration
npx vollcrypt-db-guard migrate \
  --db-type postgres \
  --db-url "postgres://user:pass@localhost:5432/db" \
  --table users \
  --column credit_card \
  --key "your_32_byte_hex_key_here" \
  --chunk-size 100 \
  --id-col id

# Run MongoDB migration
npx vollcrypt-db-guard migrate \
  --db-type mongodb \
  --db-url "mongodb://localhost:27017/db" \
  --table users \
  --column credit_card \
  --key "your_32_byte_hex_key_here" \
  --chunk-size 100 \
  --id-col _id
```

### 2. Compliance Scorecard Generator (`compliance`)
Scans cryptographic configurations and generates an auditor-ready HTML compliance report:

```bash
npx vollcrypt-db-guard compliance \
  --config compliance-config.json \
  --output compliance-report.html
```

---

## Supply Chain & Compliance Verification

Refer to the following standalone validation documentation for formal verification processes:
- **Supply Chain Artifacts**: Signed CycloneDX SBOM and SLSA Level 4 Provenance are located in `dist/sbom.json` and `dist/provenance.json` post-build.
- **FIPS 140-3 Boundaries**: Detailed logical boundaries, Approved algorithm registries, and post-quantum hybrid structures are defined in [FIPS_VALIDATION.md](file:///c:/Users/iTopya/Desktop/Project/vollcrypt/db-guard/FIPS_VALIDATION.md).
