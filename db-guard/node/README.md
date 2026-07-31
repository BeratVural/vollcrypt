# db-guard

Application-level, field-level encryption integrations for ORMs (Prisma, Mongoose, Drizzle, TypeORM, Diesel, SeaORM). This package is not FIPS or CMVP validated.

`db-guard` secures sensitive database columns (SSN, credit card numbers, addresses, personal data) by encrypting them before they hit the database. It prevents data leakage from compromised database dumps, unauthorized database connections, or compromised database administrators (DBAs).

---

## Key Features

- **Multi-ORM Support**: Integrations for Node.js (Prisma, Mongoose, Drizzle, TypeORM) and Rust (Diesel, SeaORM).
- **Dynamic Multi-Tenant Routing**: Dynamically resolves distinct KMS keys or database configurations per request context using AsyncLocalStorage.
- **Secure Key Cache**: Wraps cached DEKs with an ephemeral process key, applies TTL eviction, and performs best-effort zeroization of mutable buffers. This does not prevent privileged process-memory inspection.
- **Schema Evolution & Crypto-Agility**: Features backward-compatible prefixes for smooth algorithm transitions without database downtime.
- **M-of-N Break-Glass Protocol**: Emergency KMS bypass via threshold Ed25519 signature verification.
- **Configuration Scorecard CLI**: Reports whether selected technical controls are configured. The output is evidence for review, not a GDPR, KVKK, PCI-DSS, FIPS, or CMVP certification.
- **Supply Chain Artifacts**: Builds generate a CycloneDX SBOM and signed provenance metadata. These repository-generated artifacts are not an independent SLSA Level 4 attestation.
- **Validation Status**: The package is not FIPS 140-3 validated and does not claim a CMVP certificate. Post-quantum support is a roadmap item for db-guard.
- **Explicit-Risk Blind Indexing**: Keyed deterministic equality indexes support exact-match queries but reveal equality frequencies and require allowFrequencyLeakage: true.
- **Memory Hygiene**: Mutable JavaScript buffers created by the package are zeroized on best-effort paths. Immutable V8 strings, native crypto internals, active secrets, and core dumps remain outside that guarantee.
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

Multi-tenant Prisma and Mongoose integrations cache wrapped key material for `multiTenant.cacheTtlMs` (default `120000` ms). A rotation controller must call `invalidateCachedKeys(tenantId, version?)` on every application node before advertising the new key generation. Use a pub/sub rotation event or equivalent deployment control; the in-process cache does not synchronize itself across hosts.

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
# Store secrets in files supplied by your secret manager with restrictive permissions.
# The CLI also accepts VOLLCRYPT_DB_GUARD_DB_URL and VOLLCRYPT_DB_GUARD_KEY_HEX.
npx vollcrypt-db-guard migrate \
  --db-type postgres \
  --db-url-file /run/secrets/db-url \
  --table users \
  --column credit_card \
  --key-file /run/secrets/db-guard-key-hex \
  --chunk-size 100 \
  --id-col id

# MongoDB uses the same secret-file inputs.
npx vollcrypt-db-guard migrate \
  --db-type mongodb \
  --db-url-file /run/secrets/mongo-url \
  --table users \
  --column credit_card \
  --key-file /run/secrets/db-guard-key-hex \
  --chunk-size 100 \
  --id-col _id
```
### 2. Compliance Scorecard Generator (`compliance`)
Scans selected configuration controls and generates a review scorecard. The report is not a certification:

```bash
npx vollcrypt-db-guard compliance \
  --config compliance-config.json \
  --output compliance-report.html
```

---

## Supply Chain and Validation Status

- **Generated artifacts**: CycloneDX SBOM and signed provenance metadata are emitted under dist during a build. Verification establishes artifact integrity only; it does not establish an independent SLSA level.
- **FIPS and PQC status**: See [FIPS_VALIDATION.md](../FIPS_VALIDATION.md). db-guard is not FIPS 140-3 validated, has no CMVP certificate, and must not be represented as certified.
- **Memory boundary**: Applications with a process-memory or core-dump attacker must add operating-system dump restrictions, least privilege, process isolation, and HSM/KMS-backed key custody. JavaScript code cannot guarantee deterministic erasure of V8 strings or native OpenSSL allocations.
