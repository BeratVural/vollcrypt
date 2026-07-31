# DB Guard Adapter Contract

`DbGuardContractV1` is the canonical configuration boundary for all six ORM adapters. New integrations should construct this contract and convert it to the framework adapter instead of defining framework-specific key, field, RBAC, or rate-limit configuration.

## Version 1

The contract has four security-relevant scopes:

- `contractVersion` / `contract_version`: must equal `1`.
- `keyring`: one or both supported key versions (`1`, `2`), each exactly 32 bytes, plus an active version that is present in the keyring.
- `resources`: non-empty resource-to-encrypted-field mapping. Resource names are Prisma model, Mongoose model, TypeORM entity, or Rust schema/entity names.
- `security`: optional Crypto-RBAC, masking, rate-limit, and explicit unrestricted-decrypt policy. Blind-index resource mappings use the same resource names.

Node exports the contract from `@vollcrypt/db-guard` and `@vollcrypt/db-guard/contract`:

```ts
const contract: DbGuardContractV1 = {
  contractVersion: 1,
  keyring: {
    keys: { '1': oldKey, '2': activeKey },
    activeVersion: '2'
  },
  resources: {
    User: ['email', 'card']
  },
  security: {
    cryptoRbac: { roles: { support: { decrypt: ['User.email'] } } }
  }
};
```

Use `toPrismaDbGuardOptions`, `toMongooseDbGuardOptions`, `toDrizzleDbGuardOptions`, or `toTypeOrmDbGuardOptions`. The converters validate the complete contract before adapter setup and return `DbGuardContractError` with stable codes.

Rust exports `contract::DbGuardContractV1`, `validate_orm_contract`, and `configure_orm_contract`. Diesel and SeaORM share the same key versions, active version, and resource map. Schema declarations still determine which Rust columns use `EncryptedString`; the contract records and validates that scope before keys enter the process registry.

## Adapter Mapping

| Adapter | Contract resource | Runtime binding |
| --- | --- | --- |
| Prisma | model name | `models` |
| Mongoose | model name selected by converter | `fields` and `modelName` |
| Drizzle | table/entity name used in column path | guarded custom column type |
| TypeORM | entity metadata name | `entities` |
| Diesel | Rust schema/entity name | `EncryptedString` column |
| SeaORM | Rust entity name | `EncryptedString` value type |

Legacy adapter-specific option objects remain supported for compatibility. They are compatibility inputs, not separate security contracts.