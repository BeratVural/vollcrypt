# db-guard Enhanced Context v1

Shield DB remains fully functional without db-guard. An operator can optionally
export non-secret encryption context from db-guard and bind it into a Shield
database baseline with the global --db-guard-context option.

The JSON contract is:

~~~json
{
  "formatVersion": 1,
  "databaseId": "primary/accounts",
  "kmsRouteId": "kms/eu-central-1/app",
  "encryptionPolicyDigest": "abababababababababababababababababababababababababababababababab",
  "keyEpoch": 7
}
~~~

- formatVersion must be exactly 1. Unknown versions and fields fail closed.
- databaseId is the stable db-guard database identity.
- kmsRouteId is optional and identifies a route, never a credential or key.
- encryptionPolicyDigest is a 32-byte hexadecimal digest of the active
  db-guard encryption policy.
- keyEpoch is the monotonic encryption-key policy epoch.

Shield validates a regular, non-symlink file no larger than 64 KiB. It
canonicalizes the fields and domain-separates their digest before binding it to
the database schema hash. A context change therefore causes a normal baseline
mismatch and requires explicit baseline replacement.

The contract does not load db-guard code, discover packages, invoke plugins, or
accept key material. db-guard should write the file atomically with
administrator-only permissions. Shield intentionally does not silently detect
or trust an installed db-guard package.

~~~text
vollcrypt-shield-db --db-guard-context ./db-guard-context-v1.json baseline --state-dir ./state --database app.sqlite --table accounts
vollcrypt-shield-db --db-guard-context ./db-guard-context-v1.json verify --state-dir ./state --database app.sqlite --table accounts
~~~
