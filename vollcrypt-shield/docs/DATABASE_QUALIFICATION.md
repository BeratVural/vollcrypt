# Database Qualification Evidence

Shield database qualification is split between the public standalone record
agent and the private commercial control plane. Passing one boundary does not
substitute for the other.

## Public standalone adapters

Public commit `8570fb3332f34597a6e406cc8ac1a1a8453bb31e` produced these
successful, immutable job results:

- PostgreSQL 17 with a private test CA and certificate-validated TLS:
  [job 93344694384](https://github.com/BeratVural/vollcrypt/actions/runs/31352089417/job/93344694384)
- MySQL 8.4 with a private test CA and certificate-validated TLS:
  [job 93344694433](https://github.com/BeratVural/vollcrypt/actions/runs/31352089417/job/93344694433)

Each job creates a disposable database, establishes a consistent read-only
baseline, verifies an unchanged table, changes a row through a separate
database client, and requires the adapter to return a signed mismatch result.
The PostgreSQL adapter uses `REPEATABLE READ READ ONLY`; MySQL uses
`REPEATABLE READ`, `READ ONLY`, and `WITH CONSISTENT SNAPSHOT`. Both use
the bounded canonical record-source contract and fail closed on unsupported or
ambiguous values.

## Commercial PostgreSQL backend

The commercial source remains private and is not vendored, copied, or
submoduled into this public tree. Its private qualification ledger records a
successful run against a disposable PostgreSQL 17 server restricted to TLS
1.3, together with formatting, strict Clippy, Windows/Linux tests, and customer
archive source-leak rejection. Repository, commit, workflow, and artifact
identifiers remain private commercial metadata.

This is repeatable synthetic staging evidence. Production qualification remains
customer- and environment-specific because certificate ownership, network
policy, PostgreSQL configuration, high availability, retention, and backup
controls differ by deployment.
