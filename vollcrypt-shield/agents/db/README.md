# Vollcrypt Shield Database Agent

`vollcrypt-shield-db` is an independent database-record integrity agent. It
does not require db-guard or any other Vollcrypt package at runtime. The
built-in adapters support statically bundled SQLite plus TLS-protected
PostgreSQL and MySQL.

The scanner opens SQLite read-only, starts a consistent transaction, binds the
table schema into the snapshot, and represents each row by a path derived from
a domain-separated hash of its stable key. Primary-key values and row contents
are never written to the baseline or CLI report. Every row digest includes the
column names, typed values, and schema hash.

```text
vollcrypt-shield-db init --state-dir ./shield-db-state --scope accounts
vollcrypt-shield-db baseline --state-dir ./shield-db-state --database app.sqlite --table accounts
vollcrypt-shield-db verify --state-dir ./shield-db-state --database app.sqlite --table accounts
```

PostgreSQL always requires certificate-validated TLS and reads connection
settings from the SHIELD_POSTGRES_URL environment variable by default, so
credentials do not appear in the process list. Use baseline-postgres and
verify-postgres; a private trust root is supplied with --ca-file.

The PostgreSQL adapter uses a REPEATABLE READ, READ ONLY transaction, normalizes
session-dependent text representations, binds schema metadata into the signed
root, and streams rows through the same bounded canonical record builder used
by SQLite. Locale-dependent money and user-defined types fail closed.

When a table has no primary key, pass one or more `--key-column` values. The
scan fails closed if those values are null or do not uniquely identify rows.
SQLite views and arbitrary SQL queries are intentionally not accepted.

This package is licensed under `GPL-3.0-only OR LicenseRef-Commercial`.
MySQL implements the same canonical record-source contract over
certificate-validated TLS. Optional db-guard enhanced context uses the
explicit, versioned contract in
[DB_GUARD_CONTEXT_V1.md](DB_GUARD_CONTEXT_V1.md); it is never a runtime
prerequisite.
