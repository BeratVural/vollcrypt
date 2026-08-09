# Vollcrypt Shield Database Agent

`vollcrypt-shield-db` is an independent database-record integrity agent. It
does not require db-guard or any other Vollcrypt package at runtime. The first
built-in adapter is SQLite and is statically bundled in the binary.

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

When a table has no primary key, pass one or more `--key-column` values. The
scan fails closed if those values are null or do not uniquely identify rows.
SQLite views and arbitrary SQL queries are intentionally not accepted.

This package is licensed under `GPL-3.0-only OR LicenseRef-Commercial`.
Future PostgreSQL/MySQL drivers will implement the same canonical record-source
contract. db-guard detection will remain an optional enhanced mode, not a
runtime prerequisite.
