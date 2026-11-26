# Open release candidate

`rc/1.59.0`: PgBouncer in transaction mode. AuthKit works through a transaction-pooled `Postgres` pool and dials a direct session only for what pooling breaks (LISTEN, session advisory locks, migrations); LISTEN/NOTIFY is a wake-up hint over durable tables.

One RC is open at a time. This file names its branch (`rc/<version>`, the version it will become, cut from master) and what it is for; feature PRs target that branch. See [branches and CI](docs/ci.md).
