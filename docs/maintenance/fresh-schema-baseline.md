# AuthKit v1 fresh schema baseline

AuthKit's pre-launch schema is being consolidated into one authored baseline.
Earlier AuthKit migration histories are unsupported and must be rebuilt from
approved source data. Migration never drops an existing application's tables.
The schema-neutral `migrations/postgres.FS` interface remains available to
host-owned migratekit runners, using the canonical `authkit` ledger namespace.

Migratekit's `ApplyMigrations(ctx, migrations)` returns only an error. Migration
readiness is established by a successful apply; there is no operational need to
attribute individual migration rows to one replica when several replicas start
concurrently:

| Historical consumer/head (before the migration API hard cut) | Migration consumption at that head |
|---|---|
| Doujins `0ea039e5` | CLI prints Applied count; coordinator discards result |
| Hentai0 `ffad07de` | Raw FS migration runner |
| OpenRails `e7ecbe6e` | Discards Migrate result |
| Cozy-art `0ff4136b` | Raw FS migration runner and metadata tooling |
| Tensorhub `0f86b1b6` | Startup logs Applied names; tests assert old numbers |
| OpenRails SaaS `3511ce85` | Raw FS migration runner |

Consumers should report successful readiness after ApplyMigrations returns nil and test
required schema behavior instead of migration counts. Their dependency updates
must include the new return signature; no compatibility adapter is provided.

The baseline is checked against a PostgreSQL schema catalog and schema-only dump
from the complete prior chain, then exercised through default/custom schema,
repeat/concurrent migration, account, naming, credential and permission workflows.

## Rebuild boundary

`0001_schema.up.sql` is the fresh schema identity. The previous 1–16 migration
histories are not adopted or repaired. Migratekit applies the chain by migration
prefix and detects filename identity conflicts; content drift is reported by its
normal ledger policy. The SQL baseline independently refuses existing AuthKit
relation names. Empty precreated schemas and unrelated host tables are allowed
and remain untouched.

Provision a fresh AuthKit schema, configure the host for that schema, apply the
baseline, then re-import the intended source records. Reusing a prerelease schema
requires an explicit operator reset of AuthKit-owned relations and its ledger
scope: app `authkit`, database `postgres`, schema `profiles` by default or the
configured custom schema. The numeric migratekit ledger uses `BIGINT` sequence columns in
`public.migrations` and `public.migration_repairs`; its earlier tracker layouts
are unsupported. Start with a fresh database for this shared-ledger hard cut.
Do not clear another app's ledger rows or rely on cascading deletion of host-owned tables/foreign keys. AuthKit provides no
automatic DROP/reset path. Future schema changes can append migrations after
this baseline; consumers must test required behavior rather than numbering.

## Validation and removed fixtures

The initial consolidation in PR #186 had a normalized PostgreSQL 18 schema-only
dump exactly matching the complete pre-cut chain after #184: tables, columns,
defaults, constraints, indexes, functions, triggers, sequences and comments.
Only dump headers and per-run restrict tokens are excluded. The dump is the
comparison oracle; the maintained baseline is authored DDL without ALTER,
backfill or intermediate table construction. Subsequent pre-v1 storage cleanup
deliberately changes that candidate: role assignments use live composite primary
keys without historical timestamps, duplicate group indexes are removed, and
terminal invite/key indexes support bounded cleanup. See [storage lifetimes](storage-lifetimes.md).

Migratekit owns installation, repeat/concurrent apply and ledger validation.
AuthKit workflow fixtures apply the embedded raw FS before exercising account,
naming, credential and permission behavior. The former AuthKit-specific
migration runner, bootstrap-claim backfill and refresh-history cutover fixtures
are removed; current claim ownership, refresh rotation and cleanup tests remain.
