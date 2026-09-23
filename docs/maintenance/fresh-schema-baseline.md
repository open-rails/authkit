# AuthKit v1 fresh schema baseline

AuthKit's pre-launch schema is being consolidated into one authored baseline.
Earlier AuthKit migration histories are unsupported and must be rebuilt from
approved source data. Migration never drops an existing application's tables.
The migration source is private to AuthKit. Hosts call
`embedded.ApplyMigrations`, which uses the canonical `authkit` ledger
namespace and creates the configured target schema.

`embedded.ApplyMigrations(ctx, pool, schema)` returns only an error. Migration
readiness is established by a successful apply; there is no operational need to
attribute individual migration rows to one replica when several replicas start
concurrently.

For separate migration and application credentials, pass
`embedded.MigrationOptions{RuntimePool: applicationPool}`. The initializer
resolves the connected application's database user and grants its runtime
permissions directly, without creating roles or memberships. The two pools
must target the same database. A missing runtime pool retains migration-only
behavior; an unreachable runtime pool or a different database fails before
migration begins. With host-owned River, its grants remain host-owned too.

## Rebuild boundary

`0001_schema.up.sql` installs the fresh baseline, including recoverable account
deletion and delivery receipts. `0002_group_soft_deletion.up.sql` adds retained
inactive group state without rewriting that published baseline or existing rows.
Call `embedded.ApplyMigrations` to initialize a fresh database or apply numbered
follow-up migrations to that exact baseline. Earlier incompatible prerelease
schemas still require a fresh database; there is no ledger adoption, repair,
or automatic reset path. River owns its independent migration chain. Published
tags remain immutable.

The baseline refuses existing AuthKit-owned relation names. Empty precreated
schemas and unrelated host tables are allowed and remain untouched. Repeated
initialization uses migratekit's normal ledger validation.

## Validation

The consolidated schema is compared with the previous complete chain on
PostgreSQL 18, including constraints, indexes, functions, triggers, policies,
extensions, grants and reference rows. The only intentional schema removal is
`account_deletions.jobs_enqueued`, which existed solely for historical backfill
adoption. New deletion requests insert their lifecycle row, receipts and River
jobs in one transaction and require a composed producer before acceptance.
The historical adoption scan and upgrade fixture are removed; account deletion,
restore, callback retry and initializer concurrency tests remain.
