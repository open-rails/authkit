# Query Tests

`task sqlc-check` is the cheap universal gate. sqlc regenerates the query
package and `sqlc vet` PREPAREs every sqlc query against a migrated Postgres
database, which proves syntax and schema compatibility.

`task test-query-contracts` is the semantic gate. It starts the shared compose
Postgres dependency, creates a scratch database, applies AuthKit migrations,
seeds deterministic fixtures, and executes high-value query domains through the
real generated query methods and permission-group store.

`task test-query-perf` is the scaling gate. It uses the same scratch database
harness, bulk-seeds large users/sessions/membership/provider/rename tables with
`COPY`, runs `ANALYZE`, and checks hot queries with
`EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON)`.

The perf gate EXPLAINs the **real generated query text**: each case pulls its SQL
from `db.QueryText[...]` (the live sqlc constants), never a hand-copied string, so
the gate can never drift from what the app runs. Each case runs inside a
rolled-back transaction, so write queries (UPDATE/DELETE) are planned and timed
without mutating the shared seed. Budgets live inline in each `perfCase`.

The seed is deliberately non-uniform: one "fat" user carries many sessions and
provider links span several issuers, so per-user fan-out and per-issuer
cardinality costs (sorts, skip scans) surface instead of hiding behind
one-row-per-user data.

Coverage is deliberately selective: only queries whose plan can degrade at scale
are gated (non-unique filters, `ORDER BY`+`LIMIT`, array membership, joins, and
sweeps over growable tables). PK / unique point lookups are O(1) and not gated.
Current cases: user-by-email, user-by-username, users-by-id-array, session by
current/previous hash, sessions list/evict by user, session revoke-by-family,
provider link by issuer+subject, provider slugs by user, identity
forward-username (rename join), users purge sweep, and the raw authcore
group-roles page query. A case may also assert `ForbidSort` (no `Sort` node) for
queries that must be index-ordered, e.g. `sessions_evict_oldest`.

Known limitation: the gate catches `Seq Scan` (and, where asserted, `Sort`) on a
forbidden table, but not a *full Index Scan* (an index used but walked
end-to-end). A query can pass and still be O(n) on an index.

## Findings

Fixed (gated):

- `SessionsRevokeFamily`: was a full `refresh_sessions` seq scan (`WHERE
  family_id = $1`). Migration 002 adds `refresh_sessions_family_active`; gated by
  the `session_revoke_family` case.
- `SessionsEvictOldest`: `ORDER BY last_used_at` forced a `Sort` because the
  per-user index stopped at `(user_id, issuer)`. Migration 002 extends it to
  `(user_id, issuer, last_used_at)`; gated by `sessions_evict_oldest` with
  `ForbidSort`.
- `ProviderLinkBySlug`: was served by a PG18 skip scan over `(issuer, subject)`
  whose cost grew with issuer count. Migration 003 adds
  `user_providers_slug_subject_idx`; now a point probe, gated by
  `provider_by_slug_subject`.

Investigated, not a problem:

- `UsersPurgeCandidates`: uses a `Sort`, but only over the **partial**
  `users_deleted_at_idx` (it touches just the soft-deleted rows, never a full
  scan), then top-N sorts the `LIMIT` page in microseconds. The planner correctly
  prefers bitmap + top-N to random index-ordered heap fetches for the small
  eligible set, so it is gated for no-seq-scan + budget but **not** `ForbidSort`.

Noted (not fixed):

- `SessionsDeleteRevokedOrExpired`: seq-scans `refresh_sessions`. Periodic GC
  sweep, so a full scan is acceptable; index only if cadence/size warrants it.

Environment contract, shared with OpenRails:

- `QUERY_TEST_DATABASE_URL`: Postgres server URL override.
- `QUERY_TEST_KEEP_DB`: keep the scratch database for debugging.
- `QUERY_PERF_SCALE`: perf seed size, default `100000`.
- `QUERY_PERF_REPORT`: optional JSON report path.
