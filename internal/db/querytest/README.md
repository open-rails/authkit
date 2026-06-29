# Query Tests

`task sqlc-check` is the cheap universal gate. sqlc regenerates the query
package and `sqlc vet` PREPAREs every sqlc query against a migrated Postgres
database, which proves syntax and schema compatibility.

`task test-query-contracts` is the semantic gate. It starts the shared compose
Postgres dependency, creates a scratch database, applies AuthKit migrations,
seeds deterministic fixtures, and executes high-value query domains through the
real generated query methods and permission-group store.

`task test-query-perf` is the scaling gate. It uses the same scratch database
harness, bulk-seeds large users/sessions/membership tables with `COPY`, runs
`ANALYZE`, and checks hot queries with
`EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON)`.

Environment contract, shared with OpenRails:

- `QUERY_TEST_DATABASE_URL`: Postgres server URL override.
- `QUERY_TEST_KEEP_DB`: keep the scratch database for debugging.
- `QUERY_PERF_SCALE`: perf seed size, default `100000`.
- `QUERY_PERF_REPORT`: optional JSON report path.
