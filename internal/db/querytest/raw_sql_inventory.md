# Raw SQL Inventory

AuthKit's static application queries should live in `internal/db/queries` so
`task sqlc-check` can generate, type-check, and PREPARE them against a migrated
Postgres schema. Raw SQL remains acceptable for DDL, migration/bootstrap paths,
dynamic table selection, advisory locks, and small test fixtures.

## Keep Raw

- `migrations/postgres`: DDL is migration source, not runtime query code.
- `cmd/authkit-server`: migration runner setup and standalone server boot SQL.
- `internal/authcore/permission_group_store.go`: dynamic user-vs-remote role
  table selection and recursive authorization walks; covered by
  `TestQueryContracts/remote applications and permission groups`.
- `internal/authcore/bootstrap_manifest.go`: bootstrap advisory lock/apply guard;
  covered by existing bootstrap manifest integration tests.
- HTTP/authcore integration tests: fixture setup and assertions.
- `internal/db/schema_test.go`: schema-rewrite test doubles.

## Convert Later

- Static admin-directory and cleanup queries outside `internal/db/queries` should
  move to sqlc when those domains get query-contract coverage.
- Static invite/account-registration queries should move to sqlc after the invite
  route surface stabilizes.

## Deleted Now

- None. This issue added coverage infrastructure first; no obvious duplicated raw
  SQL in the touched high-value domains was safe to delete without widening scope.
