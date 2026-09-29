# Stability

AuthKit is pre-v1 (`v0.x`).

## Go API

Any v0 minor release may break the Go API. Breaks are hard cuts: no aliases,
deprecated shims or compatibility layers. [Release notes](release-notes/) say
what to change.
Patch releases only fix bugs.

## Contracts, even before v1

Clients, tokens and databases outlive a Go upgrade, so these change only by a
deliberate, release-noted decision:

- **HTTP routes**: method, path and auth requirement of every route in
  [api-endpoints.md](api-endpoints.md).
- **Wire error codes**: `error.code` strings and their HTTP statuses. Clients
  must tolerate new codes; `error.message` is never covered.
- **JWT claims**: token `typ` values, claim names and their meaning.
- **Migrations**: a released migration is never edited or removed
  (`scripts/check.sh contracts` enforces this); the schema changes only through
  new, higher-numbered migrations. Databases built by v0.106.2 or later keep an
  in-place upgrade path.

Not covered: anything under `internal/`, test helpers, log lines, metric names.

## Packages

Public: `authkit` (`New`, `Migrate`, configuration and `*Client`), `iam`
(shared types, standard library only), `verify` (database-free verification),
`jwtkit`, `documents`, `authprovider`, `authtest`, `devicekey` (the device-key
client) and `adapters/*`. The
implementation is `internal/engine`, the HTTP surface `internal/httpapi`.
Nothing below the root imports it (`deps_guard_test.go`).

## v1

v1.0.0 and v1.0.1 were published prematurely. Both are retracted in `go.mod`
and their tags are deleted. The Go checksum database remembers them, so those
versions can never be reused: the first real v1 must be v1.0.2 or later.
