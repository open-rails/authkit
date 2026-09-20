// Package authkit defines the public contracts shared by AuthKit hosts, the
// embedded engine, HTTP transports, and verification code.
//
// The root package owns Client, domain and wire types, typed identifiers,
// policy vocabulary, and the error catalog. It also owns the small shared
// operations on those contracts: credential parsing, permission matching,
// naming-policy evaluation, response encoding, and erasure acknowledgement.
// Importing it does not construct an engine or connect to a database.
//
// Construct the engine with embedded.New. Call embedded.ApplyMigrations before
// construction so AuthKit owns its schema and migration runner. Mount
// authentication routes through authhttp or a framework adapter, and use
// verify for credential verification and request authorization. Database
// access, token issuance, and authentication workflows are implemented by
// embedded, not this package.
//
// Client describes host operations implemented by embedded.Client. A host can
// define a smaller interface for the operations it needs; Client membership
// does not define the full supported API. Documented concrete operations are
// also covered by the repository's SEMVER.md contract.
//
// The root package remains independent of PostgreSQL drivers and framework
// adapters. Document aliases and the internal error model share their canonical
// definitions without importing the engine. The dependency guard tests preserve
// this boundary for both authkit and verify.
package authkit
