// Package authkit embeds AuthKit in a Go host: accounts, sessions, MFA,
// passkeys, permission groups, API keys and remote applications on the
// host's PostgreSQL.
//
// Run Migrate, then New with a Config and Deps. New returns *Auth, the one
// host type: its methods are the host operations, Verifier and
// Require/Optional/RequireLive verify requests, and with Config.HTTP set,
// Handler serves AuthKit's HTTP surface (Mount, Patterns and Routes place it
// on a router). If the entitlements provider needs the Auth first, pass it to
// SetEntitlements, then call Start.
//
// This package is the whole host API: auth*.go hold the operations, config.go
// and roles.go the configuration, deps.go the dependencies and migrations.go
// Migrate. The implementation lives in internal/engine.
//
// Shared identity and access types live in package iam; package verify
// verifies tokens without a database, and the adapters mount AuthKit on Gin
// or Fiber. docs/stability.md states what is stable.
package authkit
