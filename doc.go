// Package authkit embeds AuthKit in a Go host: accounts, sessions, MFA,
// passkeys, permission groups, API keys and remote applications on the
// host's PostgreSQL.
//
// Call New with a Config and Deps, then Start. New creates or upgrades
// AuthKit's tables first and returns *Client, the one host type: its methods
// are the host operations; it authenticates requests (verify.Required(client),
// and the live gates verify.RequireSession, RequirePermission and Sensitive,
// which check the session); and with Config.HTTP set, Handler serves
// AuthKit's HTTP surface (Mount and Routes place it on a router).
//
// Config is plain data; Deps holds everything that reaches outside the
// process (the pool, keys, providers, senders and the host's hooks, each a
// func). Both are defined once in internal/config and re-exported here under
// the same names, so their field docs are on that package's page and in
// gopls. auth*.go hold the operations and roles.go the permission model's
// builder. The implementation lives in internal/engine.
//
// Shared identity and access types live in package iam; package verify
// verifies tokens without a database, and the adapters mount AuthKit on Gin
// or Fiber and send its messages through Twilio.
package authkit
