// Package apitest holds black-box tests of the Client and its HTTP API, one
// file per feature. Each test builds a real Client on a scratch schema with
// authtest and drives it as a host (the Go API) or a browser (the mounted
// handler) would. Tests that need the engine's internals stay in
// internal/engine; attacks on the security guarantees live in
// internal/securitytest.
package apitest
