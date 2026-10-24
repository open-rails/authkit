// Package testdb supplies the environment contract used by public authtest.
package testdb

import (
	"os"
	"strings"
	"testing"
)

// URL returns the shared, already-migrated integration database named by
// AUTHKIT_TEST_DATABASE_URL, or skips the test when it is unset.
func URL(t testing.TB) string {
	t.Helper()
	return requireEnv(t, "AUTHKIT_TEST_DATABASE_URL")
}

// requireEnv returns the first non-empty variable among keys. When none is set
// the test skips, unless AUTHKIT_TEST_REQUIRE_DB=1 (exported by `task test` and
// CI) in which case it fails: a misconfigured pipeline must not pass by skipping.
func requireEnv(t testing.TB, keys ...string) string {
	t.Helper()
	if v := firstEnv(keys...); v != "" {
		return v
	}
	msg := strings.Join(keys, "/") + " not set"
	if os.Getenv("AUTHKIT_TEST_REQUIRE_DB") == "1" {
		t.Fatal(msg + " but AUTHKIT_TEST_REQUIRE_DB=1")
	}
	t.Skip(msg + "; skipping DB-backed test")
	return ""
}

func firstEnv(keys ...string) string {
	for _, key := range keys {
		if v := os.Getenv(key); v != "" {
			return v
		}
	}
	return ""
}
