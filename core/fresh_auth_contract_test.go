package core

import (
	"strings"
	"testing"
)

func TestFreshAuthMigrationAndPolicyContract(t *testing.T) {
	authSchema := readSource(t, "../migrations/postgres/001_auth_schema.up.sql")
	migration := readSource(t, "../migrations/postgres/016_refresh_session_fresh_auth.up.sql")
	serviceSessions := readSource(t, "service_sessions.go")

	for _, src := range []string{authSchema, migration} {
		if !strings.Contains(src, "last_authenticated_at") {
			t.Fatalf("fresh auth session storage must include last_authenticated_at")
		}
	}
	for _, marker := range []string{
		"SensitiveActionFreshAuthWindow = 30 * time.Minute",
		"COALESCE(last_authenticated_at, created_at)",
		"last_authenticated_at)\n          VALUES ($1,$2,$3,$4,$5,$6,now())",
		"ErrReauthenticationRequired",
	} {
		if !strings.Contains(serviceSessions, marker) {
			t.Fatalf("expected service_sessions.go to contain %q", marker)
		}
	}
}
