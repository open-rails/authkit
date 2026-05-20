package core

import (
	"strings"
	"testing"
)

func TestFreshAuthMigrationAndPolicyContract(t *testing.T) {
	authSchema := readSource(t, "../migrations/postgres/001_auth_schema.up.sql")
	serviceSessions := readSource(t, "service_sessions.go")

	if !strings.Contains(authSchema, "last_authenticated_at") {
		t.Fatalf("fresh auth session storage must include last_authenticated_at")
	}
	for _, marker := range []string{
		"SensitiveActionFreshAuthWindow = 30 * time.Minute",
		"COALESCE(last_authenticated_at, created_at)",
		"INSERT INTO profiles.refresh_sessions (id, family_id, user_id, issuer, current_token_hash, expires_at, user_agent, ip_addr, last_authenticated_at)",
		"VALUES ($1,$2,$3,$4,$5,$6,$7,$8,now())",
		"ErrReauthenticationRequired",
	} {
		if !strings.Contains(serviceSessions, marker) {
			t.Fatalf("expected service_sessions.go to contain %q", marker)
		}
	}
}
