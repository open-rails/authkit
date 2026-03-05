package core

import (
	"os"
	"strings"
	"testing"
)

func TestReservedMetadataMigrationAddsUserAndOrgMetadataColumns(t *testing.T) {
	sqlBytes, err := os.ReadFile("../migrations/postgres/009_user_org_metadata.up.sql")
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}
	sql := strings.ToLower(string(sqlBytes))
	if !strings.Contains(sql, "alter table profiles.users") || !strings.Contains(sql, "add column if not exists metadata jsonb") {
		t.Fatalf("expected users metadata jsonb migration in 009_user_org_metadata.up.sql")
	}
	if !strings.Contains(sql, "alter table profiles.orgs") || !strings.Contains(sql, "add column if not exists metadata jsonb") {
		t.Fatalf("expected orgs metadata jsonb migration in 009_user_org_metadata.up.sql")
	}
}
