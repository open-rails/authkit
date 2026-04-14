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

func TestReservedSlugSeedMigrationContainsCanonicalSlugs(t *testing.T) {
	sqlBytes, err := os.ReadFile("../migrations/postgres/010_seed_reserved_slugs.up.sql")
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}
	sql := strings.ToLower(string(sqlBytes))
	for _, slug := range []string{"'admin'", "'superuser'", "'root'", "'sudo'"} {
		if !strings.Contains(sql, slug) {
			t.Fatalf("expected reserved slug %s in 010_seed_reserved_slugs.up.sql", slug)
		}
	}
	if strings.Contains(sql, "'moderator'") {
		t.Fatalf("unexpected deprecated slug 'moderator' in 010_seed_reserved_slugs.up.sql")
	}
}

func TestOwnerNamespaceStateMigrationAddsReservedNameTableAndStates(t *testing.T) {
	sqlBytes, err := os.ReadFile("../migrations/postgres/012_owner_namespace_states.up.sql")
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}
	sql := strings.ToLower(string(sqlBytes))
	if !strings.Contains(sql, "create table if not exists profiles.owner_reserved_names") {
		t.Fatalf("expected owner_reserved_names table in 012_owner_namespace_states.up.sql")
	}
	if !strings.Contains(sql, "restricted_name") && !strings.Contains(sql, "owner_reserved_names") {
		t.Fatalf("expected restricted_name semantics in 012_owner_namespace_states.up.sql")
	}
	if !strings.Contains(sql, "parked_org") || !strings.Contains(sql, "registered_org") {
		t.Fatalf("expected parked_org/registered_org state backfill in 012_owner_namespace_states.up.sql")
	}
	if !strings.Contains(sql, "set is_personal=false") || !strings.Contains(sql, "owner_user_id=null") {
		t.Fatalf("expected legacy reserved personal-org conversion in 012_owner_namespace_states.up.sql")
	}
}

func TestOwnerNamespaceStateRenameMigrationExists(t *testing.T) {
	sqlBytes, err := os.ReadFile("../migrations/postgres/013_owner_namespace_state_restricted_name.up.sql")
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}
	sql := strings.ToLower(string(sqlBytes))
	if !strings.Contains(sql, "reserved_name") || !strings.Contains(sql, "restricted_name") {
		t.Fatalf("expected reserved_name -> restricted_name rewrite in 013_owner_namespace_state_restricted_name.up.sql")
	}
}
