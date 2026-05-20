package core

import (
	"os"
	"strings"
	"testing"
)

func TestReservedMetadataBaselineDefinesUserAndOrgMetadataColumns(t *testing.T) {
	sqlBytes, err := os.ReadFile("../migrations/postgres/001_auth_schema.up.sql")
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}
	sql := strings.ToLower(string(sqlBytes))
	if !strings.Contains(sql, "create table if not exists profiles.users") || !strings.Contains(sql, "metadata          jsonb not null default '{}'::jsonb") {
		t.Fatalf("expected users metadata jsonb column in baseline schema")
	}
	if !strings.Contains(sql, "create table if not exists profiles.orgs") || !strings.Contains(sql, "metadata      jsonb not null default '{}'::jsonb") {
		t.Fatalf("expected orgs metadata jsonb column in baseline schema")
	}
}

func TestReservedSlugBaselineContainsCanonicalSlugs(t *testing.T) {
	sqlBytes, err := os.ReadFile("../migrations/postgres/001_auth_schema.up.sql")
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}
	sql := strings.ToLower(string(sqlBytes))
	for _, slug := range []string{"'admin'", "'superuser'", "'root'", "'sudo'"} {
		if !strings.Contains(sql, slug) {
			t.Fatalf("expected reserved slug %s in baseline schema", slug)
		}
	}
	if strings.Contains(sql, "'moderator'") {
		t.Fatalf("unexpected deprecated slug 'moderator' in baseline schema")
	}
}

func TestOwnerNamespaceBaselineDefinesReservedNameTable(t *testing.T) {
	sqlBytes, err := os.ReadFile("../migrations/postgres/001_auth_schema.up.sql")
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}
	sql := strings.ToLower(string(sqlBytes))
	if !strings.Contains(sql, "create table if not exists profiles.owner_reserved_names") {
		t.Fatalf("expected owner_reserved_names table in baseline schema")
	}
	if !strings.Contains(sql, "constraint owner_reserved_names_slug_format_chk") {
		t.Fatalf("expected reserved-name slug constraint in baseline schema")
	}
	if !strings.Contains(sql, "insert into profiles.owner_reserved_names") {
		t.Fatalf("expected canonical reserved-name seed in baseline schema")
	}
	if strings.Contains(sql, "namespace_state=reserved_name") {
		t.Fatalf("baseline schema should use final restricted-name semantics without historical reserved_name state")
	}
}
