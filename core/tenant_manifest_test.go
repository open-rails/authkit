package core

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseTenantManifestYAMLRejectsUnknownFields(t *testing.T) {
	_, err := ParseTenantManifestYAML([]byte(`
tenants:
  - slug: cozy-art
    unknown: true
`))
	if err == nil {
		t.Fatal("expected unknown field error")
	}
}

func TestReconcileTenantManifestIdempotent(t *testing.T) {
	pool := testPG(t)
	ctx := context.Background()
	svc := NewService(Options{Issuer: "https://test", ServiceTokenPrefix: "cozy"}, Keyset{}).WithPostgres(pool)

	const slug = "manifest-test"
	_, _ = pool.Exec(ctx, `DELETE FROM profiles.tenants WHERE slug=$1`, slug)
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.tenants WHERE slug=$1`, slug) })

	out := filepath.Join(t.TempDir(), "token")
	enabled := true
	manifest := TenantManifest{Tenants: []TenantManifestTenant{{
		Slug: slug,
		Issuers: []TenantManifestIssuer{{
			Issuer:    "https://doujins.example",
			JWKSURI:   "https://doujins.example/.well-known/jwks.json",
			Audiences: []string{"openrails"},
			Enabled:   &enabled,
		}},
		Roles: []TenantManifestRole{{
			Name:        "reader",
			Permissions: []string{PermTenantRead},
		}},
		ServiceTokens: []TenantManifestServiceToken{{
			Name:        "runtime",
			Permissions: []string{"openrails:entitlements:read"},
			Resources:   []ServiceTokenResource{{Kind: "openrails.tenant", ID: slug}},
			Output:      TenantManifestServiceTokenOutput{File: out},
		}},
	}}}

	first, err := svc.ReconcileTenantManifest(ctx, manifest, FileTenantManifestTokenStore{})
	if err != nil {
		t.Fatalf("first reconcile: %v", err)
	}
	if first.Tenants != 1 || first.Issuers != 1 || first.Roles != 1 || first.TokensMinted != 1 || first.TokensKept != 0 {
		t.Fatalf("first result=%+v", first)
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read output token: %v", err)
	}
	if !strings.HasPrefix(strings.TrimSpace(string(raw)), "cozy_st_") {
		t.Fatalf("output token has wrong marker: %q", raw)
	}

	second, err := svc.ReconcileTenantManifest(ctx, manifest, FileTenantManifestTokenStore{})
	if err != nil {
		t.Fatalf("second reconcile: %v", err)
	}
	if second.TokensMinted != 0 || second.TokensKept != 1 {
		t.Fatalf("second result=%+v, want preserved token", second)
	}
}
