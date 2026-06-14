package core

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
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
	_, _ = pool.Exec(ctx, `DELETE FROM profiles.remote_applications WHERE slug=$1`, slug)
	_, _ = pool.Exec(ctx, `DELETE FROM profiles.tenants WHERE slug=$1`, slug)
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.remote_applications WHERE slug=$1`, slug)
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.tenants WHERE slug=$1`, slug)
	})

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

func TestReconcileTenantManifestUpdatesAndDisablesIssuer(t *testing.T) {
	pool := testPG(t)
	ctx := context.Background()
	svc := NewService(Options{Issuer: "https://test"}, Keyset{}).WithPostgres(pool)

	const slug = "manifest-issuer-update"
	const issuer = "https://issuer-update.example"
	_, _ = pool.Exec(ctx, `DELETE FROM profiles.remote_applications WHERE slug=$1`, slug)
	_, _ = pool.Exec(ctx, `DELETE FROM profiles.tenants WHERE slug=$1`, slug)
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.remote_applications WHERE slug=$1`, slug)
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.tenants WHERE slug=$1`, slug)
	})

	enabled := true
	manifest := TenantManifest{Tenants: []TenantManifestTenant{{
		Slug: slug,
		Issuers: []TenantManifestIssuer{{
			Issuer:    issuer,
			JWKSURI:   issuer + "/jwks-v1.json",
			Audiences: []string{"openrails-v1"},
			Enabled:   &enabled,
		}},
	}}}
	if _, err := svc.ReconcileTenantManifest(ctx, manifest, nil); err != nil {
		t.Fatalf("initial reconcile: %v", err)
	}

	disabled := false
	manifest.Tenants[0].Issuers[0].JWKSURI = issuer + "/jwks-v2.json"
	manifest.Tenants[0].Issuers[0].Audiences = []string{"openrails-v2", "openrails-admin"}
	manifest.Tenants[0].Issuers[0].Enabled = &disabled
	if _, err := svc.ReconcileTenantManifest(ctx, manifest, nil); err != nil {
		t.Fatalf("update reconcile: %v", err)
	}

	got, err := svc.GetRemoteApplication(ctx, issuer)
	if err != nil {
		t.Fatalf("GetRemoteApplication: %v", err)
	}
	if got.Enabled {
		t.Fatalf("remote_application should be disabled after manifest update")
	}
	if got.JWKSURI != issuer+"/jwks-v2.json" {
		t.Fatalf("JWKSURI=%q", got.JWKSURI)
	}
	if strings.Join(got.Audiences, ",") != "openrails-v2,openrails-admin" {
		t.Fatalf("Audiences=%v", got.Audiences)
	}
}

func TestReconcileTenantManifestAdvisoryLockPreventsDuplicateTokenMint(t *testing.T) {
	pool := testPG(t)
	ctx := context.Background()
	svcA := NewService(Options{Issuer: "https://test", ServiceTokenPrefix: "cozy"}, Keyset{}).WithPostgres(pool)
	svcB := NewService(Options{Issuer: "https://test", ServiceTokenPrefix: "cozy"}, Keyset{}).WithPostgres(pool)

	const slug = "manifest-lock"
	_, _ = pool.Exec(ctx, `DELETE FROM profiles.tenants WHERE slug=$1`, slug)
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.tenants WHERE slug=$1`, slug) })

	store := &memoryManifestTokenStore{writeDelay: 100 * time.Millisecond}
	manifest := TenantManifest{Tenants: []TenantManifestTenant{{
		Slug: slug,
		ServiceTokens: []TenantManifestServiceToken{{
			Name:        "runtime",
			Permissions: []string{"openrails:entitlements:read"},
			Resources:   []ServiceTokenResource{{Kind: "openrails.tenant", ID: slug}},
			Output:      TenantManifestServiceTokenOutput{File: "runtime"},
		}},
	}}}

	start := make(chan struct{})
	results := make(chan TenantManifestResult, 2)
	errs := make(chan error, 2)
	run := func(svc *Service) {
		<-start
		res, err := svc.ReconcileTenantManifest(ctx, manifest, store)
		if err != nil {
			errs <- err
			return
		}
		results <- res
	}
	go run(svcA)
	go run(svcB)
	close(start)

	for range 2 {
		select {
		case err := <-errs:
			t.Fatalf("reconcile: %v", err)
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for concurrent reconcilers")
		case <-results:
		}
	}
	if writes := store.writes.Load(); writes != 1 {
		t.Fatalf("token writes=%d, want 1", writes)
	}
	var tokenCount int
	if err := pool.QueryRow(ctx, `
		SELECT COUNT(*)
		FROM profiles.service_tokens st
		JOIN profiles.tenants t ON t.id = st.tenant_id
		WHERE t.slug=$1
	`, slug).Scan(&tokenCount); err != nil {
		t.Fatalf("count service tokens: %v", err)
	}
	if tokenCount != 1 {
		t.Fatalf("service token rows=%d, want 1", tokenCount)
	}
}

type memoryManifestTokenStore struct {
	mu         sync.Mutex
	values     map[string]string
	writes     atomic.Int32
	writeDelay time.Duration
}

func (m *memoryManifestTokenStore) ReadTenantManifestToken(_ context.Context, out TenantManifestServiceTokenOutput) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.values == nil {
		m.values = map[string]string{}
	}
	return m.values[out.File], nil
}

func (m *memoryManifestTokenStore) WriteTenantManifestToken(_ context.Context, out TenantManifestServiceTokenOutput, token string) error {
	m.writes.Add(1)
	if m.writeDelay > 0 {
		time.Sleep(m.writeDelay)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.values == nil {
		m.values = map[string]string{}
	}
	m.values[out.File] = token
	return nil
}
