package core

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestParseOrgManifestYAMLRejectsUnknownFields(t *testing.T) {
	_, err := ParseOrgManifestYAML([]byte(`
orgs:
  - slug: cozy-art
    unknown: true
`))
	if err == nil {
		t.Fatal("expected unknown field error")
	}
}

func TestReconcileOrgManifestIdempotent(t *testing.T) {
	pool := testPG(t)
	ctx := context.Background()
	svc := NewService(Options{Issuer: "https://test", ServiceTokenPrefix: "cozy"}, Keyset{}).WithPostgres(pool)

	const slug = "manifest-test"
	_, _ = pool.Exec(ctx, `DELETE FROM profiles.remote_applications WHERE slug=$1`, slug)
	_, _ = pool.Exec(ctx, `DELETE FROM profiles.orgs WHERE slug=$1`, slug)
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.remote_applications WHERE slug=$1`, slug)
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.orgs WHERE slug=$1`, slug)
	})

	out := filepath.Join(t.TempDir(), "api.key")
	enabled := true
	manifest := OrgManifest{Orgs: []OrgManifestOrg{{
		Slug: slug,
		Issuers: []OrgManifestIssuer{{
			Issuer:    "https://doujins.example",
			JWKSURI:   "https://doujins.example/.well-known/jwks.json",
			Audiences: []string{"openrails"},
			Enabled:   &enabled,
		}},
		Roles: []OrgManifestRole{{
			Name:        "reader",
			Permissions: []string{PermOrgRead},
		}},
		APIKeys: []OrgManifestAPIKey{{
			Name:        "runtime",
			Permissions: []string{"openrails:entitlements:read"},
			Resources:   []ServiceTokenResource{{Kind: "openrails.merchant", ID: slug}},
			Output:      OrgManifestServiceTokenOutput{File: out},
		}},
	}}}

	first, err := svc.ReconcileOrgManifest(ctx, manifest, FileOrgManifestTokenStore{})
	if err != nil {
		t.Fatalf("first reconcile: %v", err)
	}
	if first.Orgs != 1 || first.Issuers != 1 || first.Roles != 1 || first.TokensMinted != 1 || first.TokensKept != 0 {
		t.Fatalf("first result=%+v", first)
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read output token: %v", err)
	}
	if !strings.HasPrefix(strings.TrimSpace(string(raw)), "cozy_st_") {
		t.Fatalf("output token has wrong marker: %q", raw)
	}

	second, err := svc.ReconcileOrgManifest(ctx, manifest, FileOrgManifestTokenStore{})
	if err != nil {
		t.Fatalf("second reconcile: %v", err)
	}
	if second.TokensMinted != 0 || second.TokensKept != 1 {
		t.Fatalf("second result=%+v, want preserved token", second)
	}
}

func TestParseOrgManifestYAMLRejectsMixedAPIKeysAndServiceTokens(t *testing.T) {
	_, err := ParseOrgManifestYAML([]byte(`
orgs:
  - slug: cozy-art
    api_keys:
      - name: runtime
        permissions: [openrails:admin]
        output:
          file: runtime.key
    service_tokens:
      - name: legacy
        permissions: [openrails:admin]
        output:
          file: legacy.token
`))
	if !errors.Is(err, ErrInvalidOrgManifest) {
		t.Fatalf("err=%v, want ErrInvalidOrgManifest", err)
	}
}

func TestReconcileOrgManifestSeedsIssuerAuthority(t *testing.T) {
	pool := testPG(t)
	ctx := context.Background()
	svc := NewService(Options{Issuer: "https://test"}, Keyset{}).WithPostgres(pool)

	suffix := time.Now().UnixNano()
	slug := fmt.Sprintf("manifest-authority-%d", suffix)
	appSlug := fmt.Sprintf("manifest-authority-app-%d", suffix)
	issuer := fmt.Sprintf("https://manifest-authority-%d.example", suffix)
	manifest, err := ParseOrgManifestYAML([]byte(fmt.Sprintf(`
orgs:
  - slug: %s
    roles:
      - name: operator
        permissions:
          - platform:read
    issuers:
      - slug: %s
        issuer: %s
        jwks_uri: %s/.well-known/jwks.json
        audiences:
          - tensorhub
        role: operator
        permissions:
          - platform:write
`, slug, appSlug, issuer, issuer)))
	if err != nil {
		t.Fatalf("parse manifest: %v", err)
	}
	_, _ = pool.Exec(ctx, `DELETE FROM profiles.remote_applications WHERE slug=$1`, appSlug)
	_, _ = pool.Exec(ctx, `DELETE FROM profiles.orgs WHERE slug=$1`, slug)
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.remote_applications WHERE slug=$1`, appSlug)
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.orgs WHERE slug=$1`, slug)
	})

	result, err := svc.ReconcileOrgManifest(ctx, manifest, nil)
	if err != nil {
		t.Fatalf("reconcile manifest: %v", err)
	}
	if result.Orgs != 1 || result.Roles != 1 || result.Issuers != 1 {
		t.Fatalf("result=%+v", result)
	}
	ra, err := svc.GetRemoteApplication(ctx, issuer)
	if err != nil {
		t.Fatalf("get remote application: %v", err)
	}
	memberships, perms, err := svc.ResolveRemoteApplicationAuthority(ctx, ra.ID)
	if err != nil {
		t.Fatalf("resolve authority: %v", err)
	}
	if !containsString(perms, "platform:read") || !containsString(perms, "platform:write") {
		t.Fatalf("perms=%v, want role-derived and direct issuer permissions", perms)
	}
	if len(memberships) != 1 || memberships[0].Org != slug || !containsString(memberships[0].Roles, "operator") {
		t.Fatalf("memberships=%+v, want %s/operator", memberships, slug)
	}

	if _, err := svc.ReconcileOrgManifest(ctx, manifest, nil); err != nil {
		t.Fatalf("second reconcile: %v", err)
	}
	_, perms, err = svc.ResolveRemoteApplicationAuthority(ctx, ra.ID)
	if err != nil {
		t.Fatalf("resolve authority after second reconcile: %v", err)
	}
	if len(perms) != 2 {
		t.Fatalf("perms after second reconcile=%v, want no duplicate grants", perms)
	}
}

func TestReconcileOrgManifestUpdatesAndDisablesIssuer(t *testing.T) {
	pool := testPG(t)
	ctx := context.Background()
	svc := NewService(Options{Issuer: "https://test"}, Keyset{}).WithPostgres(pool)

	const slug = "manifest-issuer-update"
	const issuer = "https://issuer-update.example"
	_, _ = pool.Exec(ctx, `DELETE FROM profiles.remote_applications WHERE slug=$1`, slug)
	_, _ = pool.Exec(ctx, `DELETE FROM profiles.orgs WHERE slug=$1`, slug)
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.remote_applications WHERE slug=$1`, slug)
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.orgs WHERE slug=$1`, slug)
	})

	enabled := true
	manifest := OrgManifest{Orgs: []OrgManifestOrg{{
		Slug: slug,
		Issuers: []OrgManifestIssuer{{
			Issuer:    issuer,
			JWKSURI:   issuer + "/jwks-v1.json",
			Audiences: []string{"openrails-v1"},
			Enabled:   &enabled,
		}},
	}}}
	if _, err := svc.ReconcileOrgManifest(ctx, manifest, nil); err != nil {
		t.Fatalf("initial reconcile: %v", err)
	}

	disabled := false
	manifest.Orgs[0].Issuers[0].JWKSURI = issuer + "/jwks-v2.json"
	manifest.Orgs[0].Issuers[0].Audiences = []string{"openrails-v2", "openrails-admin"}
	manifest.Orgs[0].Issuers[0].Enabled = &disabled
	if _, err := svc.ReconcileOrgManifest(ctx, manifest, nil); err != nil {
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

func TestReconcileOrgManifestAdvisoryLockPreventsDuplicateTokenMint(t *testing.T) {
	pool := testPG(t)
	ctx := context.Background()
	svcA := NewService(Options{Issuer: "https://test", ServiceTokenPrefix: "cozy"}, Keyset{}).WithPostgres(pool)
	svcB := NewService(Options{Issuer: "https://test", ServiceTokenPrefix: "cozy"}, Keyset{}).WithPostgres(pool)

	const slug = "manifest-lock"
	_, _ = pool.Exec(ctx, `DELETE FROM profiles.orgs WHERE slug=$1`, slug)
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.orgs WHERE slug=$1`, slug) })

	store := &memoryManifestTokenStore{writeDelay: 100 * time.Millisecond}
	manifest := OrgManifest{Orgs: []OrgManifestOrg{{
		Slug: slug,
		APIKeys: []OrgManifestAPIKey{{
			Name:        "runtime",
			Permissions: []string{"openrails:entitlements:read"},
			Resources:   []ServiceTokenResource{{Kind: "openrails.merchant", ID: slug}},
			Output:      OrgManifestServiceTokenOutput{File: "runtime"},
		}},
	}}}

	start := make(chan struct{})
	results := make(chan OrgManifestResult, 2)
	errs := make(chan error, 2)
	run := func(svc *Service) {
		<-start
		res, err := svc.ReconcileOrgManifest(ctx, manifest, store)
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
		JOIN profiles.orgs t ON t.id = st.org_id
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

func (m *memoryManifestTokenStore) ReadOrgManifestToken(_ context.Context, out OrgManifestServiceTokenOutput) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.values == nil {
		m.values = map[string]string{}
	}
	return m.values[out.File], nil
}

func (m *memoryManifestTokenStore) WriteOrgManifestToken(_ context.Context, out OrgManifestServiceTokenOutput, token string) error {
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
