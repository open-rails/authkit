package core

import (
	"context"
	"errors"
	"testing"
)

func TestTouchTenantSubjectPersistsOIDCTuple(t *testing.T) {
	pool := testPG(t)
	ctx := context.Background()
	svc := NewService(Options{Issuer: "https://test"}, Keyset{}).WithPostgres(pool)

	const slug = "tenant-subjects-test"
	_, _ = pool.Exec(ctx, `DELETE FROM profiles.tenants WHERE slug=$1`, slug)
	var tenantID string
	if err := pool.QueryRow(ctx, `INSERT INTO profiles.tenants (slug) VALUES ($1) RETURNING id::text`, slug).Scan(&tenantID); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.tenants WHERE id=$1::uuid`, tenantID) })

	// uuid-keyed touch (canonical path: tenant_id claim present).
	first, err := svc.TouchTenantSubject(ctx, tenantID, "", "https://issuer-a.example", "same-sub")
	if err != nil {
		t.Fatalf("touch first: %v", err)
	}
	if first.TenantID != tenantID {
		t.Fatalf("TenantID=%q, want %q", first.TenantID, tenantID)
	}
	// slug-keyed touch (legacy fallback) must hit the same row.
	second, err := svc.TouchTenantSubject(ctx, "", slug, "https://issuer-a.example", "same-sub")
	if err != nil {
		t.Fatalf("touch second: %v", err)
	}
	if second.ID != first.ID {
		t.Fatalf("uuid and slug touches diverged: %q != %q", second.ID, first.ID)
	}
	if second.LastSeenAt.Before(first.LastSeenAt) {
		t.Fatalf("last_seen_at moved backwards: first=%s second=%s", first.LastSeenAt, second.LastSeenAt)
	}

	otherIssuer, err := svc.TouchTenantSubject(ctx, tenantID, "", "https://issuer-b.example", "same-sub")
	if err != nil {
		t.Fatalf("touch other issuer: %v", err)
	}
	if otherIssuer.ID == first.ID {
		t.Fatalf("different issuers with the same subject must be distinct tenant subjects")
	}

	var count int
	if err := pool.QueryRow(ctx, `
		SELECT count(*)
		FROM profiles.tenant_subjects ts
		JOIN profiles.tenants t ON t.id = ts.tenant_id
		WHERE t.slug=$1 AND ts.subject='same-sub'
	`, slug).Scan(&count); err != nil {
		t.Fatalf("count tenant subjects: %v", err)
	}
	if count != 2 {
		t.Fatalf("tenant subject count=%d, want 2", count)
	}

	// Deprecated wrapper still works and lands on the same row.
	viaWrapper, err := svc.TouchDelegatedUser(ctx, slug, "https://issuer-a.example", "same-sub")
	if err != nil {
		t.Fatalf("deprecated wrapper: %v", err)
	}
	if viaWrapper.ID != first.ID {
		t.Fatalf("wrapper diverged from canonical row: %q != %q", viaWrapper.ID, first.ID)
	}
}

func TestTouchTenantSubjectValidation(t *testing.T) {
	svc := NewService(Options{Issuer: "https://test"}, Keyset{})
	if _, err := svc.TouchTenantSubject(context.Background(), "", "", "https://issuer.example", "sub"); err == nil {
		t.Fatal("expected validation error")
	}

	pool := testPG(t)
	svc = svc.WithPostgres(pool)
	if _, err := svc.TouchTenantSubject(context.Background(), "", "missing-tenant", "https://issuer.example", "sub"); !errors.Is(err, ErrInvalidTenantSubject) {
		t.Fatalf("missing tenant err=%v, want ErrInvalidTenantSubject", err)
	}
	// uuid that points at no tenant: FK violation maps to the credential error.
	if _, err := svc.TouchTenantSubject(context.Background(), "00000000-0000-7000-8000-000000000000", "", "https://issuer.example", "sub"); !errors.Is(err, ErrInvalidTenantSubject) {
		t.Fatalf("unknown tenant uuid err=%v, want ErrInvalidTenantSubject", err)
	}
	// Malformed uuid maps to the credential error, not an internal failure.
	if _, err := svc.TouchTenantSubject(context.Background(), "not-a-uuid", "", "https://issuer.example", "sub"); !errors.Is(err, ErrInvalidTenantSubject) {
		t.Fatalf("malformed tenant uuid err=%v, want ErrInvalidTenantSubject", err)
	}
}
