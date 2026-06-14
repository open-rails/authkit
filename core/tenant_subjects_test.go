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

	const slug = "tenant-subjects-app"
	const iss = "https://subjects-test.example/iss"
	_, _ = pool.Exec(ctx, `DELETE FROM profiles.remote_applications WHERE slug=$1`, slug)
	ra, err := svc.UpsertRemoteApplication(ctx, RemoteApplication{Slug: slug, Issuer: iss, JWKSURI: "https://subjects-test.example/jwks.json", Enabled: true})
	if err != nil {
		t.Fatalf("create remote_application: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.remote_applications WHERE slug=$1`, slug) })

	first, err := svc.TouchTenantSubject(ctx, ra.ID, "https://issuer-a.example", "same-sub")
	if err != nil {
		t.Fatalf("touch first: %v", err)
	}
	if first.RemoteApplicationID != ra.ID {
		t.Fatalf("RemoteApplicationID=%q, want %q", first.RemoteApplicationID, ra.ID)
	}
	second, err := svc.TouchTenantSubject(ctx, ra.ID, "https://issuer-a.example", "same-sub")
	if err != nil {
		t.Fatalf("touch second: %v", err)
	}
	if second.ID != first.ID {
		t.Fatalf("repeat touches diverged: %q != %q", second.ID, first.ID)
	}
	if second.LastSeenAt.Before(first.LastSeenAt) {
		t.Fatalf("last_seen_at moved backwards: first=%s second=%s", first.LastSeenAt, second.LastSeenAt)
	}

	otherIssuer, err := svc.TouchTenantSubject(ctx, ra.ID, "https://issuer-b.example", "same-sub")
	if err != nil {
		t.Fatalf("touch other issuer: %v", err)
	}
	if otherIssuer.ID == first.ID {
		t.Fatalf("different issuers with the same subject must be distinct subjects")
	}

	subjects, err := svc.ListRemoteAppSubjects(ctx, ra.ID)
	if err != nil {
		t.Fatalf("list subjects: %v", err)
	}
	count := 0
	for _, s := range subjects {
		if s.Subject == "same-sub" {
			count++
		}
	}
	if count != 2 {
		t.Fatalf("subject count=%d, want 2", count)
	}
}

func TestTouchTenantSubjectValidation(t *testing.T) {
	svc := NewService(Options{Issuer: "https://test"}, Keyset{})
	if _, err := svc.TouchTenantSubject(context.Background(), "", "https://issuer.example", "sub"); err == nil {
		t.Fatal("expected validation error")
	}

	pool := testPG(t)
	svc = svc.WithPostgres(pool)
	// Empty principal uuid is rejected outright (hard cut: no slug fallback).
	if _, err := svc.TouchTenantSubject(context.Background(), "", "https://issuer.example", "sub"); !errors.Is(err, ErrInvalidTenantSubject) {
		t.Fatalf("empty principal uuid err=%v, want ErrInvalidTenantSubject", err)
	}
	// uuid that points at no remote_application: FK violation maps to the credential error.
	if _, err := svc.TouchTenantSubject(context.Background(), "00000000-0000-7000-8000-000000000000", "https://issuer.example", "sub"); !errors.Is(err, ErrInvalidTenantSubject) {
		t.Fatalf("unknown principal uuid err=%v, want ErrInvalidTenantSubject", err)
	}
	// Malformed uuid maps to the credential error, not an internal failure.
	if _, err := svc.TouchTenantSubject(context.Background(), "not-a-uuid", "https://issuer.example", "sub"); !errors.Is(err, ErrInvalidTenantSubject) {
		t.Fatalf("malformed principal uuid err=%v, want ErrInvalidTenantSubject", err)
	}
}
