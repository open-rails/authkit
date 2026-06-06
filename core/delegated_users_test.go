package core

import (
	"context"
	"errors"
	"testing"
)

func TestTouchDelegatedUserPersistsOIDCTuple(t *testing.T) {
	pool := testPG(t)
	ctx := context.Background()
	svc := NewService(Options{Issuer: "https://test"}, Keyset{}).WithPostgres(pool)

	const slug = "delegated-users-test"
	_, _ = pool.Exec(ctx, `DELETE FROM profiles.tenants WHERE slug=$1`, slug)
	var tenantID string
	if err := pool.QueryRow(ctx, `INSERT INTO profiles.tenants (slug) VALUES ($1) RETURNING id::text`, slug).Scan(&tenantID); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.tenants WHERE id=$1::uuid`, tenantID) })

	first, err := svc.TouchDelegatedUser(ctx, slug, "https://issuer-a.example", "same-sub")
	if err != nil {
		t.Fatalf("touch first: %v", err)
	}
	second, err := svc.TouchDelegatedUser(ctx, slug, "https://issuer-a.example", "same-sub")
	if err != nil {
		t.Fatalf("touch second: %v", err)
	}
	if second.ID != first.ID {
		t.Fatalf("repeat touch created a new delegated user: %q != %q", second.ID, first.ID)
	}
	if second.LastSeenAt.Before(first.LastSeenAt) {
		t.Fatalf("last_seen_at moved backwards: first=%s second=%s", first.LastSeenAt, second.LastSeenAt)
	}

	otherIssuer, err := svc.TouchDelegatedUser(ctx, slug, "https://issuer-b.example", "same-sub")
	if err != nil {
		t.Fatalf("touch other issuer: %v", err)
	}
	if otherIssuer.ID == first.ID {
		t.Fatalf("different issuers with the same subject must be distinct delegated users")
	}

	var count int
	if err := pool.QueryRow(ctx, `
		SELECT count(*)
		FROM profiles.delegated_users du
		JOIN profiles.tenants t ON t.id = du.tenant_id
		WHERE t.slug=$1 AND du.subject='same-sub'
	`, slug).Scan(&count); err != nil {
		t.Fatalf("count delegated users: %v", err)
	}
	if count != 2 {
		t.Fatalf("delegated user count=%d, want 2", count)
	}
}

func TestTouchDelegatedUserValidation(t *testing.T) {
	svc := NewService(Options{Issuer: "https://test"}, Keyset{})
	if _, err := svc.TouchDelegatedUser(context.Background(), "", "https://issuer.example", "sub"); err == nil {
		t.Fatal("expected validation error")
	}

	pool := testPG(t)
	svc = svc.WithPostgres(pool)
	_, err := svc.TouchDelegatedUser(context.Background(), "missing-tenant", "https://issuer.example", "sub")
	if !errors.Is(err, ErrInvalidDelegatedUser) {
		t.Fatalf("missing tenant err=%v, want ErrInvalidDelegatedUser", err)
	}
}
