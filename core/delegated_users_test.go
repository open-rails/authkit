package core

import (
	"context"
	"errors"
	"testing"
)

// #80: an org-LESS issuer (doujins standalone shape) registers and resolves to
// an empty org; an org-BOUND issuer (cozy-art shape) resolves to its org id.
func TestRemoteApplicationOrgOptional(t *testing.T) {
	pool := testPG(t)
	svc := NewService(Options{Issuer: "https://test"}, Keyset{}).WithPostgres(pool)
	ctx := context.Background()

	// Org-less (doujins): no org bound at all.
	const orglessSlug = "doujins-orgless"
	const orglessIss = "https://doujins.example/iss"
	_, _ = pool.Exec(ctx, `DELETE FROM profiles.remote_applications WHERE slug=$1`, orglessSlug)
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.remote_applications WHERE slug=$1`, orglessSlug) })
	raLess, err := svc.UpsertRemoteApplication(ctx, RemoteApplication{
		Slug: orglessSlug, Issuer: orglessIss, JWKSURI: "https://doujins.example/jwks.json", Enabled: true,
	})
	if err != nil {
		t.Fatalf("org-less upsert: %v", err)
	}
	if raLess.OrgID != "" {
		t.Fatalf("org-less issuer should have empty OrgID, got %q", raLess.OrgID)
	}
	orgID, err := svc.ResolveRemoteApplicationOrg(ctx, orglessIss)
	if err != nil {
		t.Fatalf("resolve org-less: %v", err)
	}
	if orgID != "" {
		t.Fatalf("org-less resolve should be empty, got %q", orgID)
	}

	// Org-bound (cozy-art): org set and resolves back.
	const boundSlug = "cozy-bound"
	const boundIss = "https://cozy.example/bound-iss"
	boundOrg := createTestOrg(t, ctx, svc, pool, "cozy-bound-org")
	_, _ = pool.Exec(ctx, `DELETE FROM profiles.remote_applications WHERE slug=$1`, boundSlug)
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.remote_applications WHERE slug=$1`, boundSlug) })
	raBound, err := svc.UpsertRemoteApplication(ctx, RemoteApplication{
		Slug: boundSlug, OrgID: boundOrg, Issuer: boundIss, JWKSURI: "https://cozy.example/jwks.json", Enabled: true,
	})
	if err != nil {
		t.Fatalf("org-bound upsert: %v", err)
	}
	if raBound.OrgID != boundOrg {
		t.Fatalf("org-bound OrgID = %q, want %q", raBound.OrgID, boundOrg)
	}
	resolved, err := svc.ResolveRemoteApplicationOrg(ctx, boundIss)
	if err != nil {
		t.Fatalf("resolve org-bound: %v", err)
	}
	if resolved != boundOrg {
		t.Fatalf("org-bound resolve = %q, want %q", resolved, boundOrg)
	}
}

// #81: TouchDelegatedUser is idempotent on (remote_application_id, subject) —
// a repeated (issuer, subject) returns the SAME uuidv7 anchor id, and reads find it.
func TestDelegatedUserTouchIdempotent(t *testing.T) {
	pool := testPG(t)
	svc := NewService(Options{Issuer: "https://test"}, Keyset{}).WithPostgres(pool)
	ctx := context.Background()

	const slug = "del-app"
	const iss = "https://del.example/iss"
	const subject = "11111111-1111-1111-1111-111111111111"
	_, _ = pool.Exec(ctx, `DELETE FROM profiles.remote_applications WHERE slug=$1`, slug)
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.remote_applications WHERE slug=$1`, slug) })
	ra, err := svc.UpsertRemoteApplication(ctx, RemoteApplication{
		Slug: slug, Issuer: iss, JWKSURI: "https://del.example/jwks.json", Enabled: true,
	})
	if err != nil {
		t.Fatalf("upsert app: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.delegated_users WHERE remote_application_id=$1`, ra.ID) })

	id1, err := svc.TouchDelegatedUser(ctx, iss, subject)
	if err != nil {
		t.Fatalf("first touch: %v", err)
	}
	if id1 == "" {
		t.Fatal("first touch returned empty id")
	}
	id2, err := svc.TouchDelegatedUser(ctx, iss, subject)
	if err != nil {
		t.Fatalf("second touch: %v", err)
	}
	if id1 != id2 {
		t.Fatalf("idempotent touch returned different ids: %q vs %q", id1, id2)
	}

	got, err := svc.GetDelegatedUser(ctx, iss, subject)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.ID != id1 || got.Subject != subject || got.Issuer != iss {
		t.Fatalf("get mismatch: %+v", got)
	}
	if !got.LastSeenAt.After(got.FirstSeenAt) && !got.LastSeenAt.Equal(got.FirstSeenAt) {
		t.Fatalf("last_seen_at should be >= first_seen_at: %+v", got)
	}

	list, err := svc.ListDelegatedUsersForIssuer(ctx, iss)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 1 || list[0].ID != id1 {
		t.Fatalf("list = %+v, want one row id=%q", list, id1)
	}

	// Unknown issuer fails closed as an invalid delegated user.
	if _, err := svc.TouchDelegatedUser(ctx, "https://nope.example/iss", subject); !errors.Is(err, ErrInvalidDelegatedUser) {
		t.Fatalf("unknown issuer should be ErrInvalidDelegatedUser, got %v", err)
	}
}
