package authcore

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

// mkUnlinkUser creates a user with the given provider slugs linked, and optionally
// a password row, returning the user id.
func mkUnlinkUser(t *testing.T, ctx context.Context, svc *Service, withPassword bool, providers ...string) string {
	t.Helper()
	uname := fmt.Sprintf("unlink-%d", time.Now().UnixNano())
	var id string
	if err := svc.pg.QueryRow(ctx, `INSERT INTO profiles.users (username) VALUES ($1) RETURNING id::text`, uname).Scan(&id); err != nil {
		t.Fatalf("create user: %v", err)
	}
	t.Cleanup(func() { _, _ = svc.pg.Exec(ctx, `DELETE FROM profiles.users WHERE id=$1::uuid`, id) })
	if withPassword {
		if _, err := svc.pg.Exec(ctx, `INSERT INTO profiles.user_passwords (user_id, password_hash, hash_algo) VALUES ($1::uuid, 'x', 'argon2id')`, id); err != nil {
			t.Fatalf("seed password: %v", err)
		}
	}
	for i, p := range providers {
		if _, err := svc.pg.Exec(ctx,
			`INSERT INTO profiles.user_providers (user_id, issuer, provider_slug, subject) VALUES ($1::uuid, $2, $3, $4)`,
			id, "https://"+p+".example", p, fmt.Sprintf("subj-%d-%s", i, id)); err != nil {
			t.Fatalf("seed provider %s: %v", p, err)
		}
	}
	return id
}

func (s *Service) providerCount(t *testing.T, ctx context.Context, userID string) int {
	t.Helper()
	var n int
	if err := s.pg.QueryRow(ctx, `SELECT count(*)::int FROM profiles.user_providers WHERE user_id=$1::uuid`, userID).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	return n
}

// TestUnlinkProviderUnlessLast_Guard: a password-less user with one provider cannot
// unlink it (would strip the last login method); the row survives.
func TestUnlinkProviderUnlessLast_Guard(t *testing.T) {
	pool := testPG(t)
	ctx := context.Background()
	svc := NewService(Config{Token: TokenConfig{Issuer: "https://test"}}, Keyset{}, WithPostgres(pool))
	uid := mkUnlinkUser(t, ctx, svc, false, "google")

	removed, err := svc.UnlinkProviderUnlessLast(ctx, uid, "google")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if removed {
		t.Fatalf("unlinking the last login method must be refused (removed=false)")
	}
	if got := svc.providerCount(t, ctx, uid); got != 1 {
		t.Fatalf("provider must survive a refused unlink; count=%d", got)
	}
}

// TestUnlinkProviderUnlessLast_Allowed: with a password (a remaining login method),
// the single provider can be unlinked.
func TestUnlinkProviderUnlessLast_Allowed(t *testing.T) {
	pool := testPG(t)
	ctx := context.Background()
	svc := NewService(Config{Token: TokenConfig{Issuer: "https://test"}}, Keyset{}, WithPostgres(pool))
	uid := mkUnlinkUser(t, ctx, svc, true, "google")

	removed, err := svc.UnlinkProviderUnlessLast(ctx, uid, "google")
	if err != nil || !removed {
		t.Fatalf("unlink with a password present should succeed: removed=%v err=%v", removed, err)
	}
	if got := svc.providerCount(t, ctx, uid); got != 0 {
		t.Fatalf("provider should be gone; count=%d", got)
	}
}

// TestUnlinkProviderUnlessLast_ConcurrentNeverZero: a password-less user with two
// providers, hit by two concurrent unlinks of the DIFFERENT providers, must end up
// with at least one login method (exactly one unlink succeeds) — the L1 lockout.
func TestUnlinkProviderUnlessLast_ConcurrentNeverZero(t *testing.T) {
	pool := testPG(t)
	ctx := context.Background()
	svc := NewService(Config{Token: TokenConfig{Issuer: "https://test"}}, Keyset{}, WithPostgres(pool))
	uid := mkUnlinkUser(t, ctx, svc, false, "google", "github")

	var wg sync.WaitGroup
	res := make([]bool, 2)
	errs := make([]error, 2)
	for i, p := range []string{"google", "github"} {
		wg.Add(1)
		go func(i int, p string) {
			defer wg.Done()
			res[i], errs[i] = svc.UnlinkProviderUnlessLast(ctx, uid, p)
		}(i, p)
	}
	wg.Wait()

	successes := 0
	for i := range res {
		if errs[i] != nil {
			t.Fatalf("unexpected error: %v", errs[i])
		}
		if res[i] {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("exactly one concurrent unlink must succeed, got %d", successes)
	}
	if got := svc.providerCount(t, ctx, uid); got != 1 {
		t.Fatalf("user must retain one login method, never zero; count=%d", got)
	}
}
