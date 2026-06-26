package authcore

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// TestUserProfileLinks verifies the service method that GET /me now uses (instead of
// a raw db handle in the HTTP layer) returns the user's linked provider slugs and
// username aliases — the data the /me response maps to linked_providers/user_aliases.
func TestUserProfileLinks(t *testing.T) {
	pool := testPG(t)
	ctx := context.Background()
	svc := NewService(Options{Issuer: "https://test"}, Keyset{}, WithPostgres(pool))

	var uid string
	uname := fmt.Sprintf("plinks-%d", time.Now().UnixNano())
	if err := pool.QueryRow(ctx, `INSERT INTO profiles.users (username) VALUES ($1) RETURNING id::text`, uname).Scan(&uid); err != nil {
		t.Fatalf("create user: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE id=$1::uuid`, uid) })

	for _, p := range []string{"google", "github"} {
		if _, err := pool.Exec(ctx, `INSERT INTO profiles.user_providers (user_id, issuer, provider_slug, subject) VALUES ($1::uuid,$2,$3,$4)`,
			uid, "https://"+p+".example", p, "subj-"+p); err != nil {
			t.Fatalf("seed provider %s: %v", p, err)
		}
	}
	if _, err := pool.Exec(ctx, `INSERT INTO profiles.user_renames (user_id, from_slug) VALUES ($1::uuid, $2)`, uid, "oldname"); err != nil {
		t.Fatalf("seed rename: %v", err)
	}

	slugs, aliases, err := svc.UserProfileLinks(ctx, uid)
	if err != nil {
		t.Fatalf("UserProfileLinks: %v", err)
	}
	has := func(xs []string, want string) bool {
		for _, x := range xs {
			if x == want {
				return true
			}
		}
		return false
	}
	if !has(slugs, "google") || !has(slugs, "github") {
		t.Fatalf("expected provider slugs google+github, got %v", slugs)
	}
	if !has(aliases, "oldname") {
		t.Fatalf("expected alias oldname, got %v", aliases)
	}
}
