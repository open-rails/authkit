package authcore

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	jwtkit "github.com/open-rails/authkit/jwt"
)

// keyedServiceWithPG builds a Service with generated signing keys AND a Postgres
// pool, so ExchangeRefreshToken (which mints an access token after rotating) works
// end to end.
func keyedServiceWithPG(t *testing.T) *Service {
	t.Helper()
	pool := testPG(t)
	ks, err := jwtkit.NewGeneratedKeySource()
	if err != nil {
		t.Fatalf("gen keys: %v", err)
	}
	svc, err := NewFromConfig(Config{
		Token: TokenConfig{
			Issuer:            "https://issuer.test",
			IssuedAudiences:   []string{"app"},
			ExpectedAudiences: []string{"app"},
		},
		Keys: KeysConfig{Source: ks},
	}, pool)
	if err != nil {
		t.Fatalf("NewFromConfig: %v", err)
	}
	return svc
}

func mkRefreshTestUser(t *testing.T, ctx context.Context, svc *Service, tag string) string {
	t.Helper()
	uname := fmt.Sprintf("refresh-%s-%d", tag, time.Now().UnixNano())
	var id string
	if err := svc.pg.QueryRow(ctx, `INSERT INTO profiles.users (username) VALUES ($1) RETURNING id::text`, uname).Scan(&id); err != nil {
		t.Fatalf("create user: %v", err)
	}
	t.Cleanup(func() { _, _ = svc.pg.Exec(ctx, `DELETE FROM profiles.users WHERE id=$1::uuid`, id) })
	return id
}

// TestExchangeRefreshToken_RotateAndReuse: a successful exchange invalidates the old
// token; replaying the old token trips reuse detection and revokes the family.
func TestExchangeRefreshToken_RotateAndReuse(t *testing.T) {
	svc := keyedServiceWithPG(t)
	ctx := context.Background()
	uid := mkRefreshTestUser(t, ctx, svc, "rotate")

	_, rt, _, err := svc.IssueRefreshSession(ctx, uid, "ua", nil)
	if err != nil {
		t.Fatalf("issue session: %v", err)
	}

	_, _, newRT, err := svc.ExchangeRefreshToken(ctx, rt, "ua", nil)
	if err != nil {
		t.Fatalf("first exchange should succeed: %v", err)
	}
	if newRT == "" || newRT == rt {
		t.Fatalf("expected a rotated refresh token distinct from the old one")
	}

	// Replaying the OLD token must be detected as reuse.
	if _, _, _, err := svc.ExchangeRefreshToken(ctx, rt, "ua", nil); err == nil {
		t.Fatalf("replaying the old refresh token must fail (reuse detection)")
	}
}

// TestExchangeRefreshToken_ConcurrentSingleWinner: two concurrent exchanges of the
// same valid token must yield EXACTLY ONE success — the CAS prevents the old
// double-mint where both calls minted a valid refresh token from one read.
func TestExchangeRefreshToken_ConcurrentSingleWinner(t *testing.T) {
	svc := keyedServiceWithPG(t)
	ctx := context.Background()
	uid := mkRefreshTestUser(t, ctx, svc, "concurrent")

	_, rt, _, err := svc.IssueRefreshSession(ctx, uid, "ua", nil)
	if err != nil {
		t.Fatalf("issue session: %v", err)
	}

	const n = 2
	var wg sync.WaitGroup
	results := make([]error, n)
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			_, _, _, e := svc.ExchangeRefreshToken(ctx, rt, "ua", nil)
			results[i] = e
		}(i)
	}
	wg.Wait()

	successes := 0
	for _, e := range results {
		if e == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("concurrent exchange of one token: want exactly 1 success, got %d", successes)
	}
}
