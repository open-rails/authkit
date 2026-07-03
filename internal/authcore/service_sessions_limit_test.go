package authcore

import (
	"context"
	"sync"
	"testing"
)

// TestIssueRefreshSession_CapHoldsUnderConcurrency: with SessionMaxPerUser=N, firing
// many concurrent session creations for one user must leave at most N active sessions.
// Before the fix the count→evict→insert sequence raced (each concurrent login read
// count==N, evicted the same one oldest, and inserted), so the user could exceed the
// cap; the per-user advisory lock + single transaction make the cap an invariant.
func TestIssueRefreshSession_CapHoldsUnderConcurrency(t *testing.T) {
	pool := testPG(t)
	ks := testKeySource(t)
	const maxSessions = 3
	svc, err := NewFromConfig(Config{
		Token: TokenConfig{
			Issuer:            "https://issuer.test",
			IssuedAudiences:   []string{"app"},
			ExpectedAudiences: []string{"app"},
			SessionMaxPerUser: maxSessions,
		},
		Keys: KeysConfig{Source: ks},
	}, pool)
	if err != nil {
		t.Fatalf("NewFromConfig: %v", err)
	}
	ctx := context.Background()
	uid := mkRefreshTestUser(t, ctx, svc, "cap")

	const n = 4 * maxSessions
	var wg sync.WaitGroup
	wg.Add(n)
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			_, _, _, e := svc.IssueRefreshSession(ctx, uid, "ua", nil)
			errs[i] = e
		}(i)
	}
	wg.Wait()
	for i, e := range errs {
		if e != nil {
			t.Fatalf("concurrent issue %d failed: %v", i, e)
		}
	}

	var active int
	if err := svc.pg.QueryRow(ctx,
		`SELECT count(*) FROM profiles.refresh_sessions
		 WHERE user_id=$1::uuid AND issuer=$2 AND revoked_at IS NULL
		   AND (expires_at IS NULL OR expires_at > now())`,
		uid, "https://issuer.test").Scan(&active); err != nil {
		t.Fatalf("count active sessions: %v", err)
	}
	if active > maxSessions {
		t.Fatalf("active sessions %d exceeds cap %d (session-limit enforcement raced)", active, maxSessions)
	}
}
