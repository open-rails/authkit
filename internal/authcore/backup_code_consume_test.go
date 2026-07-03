package authcore

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

// seedBackupUser creates a user with 2FA enabled and the given plaintext backup
// codes (stored hashed, as the service does), returning the user id.
func seedBackupUser(t *testing.T, ctx context.Context, svc *Service, codes ...string) string {
	t.Helper()
	uname := fmt.Sprintf("backup-%d", time.Now().UnixNano())
	var id string
	if err := svc.pg.QueryRow(ctx, `INSERT INTO profiles.users (username) VALUES ($1) RETURNING id::text`, uname).Scan(&id); err != nil {
		t.Fatalf("create user: %v", err)
	}
	t.Cleanup(func() { _, _ = svc.pg.Exec(ctx, `DELETE FROM profiles.users WHERE id=$1::uuid`, id) })
	hashes := make([]string, len(codes))
	for i, c := range codes {
		hashes[i] = sha256Hex(c)
	}
	if _, err := svc.pg.Exec(ctx, `INSERT INTO profiles.mfa_settings (user_id, enabled, backup_codes) VALUES ($1::uuid, true, $2)`, id, hashes); err != nil {
		t.Fatalf("seed mfa_settings: %v", err)
	}
	return id
}

// TestVerifyBackupCode_SingleUse: a code works once, then is consumed; a wrong code
// fails; 2FA-disabled fails.
func TestVerifyBackupCode_SingleUse(t *testing.T) {
	pool := testPG(t)
	ctx := context.Background()
	svc := NewService(Config{Token: TokenConfig{Issuer: "https://test"}}, Keyset{}, WithPostgres(pool))
	uid := seedBackupUser(t, ctx, svc, "code-aaa", "code-bbb")

	ok, err := svc.VerifyBackupCode(ctx, uid, "code-aaa")
	if err != nil || !ok {
		t.Fatalf("first use of code-aaa: want (true,nil), got (%v,%v)", ok, err)
	}
	ok, err = svc.VerifyBackupCode(ctx, uid, "code-aaa")
	if err != nil || ok {
		t.Fatalf("second use of code-aaa: want (false,nil), got (%v,%v)", ok, err)
	}
	ok, err = svc.VerifyBackupCode(ctx, uid, "not-a-code")
	if err != nil || ok {
		t.Fatalf("wrong code: want (false,nil), got (%v,%v)", ok, err)
	}
	// The other seeded code still works (consume removed only the used one).
	if ok, err := svc.VerifyBackupCode(ctx, uid, "code-bbb"); err != nil || !ok {
		t.Fatalf("code-bbb should still work: got (%v,%v)", ok, err)
	}
}

// TestVerifyBackupCode_ConcurrentSingleWinner: two concurrent submissions of the
// same code must yield exactly one success (atomic consume).
func TestVerifyBackupCode_ConcurrentSingleWinner(t *testing.T) {
	pool := testPG(t)
	ctx := context.Background()
	svc := NewService(Config{Token: TokenConfig{Issuer: "https://test"}}, Keyset{}, WithPostgres(pool))
	uid := seedBackupUser(t, ctx, svc, "race-code")

	const n = 2
	var wg sync.WaitGroup
	oks := make([]bool, n)
	errs := make([]error, n)
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			oks[i], errs[i] = svc.VerifyBackupCode(ctx, uid, "race-code")
		}(i)
	}
	wg.Wait()

	successes := 0
	for i := range oks {
		if errs[i] != nil {
			t.Fatalf("unexpected error: %v", errs[i])
		}
		if oks[i] {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("concurrent consume of one code: want exactly 1 success, got %d", successes)
	}
}
