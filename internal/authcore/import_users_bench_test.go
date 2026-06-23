package authcore

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/open-rails/authkit/internal/db"
)

// TestImportUsers_Benchmark is a throughput probe (not a unit test). It runs only
// when AUTHKIT_IMPORT_BENCH is set, imports N synthetic users (default 100k,
// override with AUTHKIT_IMPORT_BENCH_N), reports users/sec, then deletes them.
// Needs AUTHKIT_TEST_DATABASE_URL (via testPG).
func TestImportUsers_Benchmark(t *testing.T) {
	if os.Getenv("AUTHKIT_IMPORT_BENCH") == "" {
		t.Skip("set AUTHKIT_IMPORT_BENCH=1 to run the bulk-import throughput probe")
	}
	svc, ctx := importTestService(t)

	n := 100000
	if v := os.Getenv("AUTHKIT_IMPORT_BENCH_N"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 {
			n = parsed
		}
	}
	withPW := os.Getenv("AUTHKIT_IMPORT_BENCH_PW") != "" // also import a password hash per user

	prefix := fmt.Sprintf("b%06d", time.Now().UnixNano()%1_000_000)
	t.Cleanup(func() {
		_, _ = svc.pg.Exec(context.Background(),
			db.RewriteSQL("DELETE FROM profiles.user_passwords WHERE user_id IN (SELECT id FROM profiles.users WHERE username LIKE $1)", svc.dbSchema()), prefix+"%")
		del, _ := svc.pg.Exec(context.Background(),
			db.RewriteSQL("DELETE FROM profiles.users WHERE username LIKE $1", svc.dbSchema()), prefix+"%")
		t.Logf("cleanup: deleted %d benchmark users", del.RowsAffected())
	})

	// A single fixed argon2id hash reused across rows (we're timing the DB load,
	// not hashing).
	const fixedArgon2id = "$argon2id$v=19$m=65536,t=1,p=4$YWJjZGVmZ2hpamtsbW5vcA$3hf8m0Yx9m1q2r3s4t5u6v7w8x9y0z1a2b3c4d5e6f8"

	inputs := make([]ImportUserInput, n)
	for i := range inputs {
		in := ImportUserInput{
			Username: fmt.Sprintf("%su%d", prefix, i),
			Email:    fmt.Sprintf("%su%d@example.com", prefix, i),
		}
		if withPW {
			in.PasswordHash = fixedArgon2id
			in.HashAlgo = "argon2id"
		}
		inputs[i] = in
	}

	start := time.Now()
	res, err := svc.ImportUsers(ctx, inputs)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("ImportUsers(%d): %v", n, err)
	}
	rate := float64(res.Inserted) / elapsed.Seconds()
	t.Logf("ImportUsers: %d users (pw=%v) -> inserted=%d skipped=%d rejected=%d in %s = %.0f users/sec",
		n, withPW, res.Inserted, res.Skipped, res.Rejected, elapsed.Round(time.Millisecond), rate)
	if res.Inserted != n {
		t.Fatalf("inserted %d, want %d", res.Inserted, n)
	}
}
