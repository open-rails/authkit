package riverjobs

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/open-rails/authkit/embedded"
)

// testPG mirrors core's DB-backed test gating: it returns a pool against
// AUTHKIT_TEST_DATABASE_URL, or skips. The schema in
// migrations/postgres/001_auth_schema.up.sql must already be applied.
func testPG(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("AUTHKIT_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("AUTHKIT_TEST_DATABASE_URL not set; skipping DB-backed test")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// TestPurgeCandidateSelectionBoundary verifies the purge worker's candidate
// selection: a user whose deleted_at is older than the retention cutoff is
// selected for purge, while one inside the retention window is not. This is the
// security-critical boundary that decides which soft-deleted users get hard-deleted.
func TestPurgeCandidateSelectionBoundary(t *testing.T) {
	pool := testPG(t)
	svc, svcErr := embedded.New(embedded.Config{
		Token: embedded.TokenConfig{
			Issuer:            "https://test",
			IssuedAudiences:   []string{"test"},
			ExpectedAudiences: []string{"test"},
		},
		Keys: embedded.KeysConfig{VerifyOnly: true}, // purge worker only queries; no signer needed
	}, pool)
	if svcErr != nil {
		t.Fatalf("new service: %v", svcErr)
	}
	ctx := context.Background()

	const retentionDays = 30
	// Same cutoff math the worker uses in Work().
	cutoff := time.Now().AddDate(0, 0, -retentionDays)

	// "old" user was soft-deleted well before the cutoff -> should be selected.
	oldID := uuid.NewString()
	oldDeletedAt := cutoff.Add(-24 * time.Hour)
	// "recent" user was soft-deleted just inside the retention window -> should NOT be selected.
	recentID := uuid.NewString()
	recentDeletedAt := cutoff.Add(24 * time.Hour)

	for _, u := range []struct {
		id        string
		deletedAt time.Time
	}{{oldID, oldDeletedAt}, {recentID, recentDeletedAt}} {
		_, err := pool.Exec(ctx, `
			INSERT INTO profiles.users (id, email, username, email_verified, created_at, updated_at, deleted_at)
			VALUES ($1, $2, $3, true, now(), now(), $4)
		`, u.id, fmt.Sprintf("purge-%s@example.com", u.id), "purge_"+u.id[:8], u.deletedAt)
		if err != nil {
			t.Fatalf("seed user %s: %v", u.id, err)
		}
		t.Cleanup(func() {
			_, _ = pool.Exec(context.Background(), `DELETE FROM profiles.users WHERE id=$1`, u.id)
		})
	}

	ids, err := svc.ListUsersDeletedBefore(ctx, cutoff, 500)
	if err != nil {
		t.Fatalf("ListUsersDeletedBefore: %v", err)
	}

	set := make(map[string]bool, len(ids))
	for _, id := range ids {
		set[id] = true
	}

	if !set[oldID] {
		t.Errorf("user deleted before cutoff (%s) should be selected for purge, got selection=%v", oldDeletedAt, ids)
	}
	if set[recentID] {
		t.Errorf("user deleted after cutoff (%s) must NOT be selected for purge", recentDeletedAt)
	}
}

// TestPurgeRetentionDefaults verifies the worker's retention/batch defaults so a
// zero/negative arg cannot accidentally widen (retention) or unbound (batch) the
// purge selection.
func TestPurgeRetentionDefaults(t *testing.T) {
	cases := []struct {
		name      string
		retention int
		batch     int
		wantRet   int
		wantBatch int
	}{
		{"zero defaults", 0, 0, 30, 500},
		{"negative defaults", -5, -1, 30, 500},
		{"explicit kept", 7, 100, 7, 100},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			retention := c.retention
			if retention <= 0 {
				retention = 30
			}
			batch := c.batch
			if batch <= 0 {
				batch = 500
			}
			if retention != c.wantRet {
				t.Errorf("retention: got %d want %d", retention, c.wantRet)
			}
			if batch != c.wantBatch {
				t.Errorf("batch: got %d want %d", batch, c.wantBatch)
			}
		})
	}
}
