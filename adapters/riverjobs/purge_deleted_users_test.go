package riverjobs

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/open-rails/authkit/embedded"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/riverqueue/river"
)

// testPG mirrors core's DB-backed test gating: it returns a pool against
// AUTHKIT_TEST_DATABASE_URL, or skips. The schema in
// migrations/postgres/0001_auth_schema.up.sql must already be applied.
func testPG(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := testdb.URL(t)
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

// TestPurgeInsertOptsQueue verifies queue routing (#246): InsertOpts() must
// never fall back to river.QueueDefault, and a host-supplied Args.Queue must
// be honored. authkit pinning its jobs to the shared `default` queue would
// poison any deployment where the host also runs its own River workers on
// `default` (River fetches by queue name only; a client that pulls a kind it
// has no worker for burns a failed attempt).
func TestPurgeInsertOptsQueue(t *testing.T) {
	if DefaultQueue == river.QueueDefault {
		t.Fatalf("DefaultQueue must never equal river.QueueDefault")
	}

	cases := []struct {
		name      string
		queue     string
		wantQueue string
	}{
		{"blank Queue falls back to DefaultQueue", "", DefaultQueue},
		{"explicit Queue overrides DefaultQueue", "host-custom-queue", "host-custom-queue"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			args := PurgeDeletedUsersArgs{RetentionDays: 30, BatchSize: 500, Queue: c.queue}
			opts := args.InsertOpts()
			if opts.Queue != c.wantQueue {
				t.Errorf("queue: got %q want %q", opts.Queue, c.wantQueue)
			}
			// Queue is routing-only: it must never leak into the persisted
			// job args, or it would perturb the ByArgs uniqueness hash.
			if opts.UniqueOpts.ByArgs != true || opts.UniqueOpts.ByQueue != true {
				t.Errorf("UniqueOpts regressed: got %+v", opts.UniqueOpts)
			}
		})
	}

	// Queue must be excluded from the persisted job args (json:"-"): it's a
	// routing concern, not job data, and must not perturb the ByArgs hash.
	raw, err := json.Marshal(PurgeDeletedUsersArgs{RetentionDays: 30, BatchSize: 500, Queue: "host-custom-queue"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(raw), "host-custom-queue") || strings.Contains(string(raw), "queue") {
		t.Errorf("Queue leaked into persisted job args: %s", raw)
	}
}
