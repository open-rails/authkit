package riverjobs

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/open-rails/authkit/embedded"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/riverqueue/river"
)

// purgeFixture seeds soft-deleted users with their erasure obligations by SQL
// (this module compiles against the published root, so it drives only the
// worker's own entry points) and reports the store's state.
type purgeFixture struct {
	t    *testing.T
	pool interface {
		Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
		QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	}
}

func newPurgeService(t *testing.T, pool *pgxpool.Pool, issuer string) *embedded.Client {
	t.Helper()
	svc, err := embedded.New(embedded.Config{
		Token: embedded.TokenConfig{
			Issuer:            issuer,
			IssuedAudiences:   []string{"test"},
			ExpectedAudiences: []string{"test"},
		},
		Keys:      embedded.KeysConfig{VerifyOnly: true}, // purge worker only queries; no signer needed
		Ephemeral: embedded.EphemeralConfig{AllowMemory: true},
	}, embedded.Deps{Postgres: pool})
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	return svc
}

// deletedUser seeds a soft-deleted user owed to issuers; acked marks which of
// them already acknowledged.
func (f purgeFixture) deletedUser(tag string, deletedAt time.Time, issuers []string, acked ...string) string {
	f.t.Helper()
	ctx := context.Background()
	id := uuid.NewString()
	if _, err := f.pool.Exec(ctx, `
		INSERT INTO profiles.users (id, email, username, email_verified, created_at, updated_at, deleted_at)
		VALUES ($1, $2, $3, true, now(), now(), $4)`, id, fmt.Sprintf("purge-%s@example.com", id), "purge_"+tag+"_"+id[:8], deletedAt); err != nil {
		f.t.Fatalf("seed user %s: %v", tag, err)
	}
	f.t.Cleanup(func() {
		_, _ = f.pool.Exec(context.Background(), `DELETE FROM profiles.users WHERE id=$1::uuid`, id)
		_, _ = f.pool.Exec(context.Background(), `DELETE FROM profiles.account_erasure_obligations WHERE user_id=$1::uuid`, id)
	})
	if _, err := f.pool.Exec(ctx, `INSERT INTO profiles.account_erasure_obligations (user_id, email, created_at, pending_sites)
		SELECT id, email, $2, $3 FROM profiles.users WHERE id=$1::uuid`, id, deletedAt, len(issuers)); err != nil {
		f.t.Fatalf("seed obligation %s: %v", tag, err)
	}
	for _, issuer := range issuers {
		if _, err := f.pool.Exec(ctx, `INSERT INTO profiles.account_erasure_acknowledgements (user_id, issuer, obligation_created_at) VALUES ($1::uuid, $2, $3)`, id, issuer, deletedAt); err != nil {
			f.t.Fatalf("seed acknowledgement %s: %v", tag, err)
		}
	}
	for _, issuer := range acked {
		f.acknowledge(id, issuer)
	}
	return id
}

func (f purgeFixture) acknowledge(id, issuer string) {
	f.t.Helper()
	if _, err := f.pool.Exec(context.Background(), `UPDATE profiles.account_erasure_acknowledgements SET acknowledged_at=now() WHERE user_id=$1::uuid AND issuer=$2`, id, issuer); err != nil {
		f.t.Fatalf("acknowledge %s: %v", issuer, err)
	}
	if _, err := f.pool.Exec(context.Background(), `UPDATE profiles.account_erasure_obligations o SET pending_sites=(
		SELECT count(*) FROM profiles.account_erasure_acknowledgements a WHERE a.user_id=o.user_id AND a.acknowledged_at IS NULL)
		WHERE o.user_id=$1::uuid`, id); err != nil {
		f.t.Fatalf("refresh pending: %v", err)
	}
}

func (f purgeFixture) count(table, column, id string) int {
	f.t.Helper()
	var n int
	if err := f.pool.QueryRow(context.Background(), `SELECT count(*) FROM profiles.`+table+` WHERE `+column+`=$1::uuid`, id).Scan(&n); err != nil {
		f.t.Fatal(err)
	}
	return n
}

// TestPurgeCandidateSelectionBoundary verifies the purge worker's candidate
// selection: a user whose deleted_at is older than the retention cutoff is
// selected for purge, one inside the retention window is not, and an old
// deletion an account issuer has not acknowledged yet is retained. This is the
// security-critical boundary that decides which soft-deleted users get
// hard-deleted.
func TestPurgeCandidateSelectionBoundary(t *testing.T) {
	pool := testdb.Pool(t)
	ctx := context.Background()
	svc := newPurgeService(t, pool, "https://test")
	f := purgeFixture{t: t, pool: pool}
	sites := []string{"https://test"}

	const retentionDays = 30
	// Same cutoff math the worker uses in Work().
	cutoff := time.Now().AddDate(0, 0, -retentionDays)

	// "old" user was soft-deleted well before the cutoff -> should be selected.
	oldID := f.deletedUser("old", cutoff.Add(-24*time.Hour), sites, sites...)
	// "recent" user was soft-deleted just inside the retention window -> should NOT be selected.
	recentID := f.deletedUser("recent", cutoff.Add(24*time.Hour), sites, sites...)
	// "owed" user is old but its erasure obligation is still unacknowledged.
	owedID := f.deletedUser("owed", cutoff.Add(-48*time.Hour), sites)

	ids, err := svc.ListUsersDeletedBefore(ctx, cutoff, 500)
	if err != nil {
		t.Fatalf("ListUsersDeletedBefore: %v", err)
	}

	set := make(map[string]bool, len(ids))
	for _, id := range ids {
		set[id] = true
	}

	if !set[oldID] {
		t.Errorf("user deleted before cutoff should be selected for purge, got selection=%v", ids)
	}
	if set[recentID] {
		t.Errorf("user deleted after cutoff must NOT be selected for purge")
	}
	if set[owedID] {
		t.Errorf("user with an unacknowledged erasure obligation must NOT be selected for purge")
	}
}

// TestPurgeWorkerHonoursErasureAcknowledgements drives the real worker over a
// store shared by two account issuers: only accounts both acknowledged are
// purged, the host hook runs for those alone, and the rest are purged once the
// other site acknowledges.
func TestPurgeWorkerHonoursErasureAcknowledgements(t *testing.T) {
	pool := testdb.Pool(t)
	ctx := context.Background()
	siteA, siteB := "https://purge-a.test", "https://purge-b.test"
	svc := newPurgeService(t, pool, siteA)
	f := purgeFixture{t: t, pool: pool}
	sites := []string{siteA, siteB}
	old := time.Now().AddDate(0, 0, -40)
	settled := f.deletedUser("settled", old, sites, siteA, siteB)
	pending := f.deletedUser("pending", old, sites, siteA)

	var hooked []string
	worker := newPurgeDeletedUsersWorker(svc, func(_ context.Context, userID string) error {
		hooked = append(hooked, userID)
		return nil
	})
	job := &river.Job[PurgeDeletedUsersArgs]{Args: PurgeDeletedUsersArgs{RetentionDays: 30, BatchSize: 10}}
	if err := worker.Work(ctx, job); err != nil {
		t.Fatalf("work: %v", err)
	}
	if len(hooked) != 1 || hooked[0] != settled {
		t.Fatalf("hook ran for %v, want only %s", hooked, settled)
	}
	if f.count("users", "id", settled) != 0 {
		t.Fatal("fully acknowledged user must be purged")
	}
	if f.count("account_erasure_obligations", "user_id", settled) != 0 {
		t.Fatal("purged and acknowledged obligation must be closed")
	}
	if f.count("users", "id", pending) != 1 {
		t.Fatal("user owed to site B must be retained")
	}

	f.acknowledge(pending, siteB)
	if err := worker.Work(ctx, job); err != nil {
		t.Fatalf("work: %v", err)
	}
	if f.count("users", "id", pending) != 0 || f.count("account_erasure_obligations", "user_id", pending) != 0 {
		t.Fatal("user must be purged and its obligation closed once site B acknowledged")
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
