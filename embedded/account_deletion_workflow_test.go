package embedded

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/riverqueue/river"
	"github.com/stretchr/testify/require"
)

func TestAccountDeletionGenerationOrderingAndFinalization(t *testing.T) {
	pg := testdb.EmptyScratchPostgres(t)
	require.NoError(t, ApplyMigrations(t.Context(), pg.Pool, ""))
	cfgPool := pg.Pool.Config().Copy()
	cfgPool.MaxConns = 1
	pool, err := pgxpool.NewWithConfig(t.Context(), cfgPool)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	cfg := maintenanceConfig()
	var runtime *Runtime
	var mu sync.Mutex
	var events []string
	hook := func(stage string) func(context.Context, authkit.UserDeletion) error {
		return func(ctx context.Context, deletion authkit.UserDeletion) error {
			// A callback may reenter the same one-slot AuthKit pool. It must
			// execute outside the mutation/delivery receipt transaction.
			user, err := runtime.Client().AdminGetUser(ctx, deletion.UserID)
			if err != nil {
				return err
			}
			if user == nil {
				return errors.New("identity purged before finalization callback")
			}
			mu.Lock()
			events = append(events, stage+":"+deletion.ID)
			mu.Unlock()
			return nil
		}
	}
	runtime, err = New(cfg, Deps{Postgres: pool, OnSoftDelete: hook("soft"), OnRestore: hook("restore"), OnHardDelete: hook("hard")})
	require.NoError(t, err)
	t.Cleanup(runtime.Close)
	client := runtime.Client()
	user, err := client.CreateUser(t.Context(), "lifecycle@example.test", "lifecycle")
	require.NoError(t, err)
	remove := func() {
		t.Helper()
		results, err := client.SoftDeleteUsers(t.Context(), []string{user.ID})
		require.NoError(t, err)
		require.NoError(t, results[0].Err)
	}
	current := func() authkit.UserDeletion {
		t.Helper()
		var deletion authkit.UserDeletion
		require.NoError(t, pg.Pool.QueryRow(t.Context(), "SELECT id::text,user_id::text,deleted_at,purge_at FROM profiles.account_deletions WHERE user_id=$1::uuid AND state='deleted'", user.ID).Scan(&deletion.ID, &deletion.UserID, &deletion.DeletedAt, &deletion.PurgeAt))
		return deletion
	}
	remove()
	first := current()
	require.Equal(t, authkit.UserRecoveryPeriod, first.PurgeAt.Sub(first.DeletedAt))
	var scheduled time.Time
	require.NoError(t, pg.Pool.QueryRow(t.Context(), `SELECT scheduled_at FROM public.river_job WHERE kind='authkit_account_finalize' AND args->>'deletion_id'=$1`, first.ID).Scan(&scheduled))
	require.True(t, first.PurgeAt.Equal(scheduled), "each account has its own exact deadline job")
	remove()
	require.Equal(t, first, current(), "repeated deletion must not reset the deadline/generation")
	results, err := client.OperatorRestoreUsers(t.Context(), []string{user.ID})
	require.NoError(t, err)
	require.NoError(t, results[0].Err)
	remove()
	second := current()
	require.NotEqual(t, first.ID, second.ID)
	require.NoError(t, runtime.engine.finalizeAccountDeletion(t.Context(), first.ID, false), "old generation cannot finalize the new deletion")
	err = runtime.engine.finalizeAccountDeletion(t.Context(), second.ID, false)
	var snooze *river.JobSnoozeError
	require.ErrorAs(t, err, &snooze, "the private finalizer also enforces the deadline")
	var deliveries []int64
	rows, err := pg.Pool.Query(t.Context(), "SELECT id FROM profiles.account_deletion_deliveries WHERE user_id=$1::uuid ORDER BY id", user.ID)
	require.NoError(t, err)
	deliveries, err = pgx.CollectRows(rows, pgx.RowTo[int64])
	require.NoError(t, err)
	require.Len(t, deliveries, 3)
	require.ErrorAs(t, runtime.engine.deliverAccountEvent(t.Context(), deliveries[1]), &snooze, "restore waits for earlier soft callback")
	for _, id := range deliveries {
		require.NoError(t, runtime.engine.deliverAccountEvent(t.Context(), id))
	}
	require.NoError(t, runtime.engine.deliverAccountEvent(t.Context(), deliveries[0]), "a completed old soft callback is never replayed after restore")
	mu.Lock()
	recorded := append([]string(nil), events...)
	mu.Unlock()
	require.Equal(t, []string{"soft:" + first.ID, "restore:" + first.ID, "soft:" + second.ID}, recorded)
	// Advance the stored deadline in this disposable fixture. No production
	// API permits shortening the recovery window.
	tx, err := pg.Pool.Begin(t.Context())
	require.NoError(t, err)
	_, err = tx.Exec(t.Context(), "UPDATE profiles.users SET deleted_at=statement_timestamp()-interval '31 days' WHERE id=$1::uuid", user.ID)
	require.NoError(t, err)
	_, err = tx.Exec(t.Context(), "UPDATE profiles.account_deletions d SET deleted_at=u.deleted_at,purge_at=u.deleted_at+interval '720 hours' FROM profiles.users u WHERE d.id=$1::uuid AND u.id=d.user_id", second.ID)
	require.NoError(t, err)
	require.NoError(t, tx.Commit(t.Context()))
	require.NoError(t, runtime.engine.finalizeAccountDeletion(t.Context(), second.ID, false))
	results, err = client.OperatorRestoreUsers(t.Context(), []string{user.ID})
	require.NoError(t, err)
	require.Error(t, results[0].Err, "finalization cannot be restored after deadline")
	// Run the real River client. Prior callbacks are receipt-idempotent, then
	// hard cleanup commits and schedules the private purge job.
	require.NoError(t, runtime.Start(t.Context()))
	require.Eventually(t, func() bool {
		var exists bool
		err := pg.Pool.QueryRow(context.Background(), "SELECT EXISTS(SELECT 1 FROM profiles.users WHERE id=$1::uuid)", user.ID).Scan(&exists)
		return err == nil && !exists
	}, 15*time.Second, 25*time.Millisecond)
	mu.Lock()
	recorded = append([]string(nil), events...)
	mu.Unlock()
	require.Equal(t, []string{"soft:" + first.ID, "restore:" + first.ID, "soft:" + second.ID, "hard:" + second.ID}, recorded)
	require.NoError(t, pool.Ping(t.Context()), "host pool remains owned by the caller")
}

func TestAccountDeletionRollsBackWhenRiverInsertFails(t *testing.T) {
	pg := testdb.EmptyScratchPostgres(t)
	require.NoError(t, ApplyMigrations(t.Context(), pg.Pool, ""))
	cfg := maintenanceConfig()
	cfg.River.Schema = "uninitialized_jobs"
	runtime, err := New(cfg, Deps{Postgres: pg.Pool})
	require.NoError(t, err)
	t.Cleanup(runtime.Close)
	user, err := runtime.Client().CreateUser(t.Context(), "rollback@example.test", "rollback")
	require.NoError(t, err)
	results, err := runtime.Client().SoftDeleteUsers(t.Context(), []string{user.ID})
	require.NoError(t, err)
	require.Error(t, results[0].Err)
	var deleted *time.Time
	var cycles int
	require.NoError(t, pg.Pool.QueryRow(t.Context(), "SELECT deleted_at FROM profiles.users WHERE id=$1::uuid", user.ID).Scan(&deleted))
	require.Nil(t, deleted, "a deletion without its durable job must not commit")
	require.NoError(t, pg.Pool.QueryRow(t.Context(), "SELECT count(*) FROM profiles.account_deletions WHERE user_id=$1::uuid", user.ID).Scan(&cycles))
	require.Zero(t, cycles)
}
