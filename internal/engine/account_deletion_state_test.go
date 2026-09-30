package engine

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/config"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/riverqueue/river"
	"github.com/stretchr/testify/require"
)

func TestAccountDeletionGenerationOrderingAndFinalization(t *testing.T) {
	pg := testdb.EmptyScratchPostgres(t)
	require.NoError(t, Migrate(t.Context(), pg.Pool, config.Config{}, config.MigrateOptions{}))
	cfgPool := pg.Pool.Config().Copy()
	cfgPool.MaxConns = 1
	pool, err := pgxpool.NewWithConfig(t.Context(), cfgPool)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	cfg := maintenanceConfig()
	var runtime *Engine
	var mu sync.Mutex
	var events []string
	record := func(entry string) {
		mu.Lock()
		defer mu.Unlock()
		events = append(events, entry)
	}
	// A hook may reenter the same one-slot AuthKit pool. It must execute
	// outside the mutation and delivery transactions.
	observe := func(ctx context.Context, entry, userID string) error {
		user, err := runtime.getUserByID(ctx, userID)
		if err != nil {
			return err
		}
		if user == nil {
			return errors.New("identity purged before its callback")
		}
		record(entry)
		return nil
	}
	runtime, err = New(context.Background(), cfg, config.Deps{
		Postgres: pool,
		OnEvent: func(ctx context.Context, e iam.Event) error {
			if e.Kind == iam.EventUserPurged {
				record(string(e.Kind))
				return nil
			}
			return observe(ctx, string(e.Kind), e.UserID)
		},
		OnPurge: func(ctx context.Context, d iam.UserDeletion) error { return observe(ctx, "purge:"+d.ID, d.UserID) },
	})
	require.NoError(t, err)
	t.Cleanup(runtime.Close)
	client := runtime
	user, err := client.createUser(t.Context(), "lifecycle@example.test", "lifecycle")
	require.NoError(t, err)
	remove := func() {
		t.Helper()
		results, err := client.DeleteUsers(t.Context(), iam.SystemActor(), []string{user.ID})
		require.NoError(t, err)
		require.NoError(t, results[0].Err)
	}
	current := func() iam.UserDeletion {
		t.Helper()
		var deletion iam.UserDeletion
		require.NoError(t, pg.Pool.QueryRow(t.Context(), "SELECT id::text,user_id::text,deleted_at,purge_at FROM profiles.account_deletions WHERE user_id=$1::uuid AND state='deleted'", user.ID).Scan(&deletion.ID, &deletion.UserID, &deletion.DeletedAt, &deletion.PurgeAt))
		return deletion
	}
	remove()
	first := current()
	require.Equal(t, iam.UserRecoveryPeriod, first.PurgeAt.Sub(first.DeletedAt))
	var scheduled time.Time
	require.NoError(t, pg.Pool.QueryRow(t.Context(), `SELECT scheduled_at FROM public.river_job WHERE kind='authkit_account_finalize' AND args->>'deletion_id'=$1`, first.ID).Scan(&scheduled))
	require.True(t, first.PurgeAt.Equal(scheduled), "each account has its own exact deadline job")
	remove()
	require.Equal(t, first, current(), "repeated deletion must not reset the deadline/generation")
	results, err := client.RestoreUsers(t.Context(), iam.SystemActor(), []string{user.ID})
	require.NoError(t, err)
	require.NoError(t, results[0].Err)
	remove()
	second := current()
	require.NotEqual(t, first.ID, second.ID)
	require.NoError(t, runtime.finalizeAccountDeletion(t.Context(), first.ID, false), "old generation cannot finalize the new deletion")
	err = runtime.finalizeAccountDeletion(t.Context(), second.ID, false)
	var snooze *river.JobSnoozeError
	require.ErrorAs(t, err, &snooze, "the private finalizer also enforces the deadline")
	var deliveries int
	require.NoError(t, pg.Pool.QueryRow(t.Context(), "SELECT count(*) FROM profiles.account_deletion_deliveries WHERE user_id=$1::uuid", user.ID).Scan(&deliveries))
	require.Zero(t, deliveries, "deletion and recovery are events; only the purge has a callback receipt")
	rows, err := pg.Pool.Query(t.Context(), "SELECT id FROM profiles.account_events WHERE user_id=$1::uuid ORDER BY id", user.ID)
	require.NoError(t, err)
	pending, err := pgx.CollectRows(rows, pgx.RowTo[int64])
	require.NoError(t, err)
	require.Len(t, pending, 4, "registered, deleted, restored, deleted")
	require.ErrorAs(t, runtime.deliverEvent(t.Context(), pending[2]), &snooze, "restore waits for the earlier deletion")
	for _, id := range pending {
		require.NoError(t, runtime.deliverEvent(t.Context(), id))
	}
	require.NoError(t, runtime.deliverEvent(t.Context(), pending[1]), "a delivered deletion is never replayed after restore")
	mu.Lock()
	recorded := append([]string(nil), events...)
	mu.Unlock()
	lifecycle := []string{string(iam.EventUserRegistered), string(iam.EventUserDeleted), string(iam.EventUserRestored), string(iam.EventUserDeleted)}
	require.Equal(t, lifecycle, recorded)
	// Advance the stored deadline in this disposable fixture. No production
	// API permits shortening the recovery window.
	tx, err := pg.Pool.Begin(t.Context())
	require.NoError(t, err)
	_, err = tx.Exec(t.Context(), "UPDATE profiles.users SET deleted_at=statement_timestamp()-interval '31 days' WHERE id=$1::uuid", user.ID)
	require.NoError(t, err)
	_, err = tx.Exec(t.Context(), "UPDATE profiles.account_deletions d SET deleted_at=u.deleted_at,purge_at=u.deleted_at+interval '720 hours' FROM profiles.users u WHERE d.id=$1::uuid AND u.id=d.user_id", second.ID)
	require.NoError(t, err)
	require.NoError(t, tx.Commit(t.Context()))
	require.NoError(t, runtime.finalizeAccountDeletion(t.Context(), second.ID, false))
	results, err = client.RestoreUsers(t.Context(), iam.SystemActor(), []string{user.ID})
	require.NoError(t, err)
	require.Error(t, results[0].Err, "finalization cannot be restored after deadline")
	// Run the real River client. Delivered events are receipt-idempotent, then
	// the purge callback commits and schedules the private purge job, whose
	// user.purged event follows.
	require.NoError(t, runtime.Start(t.Context()))
	require.Eventually(t, func() bool {
		var exists bool
		err := pg.Pool.QueryRow(context.Background(), "SELECT EXISTS(SELECT 1 FROM profiles.users WHERE id=$1::uuid)", user.ID).Scan(&exists)
		return err == nil && !exists
	}, 15*time.Second, 25*time.Millisecond)
	want := append(lifecycle, "purge:"+second.ID, string(iam.EventUserPurged))
	require.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(events) >= len(want)
	}, 15*time.Second, 25*time.Millisecond)
	mu.Lock()
	recorded = append([]string(nil), events...)
	mu.Unlock()
	require.Equal(t, want, recorded)
	require.NoError(t, pool.Ping(t.Context()), "host pool remains owned by the caller")
}

func TestAccountFinalizationPreservesForeignKeysAndCascadesMemberships(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	cfg := maintenanceConfig()
	roles := config.NewRoles()
	roles.Root.Role("member")
	cfg.Roles = roles
	runtime, err := New(context.Background(), cfg, config.Deps{Postgres: pg.Pool})
	require.NoError(t, err)
	t.Cleanup(runtime.Close)
	client := runtime
	user, err := client.createUser(t.Context(), "finalize-fk@example.test", "finalizefk")
	require.NoError(t, err)
	grantRole(t, client, iam.RootGroup(), iam.UserSubject(user.ID), "member")
	_, err = pg.Pool.Exec(t.Context(), "CREATE TABLE public.host_reference(user_id uuid REFERENCES profiles.users(id))")
	require.NoError(t, err)
	_, err = pg.Pool.Exec(t.Context(), "INSERT INTO public.host_reference VALUES ($1::uuid)", user.ID)
	require.NoError(t, err)
	generation := prepareExpiredDeletion(t, runtime, user.ID)
	require.ErrorIs(t, runtime.finalizeAccountDeletion(t.Context(), generation, true), errmodel.ErrUserReferenced)
	var count int
	require.NoError(t, pg.Pool.QueryRow(t.Context(), "SELECT count(*) FROM profiles.group_user_roles WHERE user_id=$1::uuid", user.ID).Scan(&count))
	require.Equal(t, 1, count, "failed purge rolls back every cascade")
	_, err = pg.Pool.Exec(t.Context(), "DELETE FROM public.host_reference WHERE user_id=$1::uuid", user.ID)
	require.NoError(t, err)
	require.NoError(t, runtime.finalizeAccountDeletion(t.Context(), generation, true))
	require.NoError(t, pg.Pool.QueryRow(t.Context(), "SELECT count(*) FROM profiles.group_user_roles WHERE user_id=$1::uuid", user.ID).Scan(&count))
	require.Zero(t, count)
	require.NoError(t, pg.Pool.QueryRow(t.Context(), "SELECT count(*) FROM profiles.users WHERE id=$1::uuid", user.ID).Scan(&count))
	require.Zero(t, count)
}

// TestAccountPurgeSweepsCredentialsBeforeTheRowGoes (H1): PurgeUsers is the
// system's; it closes the recovery window at once, and once the row goes no
// key the account issued is live, including one no earlier sweep saw.
func TestAccountPurgeSweepsCredentialsBeforeTheRowGoes(t *testing.T) {
	pg := testdb.EmptyScratchPostgres(t)
	require.NoError(t, Migrate(t.Context(), pg.Pool, config.Config{}, config.MigrateOptions{}))
	runtime, err := New(context.Background(), maintenanceConfig(), config.Deps{Postgres: pg.Pool})
	require.NoError(t, err)
	t.Cleanup(runtime.Close)
	ctx := t.Context()
	user, err := runtime.createUser(ctx, "purged@example.test", "purgeduser")
	require.NoError(t, err)
	var rootID string
	require.NoError(t, runtime.withAuthorityMutation(ctx, iam.SystemActor(), func(st *permissionGroupStore) error {
		rootID, err = runtime.rootGroup(ctx, st)
		return err
	}))
	key := func(name string) string {
		t.Helper()
		var id string
		require.NoError(t, pg.Pool.QueryRow(ctx, `INSERT INTO profiles.api_keys (permission_group_id,key_id,secret_hash,name,created_by,role)
 VALUES ($1::uuid,$2,'\x00'::bytea,$2,$3::uuid,'root:owner') RETURNING id::text`, rootID, name+"-"+user.ID[:8], user.ID).Scan(&id))
		return id
	}
	revoked := func(id string) bool {
		t.Helper()
		var live bool
		require.NoError(t, pg.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM profiles.api_keys WHERE id=$1::uuid AND revoked_at IS NULL)`, id).Scan(&live))
		return !live
	}
	issued := key("issued")

	require.NoError(t, itemErr(runtime.PurgeUsers(ctx, []string{user.ID})))
	require.True(t, revoked(issued), "the soft delete sweeps the account's keys")
	restore, err := runtime.RestoreUsers(ctx, iam.SystemActor(), []string{user.ID})
	require.NoError(t, err)
	require.Error(t, restore[0].Err, "a purge closes the recovery window")

	// A key no sweep has seen: only the purge-time sweep can revoke it.
	leftover := key("leftover")
	require.NoError(t, runtime.Start(ctx))
	require.Eventually(t, func() bool {
		var exists bool
		err := pg.Pool.QueryRow(context.Background(), "SELECT EXISTS(SELECT 1 FROM profiles.users WHERE id=$1::uuid)", user.ID).Scan(&exists)
		return err == nil && !exists
	}, 15*time.Second, 25*time.Millisecond)
	require.True(t, revoked(leftover), "purge left a live key with no creator")
	var live int
	require.NoError(t, pg.Pool.QueryRow(ctx, `SELECT count(*) FROM profiles.api_keys WHERE created_by IS NULL AND revoked_at IS NULL`).Scan(&live))
	require.Zero(t, live)
}

func TestAccountRecoveryAndFinalizerSerializeAtDeadline(t *testing.T) {
	for _, expired := range []bool{false, true} {
		name := "recoverable"
		if expired {
			name = "expired"
		}
		t.Run(name, func(t *testing.T) {
			pg := testdb.ScratchPostgres(t)
			runtime, err := New(context.Background(), maintenanceConfig(), config.Deps{Postgres: pg.Pool})
			require.NoError(t, err)
			t.Cleanup(runtime.Close)
			user, err := runtime.createUser(t.Context(), name+"@example.test", name)
			require.NoError(t, err)
			require.NoError(t, runtime.softDelete(t.Context(), user.ID))
			var generation string
			require.NoError(t, pg.Pool.QueryRow(t.Context(), "SELECT id::text FROM profiles.account_deletions WHERE user_id=$1::uuid", user.ID).Scan(&generation))
			if expired {
				_, err = pg.Pool.Exec(t.Context(), "UPDATE profiles.users SET deleted_at=statement_timestamp()-interval '31 days' WHERE id=$1::uuid", user.ID)
				require.NoError(t, err)
				_, err = pg.Pool.Exec(t.Context(), `UPDATE profiles.account_deletions d SET deleted_at=u.deleted_at,purge_at=u.deleted_at+interval '720 hours'
 FROM profiles.users u WHERE d.id=$1::uuid AND d.user_id=u.id`, generation)
				require.NoError(t, err)
			}
			start := make(chan struct{})
			var restoreErr, finalizeErr error
			var wg sync.WaitGroup
			wg.Go(func() {
				<-start
				restoreErr = itemErr(runtime.RestoreUsers(t.Context(), iam.SystemActor(), []string{user.ID}))
			})
			wg.Go(func() {
				<-start
				finalizeErr = runtime.finalizeAccountDeletion(t.Context(), generation, false)
			})
			close(start)
			wg.Wait()
			var state string
			require.NoError(t, pg.Pool.QueryRow(t.Context(), "SELECT state FROM profiles.account_deletions WHERE id=$1::uuid", generation).Scan(&state))
			if expired {
				require.ErrorIs(t, restoreErr, errmodel.E(errmodel.CodeAccountRecoveryExpired))
				require.NoError(t, finalizeErr)
				require.Equal(t, "finalizing", state)
			} else {
				require.NoError(t, restoreErr)
				if finalizeErr != nil {
					var snooze *river.JobSnoozeError
					require.ErrorAs(t, finalizeErr, &snooze)
				}
				require.Equal(t, "restored", state)
				var hard int
				require.NoError(t, pg.Pool.QueryRow(t.Context(), "SELECT count(*) FROM profiles.account_deletion_deliveries WHERE deletion_id=$1::uuid AND stage='hard'", generation).Scan(&hard))
				require.Zero(t, hard, "an early finalizer cannot dispatch irreversible host cleanup")
			}
		})
	}
}
