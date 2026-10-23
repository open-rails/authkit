package engine

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/config"
	"github.com/open-rails/authkit/internal/db"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"
	"github.com/stretchr/testify/require"
)

func TestAccountDeletionDailySweepSeparatesDueAndRecoverable(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	e, err := New(t.Context(), maintenanceConfig(), config.Deps{Postgres: pg.Pool})
	require.NoError(t, err)
	t.Cleanup(func() { _ = e.Close(context.Background()) })
	due := newUser(t, e, "duetoday")
	future := newUser(t, e, "duelater")
	dueID := expireDeletion(t, e, due.ID)
	require.NoError(t, e.softDelete(t.Context(), future.ID))
	require.NoError(t, e.deleteDueAccounts(t.Context()))
	var state string
	require.NoError(t, e.pg.QueryRow(t.Context(), `SELECT state FROM account_deletions WHERE id=$1`, dueID).Scan(&state))
	require.Equal(t, "purged", state, "the same due pass completes local no-op cleanup")
	var deliveries, timers int
	require.NoError(t, e.pg.QueryRow(t.Context(), `SELECT count(*) FROM account_deletion_deliveries WHERE user_id=$1`, future.ID).Scan(&deliveries))
	require.Zero(t, deliveries, "recoverable accounts must not start irreversible host cleanup")
	require.NoError(t, e.pg.QueryRow(t.Context(), `SELECT count(*) FROM public.river_job WHERE kind='authkit_account_finalize'`).Scan(&timers))
	require.Zero(t, timers)
	require.NoError(t, itemErr(e.RestoreUsers(t.Context(), iam.SystemIdentity(), []string{future.ID})))

	var id int64
	require.NoError(t, e.pg.QueryRow(t.Context(), `SELECT id FROM account_deletion_deliveries WHERE deletion_id=$1`, dueID).Scan(&id))
	require.NoError(t, e.runAccountCleanup(t.Context(), id))
	var exists bool
	require.NoError(t, e.pg.QueryRow(t.Context(), `SELECT EXISTS(SELECT 1 FROM users WHERE id=$1)`, due.ID).Scan(&exists))
	require.False(t, exists, "the last successful callback purges inline without another River job")
	require.NoError(t, e.deleteDueAccounts(t.Context()), "replaying the daily sweep is harmless")
}

func TestAccountDeletionDailySweepContinuesAfterFailureAcrossBatches(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	e, err := New(t.Context(), maintenanceConfig(), config.Deps{Postgres: pg.Pool})
	require.NoError(t, err)
	t.Cleanup(func() { _ = e.Close(context.Background()) })
	// The first due account is blocked by a real host foreign key. Its failed
	// purge must not starve the following account or the next query batch.
	blocked := newUser(t, e, "blockedpurge")
	blockedID := expireDeletion(t, e, blocked.ID)
	require.NoError(t, e.finalizeAccountDeletion(t.Context(), blockedID, false))
	_, err = e.pg.Exec(t.Context(), `CREATE TABLE blocked_reference (user_id uuid REFERENCES users(id))`)
	require.NoError(t, err)
	_, err = e.pg.Exec(t.Context(), `INSERT INTO blocked_reference VALUES ($1)`, blocked.ID)
	require.NoError(t, err)
	_, err = e.pg.Exec(t.Context(), `UPDATE account_deletion_deliveries SET completed_at=statement_timestamp() WHERE deletion_id=$1`, blockedID)
	require.NoError(t, err)
	// Persisted zero-recipient legacy records need no external callbacks. A
	// batch boundary is exercised without generating 100 slow password hashes.
	_, err = e.pg.Exec(t.Context(), `INSERT INTO account_deletions(user_id,tenant_id,deleted_at,purge_at,recipients)
	 SELECT uuidv7(),$1,statement_timestamp()-interval '31 days',statement_timestamp()-interval '1 day','{}'
	 FROM generate_series(1,101)`, testdb.DefaultTenantID.String())
	require.NoError(t, err)
	require.NoError(t, e.deleteDueAccounts(t.Context()))
	var purged int
	require.NoError(t, e.pg.QueryRow(t.Context(), `SELECT count(*) FROM account_deletions WHERE state='purged'`).Scan(&purged))
	require.Equal(t, 101, purged)
	var state string
	require.NoError(t, e.pg.QueryRow(t.Context(), `SELECT state FROM account_deletions WHERE id=$1`, blockedID).Scan(&state))
	require.Equal(t, "finalizing", state, "failed purge stays durable for the next daily sweep")
	_, err = e.pg.Exec(t.Context(), `DELETE FROM blocked_reference`)
	require.NoError(t, err)
	require.NoError(t, e.deleteDueAccounts(t.Context()))
	require.NoError(t, e.pg.QueryRow(t.Context(), `SELECT state FROM account_deletions WHERE id=$1`, blockedID).Scan(&state))
	require.Equal(t, "purged", state)
}

func TestAccountDeletionDailySweepKeepsLastOwner(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	e, err := New(t.Context(), maintenanceConfig(), config.Deps{Postgres: pg.Pool})
	require.NoError(t, err)
	t.Cleanup(func() { _ = e.Close(context.Background()) })
	target, replacement := newUser(t, e, "retiringowner"), newUser(t, e, "replacementowner")
	grantRole(t, e, iam.RootGroup(), iam.UserSubject(target.ID), "owner")
	grantRole(t, e, iam.RootGroup(), iam.UserSubject(replacement.ID), "owner")
	id := expireDeletion(t, e, target.ID)
	// Simulate legacy/external drift after the valid soft deletion: normal
	// AuthKit writes already refuse disabling the remaining owner.
	_, err = e.pg.Exec(t.Context(), `UPDATE users SET banned_at=statement_timestamp() WHERE id=$1`, replacement.ID)
	require.NoError(t, err)
	require.NoError(t, e.deleteDueAccounts(t.Context()))
	var state string
	require.NoError(t, e.pg.QueryRow(t.Context(), `SELECT state FROM account_deletions WHERE id=$1`, id).Scan(&state))
	require.Equal(t, "deleted", state)
	require.ErrorIs(t, itemErr(e.PurgeUsers(t.Context(), []string{target.ID})), iam.ErrLastOwner,
		"an explicit purge must recheck ownership for an already-deleted account too")
	var count int
	require.NoError(t, e.pg.QueryRow(t.Context(), `SELECT count(*) FROM account_deletion_deliveries WHERE deletion_id=$1`, id).Scan(&count))
	require.Zero(t, count, "no irreversible callback begins when the account is the last recovery owner")
	var deadline time.Time
	require.NoError(t, e.pg.QueryRow(t.Context(), `SELECT purge_at FROM account_deletions WHERE id=$1`, id).Scan(&deadline))
	require.NoError(t, e.Unban(t.Context(), iam.SystemIdentity(), replacement.ID))
	require.NoError(t, itemErr(e.PurgeUsers(t.Context(), []string{target.ID})))
	var after time.Time
	require.NoError(t, e.pg.QueryRow(t.Context(), `SELECT purge_at,state FROM account_deletions WHERE id=$1`, id).Scan(&after, &state))
	require.Equal(t, "finalizing", state)
	require.True(t, after.Equal(deadline), "an explicit overdue purge must not extend its expired deadline")
}

func TestAccountDeletionDailyConcurrentSweeps(t *testing.T) {
	pg := testdb.EmptyScratchPostgres(t)
	issuers := []string{"https://daily-a.example.test", "https://daily-b.example.test"}
	engines := make([]*Engine, 2)
	for i, schema := range []string{"public", "daily_sibling_jobs"} {
		cfg := maintenanceConfig()
		cfg.Token.Issuer, cfg.Token.AccountIssuers = issuers[i], issuers
		cfg.Database.RiverSchema = schema
		e, err := New(t.Context(), cfg, config.Deps{Postgres: pg.Pool})
		require.NoError(t, err)
		t.Cleanup(func() { _ = e.Close(context.Background()) })
		engines[i] = e
	}
	a := engines[0]
	user := newUser(t, a, "parallelpurge")
	id := expireDeletion(t, a, user.ID)
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for _, e := range engines {
		wg.Go(func() { errs <- e.deleteDueAccounts(t.Context()) })
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
	var deliveries int
	require.NoError(t, a.pg.QueryRow(t.Context(), `SELECT count(*) FROM account_deletion_deliveries WHERE deletion_id=$1`, id).Scan(&deliveries))
	require.Equal(t, 2, deliveries, "concurrent fleets create exactly one cleanup receipt per issuer")
	var exists bool
	require.NoError(t, a.pg.QueryRow(t.Context(), `SELECT EXISTS(SELECT 1 FROM users WHERE id=$1)`, user.ID).Scan(&exists))
	require.False(t, exists, "the two issuers each complete only their own cleanup")

}

func TestExplicitPurgeQueuesOneFollowUpPerIssuer(t *testing.T) {
	pg := testdb.EmptyScratchPostgres(t)
	issuers := []string{"https://purge-a.test", "https://purge-b.test"}
	apps := make([]*Engine, 2)
	for i, schema := range []string{"purge_a_jobs", "purge_b_jobs"} {
		cfg := maintenanceConfig()
		cfg.Token.Issuer, cfg.Token.AccountIssuers = issuers[i], issuers
		cfg.Database.RiverSchema = schema
		var err error
		apps[i], err = New(t.Context(), cfg, config.Deps{Postgres: pg.Pool})
		require.NoError(t, err)
		t.Cleanup(func() { _ = apps[i].Close(context.Background()) })
		// A completed startup pass found nothing. A later explicit purge
		// must enqueue a new pass, not wait for tomorrow.
		require.NoError(t, apps[i].deleteDueAccounts(t.Context()))
	}
	for n := range 3 {
		u := newUser(t, apps[0], fmt.Sprintf("immediatepurge%d", n))
		require.NoError(t, itemErr(apps[0].PurgeUsers(t.Context(), []string{u.ID})))
		for _, schema := range []string{"purge_a_jobs", "purge_b_jobs"} {
			table := pgx.Identifier{schema, "river_job"}.Sanitize()
			var count int
			require.NoError(t, pg.Pool.QueryRow(t.Context(), `SELECT count(*) FROM `+table+` WHERE kind='authkit_account_delete_due'`).Scan(&count))
			require.Equal(t, min(n+1, 2), count, "one active pass and one coalesced follow-up per issuer")
			if n == 0 {
				_, err := pg.Pool.Exec(t.Context(), `UPDATE `+table+` SET state='running',attempted_at=now() WHERE kind='authkit_account_delete_due'`)
				require.NoError(t, err)
			}
			var withAccountID int
			require.NoError(t, pg.Pool.QueryRow(t.Context(), `SELECT count(*) FROM `+table+` WHERE kind='authkit_account_delete_due' AND (args ? 'user_id' OR args ? 'deletion_id')`).Scan(&withAccountID))
			require.Zero(t, withAccountID)
		}
	}
}

func TestAccountDeletionDailyWorkerRegistration(t *testing.T) {
	e, err := New(t.Context(), maintenanceConfig(), config.Deps{})
	require.NoError(t, err)
	defer e.Close(context.Background())
	wrong := &accountDeleteDueWorker{engine: e}
	require.Error(t, wrong.Work(t.Context(), &river.Job[accountDeleteDueArgs]{Args: accountDeleteDueArgs{Schema: "other"}}))
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	// A scan error must propagate to River rather than falsely completing a
	// pass which never read the database. Covered with a real connected engine.
	pg := testdb.ScratchPostgres(t)
	real, err := New(t.Context(), maintenanceConfig(), config.Deps{Postgres: pg.Pool})
	require.NoError(t, err)
	defer real.Close(context.Background())
	require.ErrorIs(t, real.deleteDueAccounts(ctx), context.Canceled)
	var cfg river.Config
	cfg.Schema = real.cfg.Database.RiverSchema
	require.NoError(t, real.registerRiver(&cfg))
	require.Len(t, cfg.PeriodicJobs, 2, "one auth-state cleanup and one daily account deletion sweep")
	for queue := range cfg.Queues {
		require.False(t, strings.HasPrefix(queue, "authkit_finalization-"))
	}
}

// Legacy args are test-only: production no longer registers or inserts these.
type legacyAccountFinalizeArgs struct {
	Schema     string `json:"schema"`
	DeletionID string `json:"deletion_id"`
}

func (legacyAccountFinalizeArgs) Kind() string { return "authkit_account_finalize" }

type legacyAccountDeliveryArgs struct {
	Schema     string `json:"schema"`
	Issuer     string `json:"issuer"`
	DeliveryID int64  `json:"delivery_id"`
}

func (legacyAccountDeliveryArgs) Kind() string { return "authkit_account_delivery" }

func TestAccountDeletionTimerMigrationKeepsLifecycleAndOtherFleets(t *testing.T) {
	pg := testdb.EmptyScratchPostgres(t)
	cfg := maintenanceConfig()
	e, err := New(t.Context(), cfg, config.Deps{Postgres: pg.Pool})
	require.NoError(t, err)
	defer e.Close(context.Background())
	user := newUser(t, e, "migratetimer")
	require.NoError(t, e.softDelete(t.Context(), user.ID))
	var deletion db.AccountDeletion
	require.NoError(t, e.pg.QueryRow(t.Context(), `SELECT id::text,user_id::text,purge_at,state FROM account_deletions WHERE user_id=$1`, user.ID).Scan(&deletion.ID, &deletion.UserID, &deletion.PurgeAt, &deletion.State))
	client, err := river.NewClient(riverpgxv5.New(pg.Pool), &river.Config{Schema: cfg.Database.RiverSchema})
	require.NoError(t, err)
	add := func(schema string, ids ...string) int64 {
		t.Helper()
		id := deletion.ID
		if len(ids) > 0 {
			id = ids[0]
		}
		job, err := client.Insert(t.Context(), legacyAccountFinalizeArgs{Schema: schema, DeletionID: id}, &river.InsertOpts{ScheduledAt: time.Now().Add(time.Hour)})
		require.NoError(t, err)
		return job.Job.ID
	}
	require.NoError(t, Migrate(t.Context(), pg.Pool, config.DatabaseConfig{RiverSchema: "untouched_jobs"}, MigrationOptions{LegacyTenantID: testdb.DefaultTenantID}))
	sibling, err := river.NewClient(riverpgxv5.New(pg.Pool), &river.Config{Schema: "untouched_jobs"})
	require.NoError(t, err)
	siblingJob, err := sibling.Insert(t.Context(), legacyAccountFinalizeArgs{Schema: "profiles", DeletionID: deletion.ID}, &river.InsertOpts{ScheduledAt: time.Now().Add(time.Hour)})
	require.NoError(t, err)
	var cleanupID int64
	require.NoError(t, e.pg.QueryRow(t.Context(), `INSERT INTO account_deletion_deliveries(deletion_id,user_id,issuer,stage) VALUES($1,$2,$3,'hard') RETURNING id`, deletion.ID, user.ID, cfg.Token.Issuer).Scan(&cleanupID))
	legacy, err := client.Insert(t.Context(), legacyAccountDeliveryArgs{Schema: "profiles", Issuer: cfg.Token.Issuer, DeliveryID: cleanupID}, &river.InsertOpts{ScheduledAt: time.Now().Add(time.Hour)})
	require.NoError(t, err)
	retired, foreign, running := add("profiles"), add("other_identity"), add("profiles")
	_, err = pg.Pool.Exec(t.Context(), `UPDATE public.river_job SET state='running',attempted_at=statement_timestamp(),attempt=1 WHERE id=$1`, running)
	require.NoError(t, err)
	require.ErrorContains(t, Migrate(t.Context(), pg.Pool, cfg.Database, MigrationOptions{LegacyTenantID: testdb.DefaultTenantID}), "stop old account workers")
	var untouched bool
	require.NoError(t, pg.Pool.QueryRow(t.Context(), `SELECT EXISTS(SELECT 1 FROM public.river_job WHERE id=$1)`, retired).Scan(&untouched))
	require.True(t, untouched, "running-job refusal must not partially retire other timers")
	_, err = pg.Pool.Exec(t.Context(), `UPDATE public.river_job SET state='scheduled' WHERE id=$1`, running)
	require.NoError(t, err)
	orphan := add("profiles", "00000000-0000-0000-0000-000000000000")
	require.ErrorContains(t, Migrate(t.Context(), pg.Pool, cfg.Database, MigrationOptions{LegacyTenantID: testdb.DefaultTenantID}), "no canonical deletion record")
	require.NoError(t, pg.Pool.QueryRow(t.Context(), `SELECT EXISTS(SELECT 1 FROM public.river_job WHERE id=$1)`, retired).Scan(&untouched))
	require.True(t, untouched, "invalid canonical state must leave all pending work untouched")
	_, err = pg.Pool.Exec(t.Context(), `DELETE FROM public.river_job WHERE id=$1`, orphan)
	require.NoError(t, err)
	var purgedID string
	require.NoError(t, e.pg.QueryRow(t.Context(), `INSERT INTO account_deletions(user_id,tenant_id,deleted_at,purge_at,state,purged_at)
	 VALUES (uuidv7(),$1,statement_timestamp()-interval '31 days',statement_timestamp()-interval '1 day','purged',statement_timestamp()) RETURNING id::text`, testdb.DefaultTenantID.String()).Scan(&purgedID))
	stale := add("profiles", purgedID)
	require.NoError(t, Migrate(t.Context(), pg.Pool, cfg.Database, MigrationOptions{LegacyTenantID: testdb.DefaultTenantID}))
	var retained []int64
	rows, err := pg.Pool.Query(t.Context(), `SELECT id FROM public.river_job WHERE kind='authkit_account_finalize' ORDER BY id`)
	require.NoError(t, err)
	for rows.Next() {
		var id int64
		require.NoError(t, rows.Scan(&id))
		retained = append(retained, id)
	}
	require.NoError(t, rows.Err())
	rows.Close()
	require.Equal(t, []int64{foreign}, retained)
	require.NotContains(t, retained, retired)
	require.NotContains(t, retained, stale, "purged accounts need no future finalizer")
	var jobExists, pending bool
	require.NoError(t, pg.Pool.QueryRow(t.Context(), `SELECT EXISTS(SELECT 1 FROM public.river_job WHERE id=$1)`, legacy.Job.ID).Scan(&jobExists))
	require.False(t, jobExists)
	require.NoError(t, e.pg.QueryRow(t.Context(), `SELECT completed_at IS NULL FROM account_deletion_deliveries WHERE id=$1`, cleanupID).Scan(&pending))
	require.True(t, pending, "retiring a job preserves its cleanup obligation")
	var got db.AccountDeletion
	require.NoError(t, e.pg.QueryRow(t.Context(), `SELECT id::text,user_id::text,purge_at,state FROM account_deletions WHERE id=$1`, deletion.ID).Scan(&got.ID, &got.UserID, &got.PurgeAt, &got.State))
	require.Equal(t, deletion, got, "migration removes timers, never authoritative deletion state")
	var siblingRetained bool
	require.NoError(t, pg.Pool.QueryRow(t.Context(), `SELECT EXISTS(SELECT 1 FROM untouched_jobs.river_job WHERE id=$1)`, siblingJob.Job.ID).Scan(&siblingRetained))
	require.True(t, siblingRetained, "each fleet is migrated explicitly; this pass must not touch another River schema")
}

// Restarts preserve an issuer's daily deadline, while explicit purge requests
// can still queue work immediately. Unfinished scans coalesce into one job.
func TestAccountDeletionDailyRestartOnlyCatchesUpWhenDue(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	issuer := maintenanceConfig().Token.Issuer
	start := func() *Engine {
		t.Helper()
		e, err := New(t.Context(), maintenanceConfig(), config.Deps{Postgres: pg.Pool})
		require.NoError(t, err)
		t.Cleanup(func() { _ = e.Close(context.Background()) })
		require.NoError(t, e.Start(t.Context(), nil))
		return e
	}
	awaitCompletedAfter := func(after int64) int64 {
		t.Helper()
		var id int64
		require.Eventually(t, func() bool {
			err := pg.Pool.QueryRow(t.Context(), `SELECT coalesce(max(id),0) FROM public.river_job
				WHERE kind='authkit_account_delete_due' AND args->>'issuer'=$1 AND state='completed' AND id>$2`, issuer, after).Scan(&id)
			return err == nil && id > after
		}, 10*time.Second, 25*time.Millisecond)
		return id
	}
	first := start()
	firstID := awaitCompletedAfter(0)
	require.NoError(t, first.Close(t.Context()))
	second := start()
	require.NoError(t, second.Close(t.Context()))
	var recent int
	require.NoError(t, pg.Pool.QueryRow(t.Context(), `SELECT count(*) FROM public.river_job
		WHERE kind='authkit_account_delete_due' AND args->>'issuer'=$1 AND id>$2`, issuer, firstID).Scan(&recent))
	require.Zero(t, recent, "restarting inside the daily interval must not queue another issuer scan")
	_, err := pg.Pool.Exec(t.Context(), `UPDATE public.river_job
		SET created_at=statement_timestamp()-interval '25 hours', attempted_at=statement_timestamp()-interval '25 hours',
		finalized_at=statement_timestamp()-interval '25 hours'
		WHERE kind='authkit_account_delete_due' AND args->>'issuer'=$1`, issuer)
	require.NoError(t, err)
	third := start()
	awaitCompletedAfter(firstID)
	require.NoError(t, third.Close(t.Context()))

	producer, err := river.NewClient(riverpgxv5.New(pg.Pool), &river.Config{Schema: "public"})
	require.NoError(t, err)
	args := accountDeleteDueArgs{Schema: "profiles", Issuer: maintenanceConfig().Token.Issuer}
	one, err := producer.Insert(t.Context(), args, nil)
	require.NoError(t, err)
	two, err := producer.Insert(t.Context(), args, nil)
	require.NoError(t, err)
	require.Equal(t, one.Job.ID, two.Job.ID, "pending scans coalesce even after completed history exists")
	other := args
	other.Issuer = "https://other-issuer.test"
	three, err := producer.Insert(t.Context(), other, nil)
	require.NoError(t, err)
	require.NotEqual(t, one.Job.ID, three.Job.ID, "one issuer cannot suppress another issuer's sweep")
	require.NotEqual(t, one.Job.Queue, three.Job.Queue, "one issuer's worker cannot claim another issuer's cleanup")
}

func TestAccountDeletionStartupGateSerializesReplicas(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	e, err := New(t.Context(), maintenanceConfig(), config.Deps{Postgres: pg.Pool})
	require.NoError(t, err)
	t.Cleanup(func() { _ = e.Close(context.Background()) })
	const replicas = 12
	errors := make(chan error, replicas)
	var wg sync.WaitGroup
	for range replicas {
		wg.Go(func() { errors <- e.scheduleAccountCleanup(t.Context(), e.cfg.Token.Issuer) })
	}
	wg.Wait()
	close(errors)
	for err := range errors {
		require.NoError(t, err)
	}
	var count int
	require.NoError(t, pg.Pool.QueryRow(t.Context(), `SELECT count(*) FROM public.river_job
		WHERE kind='authkit_account_delete_due' AND args->>'issuer'=$1`, e.cfg.Token.Issuer).Scan(&count))
	require.Equal(t, 1, count, "replicas must share one due-check-and-insert decision")
}
