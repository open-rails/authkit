package engine

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/config"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/riverqueue/river"
	"github.com/stretchr/testify/require"
)

func TestAccountCallbackFailureAndConcurrentRescue(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	var calls atomic.Int32
	entered, release := make(chan struct{}), make(chan struct{})
	runtime, err := New(context.Background(), maintenanceConfig(), config.Deps{Postgres: pg.Pool, OnPurge: func(ctx context.Context, _ iam.UserDeletion) error {
		switch calls.Add(1) {
		case 1:
			return errors.New("host storage unavailable")
		case 2:
			panic("host callback panic")
		default:
			select {
			case entered <- struct{}{}:
			case <-ctx.Done():
				return ctx.Err()
			}
			select {
			case <-release:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}})
	require.NoError(t, err)
	t.Cleanup(func() { _ = runtime.Close(context.Background()) })
	user, err := runtime.createUser(t.Context(), "callback-retry@example.test", "callbackretry")
	require.NoError(t, err)
	// OnPurge is the one receipt-backed account callback; finalizing an
	// expired deletion queues it.
	require.NoError(t, runtime.finalizeAccountDeletion(t.Context(), expireDeletion(t, runtime, user.ID), false))
	var id int64
	require.NoError(t, pg.Pool.QueryRow(t.Context(), "SELECT id FROM profiles.account_deletion_deliveries WHERE user_id=$1::uuid", user.ID).Scan(&id))
	worker := accountDeliveryWorker{engine: runtime}
	job := &river.Job[accountDeliveryArgs]{Args: accountDeliveryArgs{Schema: "profiles", Issuer: runtime.cfg.Token.Issuer, DeliveryID: id}}
	for range 2 {
		var snooze *river.JobSnoozeError
		require.ErrorAs(t, worker.Work(t.Context(), job), &snooze, "callback failure remains durable without exhausting attempts")
		var completed *time.Time
		require.NoError(t, pg.Pool.QueryRow(t.Context(), "SELECT completed_at FROM profiles.account_deletion_deliveries WHERE id=$1", id).Scan(&completed))
		require.Nil(t, completed)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for range 2 {
		wg.Go(func() { errs <- runtime.deliverAccountEvent(ctx, id) })
	}
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	require.Never(t, func() bool { return calls.Load() > 3 }, 100*time.Millisecond, 10*time.Millisecond, "rescued attempts must not execute the same callback concurrently")
	close(release)
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
	require.EqualValues(t, 3, calls.Load(), "the second attempt rereads the completed receipt under the shared lock")
}

func TestAccountCallbackCanObserveBindingDuringManagedShutdown(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	entered := make(chan struct{})
	var runtime *Engine
	var err error
	runtime, err = New(context.Background(), maintenanceConfig(), config.Deps{Postgres: pg.Pool, OnPurge: func(ctx context.Context, _ iam.UserDeletion) error {
		close(entered)
		<-ctx.Done()
		// A lifecycle worker may check its producer binding while shutdown is
		// waiting for it. closeRiver must not hold the binding mutex here.
		_, err := runtime.deletionRiver()
		return err
	}})
	require.NoError(t, err)
	user, err := runtime.createUser(t.Context(), "shutdown@example.test", "shutdown")
	require.NoError(t, err)
	require.NoError(t, runtime.finalizeAccountDeletion(t.Context(), expireDeletion(t, runtime, user.ID), false))
	require.NoError(t, runtime.Start(t.Context(), nil))
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("callback did not start")
	}
	closed := make(chan struct{})
	go func() {
		runtime.Close(context.Background())
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(10 * time.Second):
		t.Fatal("managed shutdown deadlocked against its active callback")
	}
	require.NoError(t, pg.Pool.Ping(t.Context()))
}

func TestAccountDeletionRollsBackWhenRiverInsertFails(t *testing.T) {
	pg := testdb.EmptyScratchPostgres(t)
	require.NoError(t, Migrate(t.Context(), pg.Pool, config.Config{}, config.MigrateOptions{}))
	cfg := maintenanceConfig()
	cfg.RiverSchema = "uninitialized_jobs"
	runtime, err := New(context.Background(), cfg, config.Deps{Postgres: pg.Pool})
	require.NoError(t, err)
	t.Cleanup(func() { _ = runtime.Close(context.Background()) })
	user, err := runtime.createUser(t.Context(), "rollback@example.test", "rollback")
	require.NoError(t, err)
	results, err := runtime.DeleteUsers(t.Context(), iam.SystemIdentity(), []string{user.ID})
	require.NoError(t, err)
	require.Error(t, results[0].Err)
	var deleted *time.Time
	var cycles int
	require.NoError(t, pg.Pool.QueryRow(t.Context(), "SELECT deleted_at FROM profiles.users WHERE id=$1::uuid", user.ID).Scan(&deleted))
	require.Nil(t, deleted, "a deletion without its durable job must not commit")
	require.NoError(t, pg.Pool.QueryRow(t.Context(), "SELECT count(*) FROM profiles.account_deletions WHERE user_id=$1::uuid", user.ID).Scan(&cycles))
	require.Zero(t, cycles)
}

// Deletion and recovery reach every account issuer through its own River
// fleet as user.deleted and user.restored events, in order, even when that
// deployment was offline throughout.
func TestAccountDeletionDeliveryAcrossSeparateRiverFleets(t *testing.T) {
	pg := testdb.EmptyScratchPostgres(t)
	require.NoError(t, Migrate(t.Context(), pg.Pool, config.Config{}, config.MigrateOptions{}))
	require.NoError(t, Migrate(t.Context(), pg.Pool, config.Config{RiverSchema: "sibling_jobs"}, config.MigrateOptions{}))
	issuers := []string{"https://first.example.test", "https://second.example.test"}
	var mu sync.Mutex
	events := map[string][]string{}
	makeRuntime := func(issuer, schema string) *Engine {
		t.Helper()
		cfg := maintenanceConfig()
		cfg.Token.Issuer = issuer
		cfg.Token.AccountIssuers = issuers
		cfg.RiverSchema = schema
		record := func(entry string) {
			mu.Lock()
			defer mu.Unlock()
			events[issuer] = append(events[issuer], entry)
		}
		runtime, err := New(context.Background(), cfg, config.Deps{
			Postgres: pg.Pool,
			OnEvent: func(_ context.Context, e iam.Event) error {
				if e.Kind == iam.EventUserDeleted || e.Kind == iam.EventUserRestored {
					record(string(e.Kind) + ":" + e.UserID)
				}
				return nil
			},
			OnPurge: func(_ context.Context, d iam.UserDeletion) error { record("purge:" + d.ID); return nil },
		})
		require.NoError(t, err)
		t.Cleanup(func() { _ = runtime.Close(context.Background()) })
		return runtime
	}
	first := makeRuntime(issuers[0], "public")
	second := makeRuntime(issuers[1], "sibling_jobs")
	user, err := first.createUser(t.Context(), "two-fleets@example.test", "twofleets")
	require.NoError(t, err)
	results, err := first.DeleteUsers(t.Context(), iam.SystemIdentity(), []string{user.ID})
	require.NoError(t, err)
	require.NoError(t, results[0].Err)
	for _, pair := range [][2]string{{"public", issuers[0]}, {"sibling_jobs", issuers[1]}} {
		var count int
		require.NoError(t, pg.Pool.QueryRow(t.Context(), "SELECT count(*) FROM "+pgx.Identifier{pair[0], "river_job"}.Sanitize()+` j
 JOIN profiles.account_events e ON e.id=(j.args->>'row')::bigint
 WHERE j.kind='authkit_account_event' AND j.args->>'issuer'=$1 AND e.issuer=$1 AND e.kind='user.deleted'`, pair[1]).Scan(&count))
		require.Equal(t, 1, count, "each event is queued in its recipient's actual fleet")
	}
	require.NoError(t, first.Start(t.Context(), nil))
	require.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(events[issuers[0]]) == 1 && len(events[issuers[1]]) == 0
	}, 10*time.Second, 25*time.Millisecond)
	results, err = first.RestoreUsers(t.Context(), iam.SystemIdentity(), []string{user.ID})
	require.NoError(t, err)
	require.NoError(t, results[0].Err)
	// The second deployment was offline throughout deletion and recovery. Its
	// own fleet must replay the events in order when it eventually starts.
	require.NoError(t, second.Start(t.Context(), nil))
	require.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(events[issuers[0]]) == 2 && len(events[issuers[1]]) == 2
	}, 10*time.Second, 25*time.Millisecond)
	mu.Lock()
	recorded := map[string][]string{issuers[0]: append([]string(nil), events[issuers[0]]...), issuers[1]: append([]string(nil), events[issuers[1]]...)}
	mu.Unlock()
	for _, issuer := range issuers {
		require.Equal(t, []string{"user.deleted:" + user.ID, "user.restored:" + user.ID}, recorded[issuer])
	}
}

func TestAccountFleetRebindRequiresQuiescenceAndFencesOldProducer(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	require.NoError(t, Migrate(t.Context(), pg.Pool, config.Config{RiverSchema: "replacement_jobs"}, config.MigrateOptions{}))
	cfg := maintenanceConfig()
	old, err := New(context.Background(), cfg, config.Deps{Postgres: pg.Pool, OnEvent: func(context.Context, iam.Event) error { return nil }})
	require.NoError(t, err)
	t.Cleanup(func() { _ = old.Close(context.Background()) })
	user, err := old.createUser(t.Context(), "rebind@example.test", "rebind")
	require.NoError(t, err)
	require.NoError(t, old.softDelete(t.Context(), user.ID))
	cfg.RiverSchema = "replacement_jobs"
	_, err = New(context.Background(), cfg, config.Deps{Postgres: pg.Pool})
	require.ErrorContains(t, err, "active account lifecycle work")
	results, err := old.RestoreUsers(t.Context(), iam.SystemIdentity(), []string{user.ID})
	require.NoError(t, err)
	require.NoError(t, results[0].Err)
	_, err = New(context.Background(), cfg, config.Deps{Postgres: pg.Pool})
	require.ErrorContains(t, err, "active account lifecycle work", "pending restore events must also block a move")
	require.Equal(t, []iam.EventKind{iam.EventUserRegistered, iam.EventUserDeleted, iam.EventUserRestored}, deliverEvents(t, old))
	replacement, err := New(context.Background(), cfg, config.Deps{Postgres: pg.Pool})
	require.NoError(t, err, "quiescent history does not permanently pin a schema")
	t.Cleanup(func() { _ = replacement.Close(context.Background()) })
	err = old.softDelete(t.Context(), user.ID)
	require.ErrorContains(t, err, "fleet was rebound")
	var deleted *time.Time
	require.NoError(t, pg.Pool.QueryRow(t.Context(), "SELECT deleted_at FROM profiles.users WHERE id=$1::uuid", user.ID).Scan(&deleted))
	require.Nil(t, deleted, "stale producer rejection rolls back the account mutation")
	require.NoError(t, replacement.softDelete(t.Context(), user.ID))
	var jobs int
	require.NoError(t, pg.Pool.QueryRow(t.Context(), "SELECT count(*) FROM replacement_jobs.river_job WHERE kind='authkit_account_finalize'").Scan(&jobs))
	require.Equal(t, 1, jobs, "the deletion's durable work lands in the current fleet")
}
