package engine

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/config"
	"github.com/open-rails/authkit/internal/testdb"
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
	// expired deletion records its pending domain obligation.
	require.NoError(t, runtime.finalizeAccountDeletion(t.Context(), expireDeletion(t, runtime, user.ID), false))
	var id int64
	require.NoError(t, pg.Pool.QueryRow(t.Context(), "SELECT id FROM profiles.account_deletion_deliveries WHERE user_id=$1::uuid", user.ID).Scan(&id))
	for range 2 {
		require.Error(t, runtime.runAccountCleanup(t.Context(), id), "callback failure leaves the receipt for a later sweep")
		var completed *time.Time
		require.NoError(t, pg.Pool.QueryRow(t.Context(), "SELECT completed_at FROM profiles.account_deletion_deliveries WHERE id=$1", id).Scan(&completed))
		require.Nil(t, completed)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for range 2 {
		wg.Go(func() { errs <- runtime.runAccountCleanup(ctx, id) })
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

func TestAccountDeletionDoesNotNeedPerAccountRiverInsert(t *testing.T) {
	pg := testdb.EmptyScratchPostgres(t)
	cfg := maintenanceConfig()
	cfg.Database.RiverSchema = "broken_jobs"
	runtime, err := New(context.Background(), cfg, config.Deps{Postgres: pg.Pool})
	require.NoError(t, err)
	t.Cleanup(func() { _ = runtime.Close(context.Background()) })
	// No event hook is configured, so a recoverable deletion needs only its
	// database record. It must not insert a separate future timer.
	_, err = pg.Pool.Exec(t.Context(), "DROP TABLE broken_jobs.river_job CASCADE")
	require.NoError(t, err)
	user, err := runtime.createUser(t.Context(), "rollback@example.test", "rollback")
	require.NoError(t, err)
	results, err := runtime.DeleteUsers(t.Context(), iam.SystemIdentity(), []string{user.ID})
	require.NoError(t, err)
	require.NoError(t, results[0].Err)
	var deleted *time.Time
	var cycles int
	require.NoError(t, pg.Pool.QueryRow(t.Context(), "SELECT deleted_at FROM profiles.users WHERE id=$1::uuid", user.ID).Scan(&deleted))
	require.NotNil(t, deleted, "the database deletion record owns the deadline")
	require.NoError(t, pg.Pool.QueryRow(t.Context(), "SELECT count(*) FROM profiles.account_deletions WHERE user_id=$1::uuid", user.ID).Scan(&cycles))
	require.Equal(t, 1, cycles)
}

// Two applications read the same committed history with independent cursors,
// even when neither application has started its River fleet.
func TestAccountEventsAcrossSeparateRiverFleets(t *testing.T) {
	pg := testdb.EmptyScratchPostgres(t)
	issuers := []string{"https://first.example.test", "https://second.example.test"}
	apps := make([]*Engine, 2)
	for i, schema := range []string{"public", "sibling_jobs"} {
		cfg := maintenanceConfig()
		cfg.Token.Issuer = issuers[i]
		cfg.Token.AccountIssuers = issuers
		cfg.Database.RiverSchema = schema
		e, err := New(t.Context(), cfg, config.Deps{Postgres: pg.Pool})
		require.NoError(t, err)
		t.Cleanup(func() { _ = e.Close(context.Background()) })
		apps[i] = e
	}
	before, err := apps[1].ListEvents(t.Context(), iam.EventQuery{})
	require.NoError(t, err)
	u, err := apps[0].CreateUser(t.Context(), iam.NewUser{Username: "twofleets"})
	require.NoError(t, err)
	require.NoError(t, itemErr(apps[0].DeleteUsers(t.Context(), iam.SystemIdentity(), []string{u.ID})))
	require.NoError(t, itemErr(apps[0].RestoreUsers(t.Context(), iam.SystemIdentity(), []string{u.ID})))
	for _, e := range apps {
		page, err := e.ListEvents(t.Context(), iam.EventQuery{After: before.NextCursor})
		require.NoError(t, err)
		var kinds []iam.EventKind
		for _, event := range page.Events {
			if event.UserID == u.ID {
				kinds = append(kinds, event.Kind)
			}
		}
		require.Equal(t, []iam.EventKind{iam.EventUserRegistered, iam.EventUserDeleted, iam.EventUserRestored}, kinds)
	}
}

func TestAccountFleetRebindRequiresQuiescenceAndFencesOldProducer(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	require.NoError(t, Migrate(t.Context(), pg.Pool, config.DatabaseConfig{RiverSchema: "replacement_jobs"}, MigrationOptions{LegacyTenantID: testdb.DefaultTenantID}))
	cfg := maintenanceConfig()
	old, err := New(context.Background(), cfg, config.Deps{Postgres: pg.Pool})
	require.NoError(t, err)
	t.Cleanup(func() { _ = old.Close(context.Background()) })
	user, err := old.createUser(t.Context(), "rebind@example.test", "rebind")
	require.NoError(t, err)
	require.NoError(t, old.softDelete(t.Context(), user.ID))
	cfg.Database.RiverSchema = "replacement_jobs"
	_, err = New(context.Background(), cfg, config.Deps{Postgres: pg.Pool})
	require.ErrorContains(t, err, "active account lifecycle work")
	results, err := old.RestoreUsers(t.Context(), iam.SystemIdentity(), []string{user.ID})
	require.NoError(t, err)
	require.NoError(t, results[0].Err)
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
	require.Zero(t, jobs, "account deadlines no longer create one job per account")
}
