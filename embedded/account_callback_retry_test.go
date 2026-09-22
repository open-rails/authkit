package embedded

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/riverqueue/river"
	"github.com/stretchr/testify/require"
)

func TestAccountCallbackFailureAndConcurrentRescue(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	var calls atomic.Int32
	entered, release := make(chan struct{}), make(chan struct{})
	runtime, err := New(maintenanceConfig(), Deps{Postgres: pg.Pool, OnSoftDelete: func(ctx context.Context, _ authkit.UserDeletion) error {
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
	t.Cleanup(runtime.Close)
	user, err := runtime.Client().CreateUser(t.Context(), "callback-retry@example.test", "callbackretry")
	require.NoError(t, err)
	results, err := runtime.Client().SoftDeleteUsers(t.Context(), []string{user.ID})
	require.NoError(t, err)
	require.NoError(t, results[0].Err)
	var id int64
	require.NoError(t, pg.Pool.QueryRow(t.Context(), "SELECT id FROM profiles.account_deletion_deliveries WHERE user_id=$1::uuid", user.ID).Scan(&id))
	worker := accountDeliveryWorker{engine: runtime.engine}
	job := &river.Job[accountDeliveryArgs]{Args: accountDeliveryArgs{Schema: "profiles", Issuer: runtime.engine.cfg.Token.Issuer, DeliveryID: id}}
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
		wg.Go(func() { errs <- runtime.engine.deliverAccountEvent(ctx, id) })
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
