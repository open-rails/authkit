package engine

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/config"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/stretchr/testify/require"
)

func TestAccountPurgeWaitsForEveryTenantApp(t *testing.T) {
	pg := testdb.EmptyScratchPostgres(t)
	issuers := []string{"https://app-a.test", "https://app-b.test"}
	var calls [2]atomic.Int32
	var failSecond atomic.Bool
	failSecond.Store(true)
	makeApp := func(i int) *Engine {
		cfg := maintenanceConfig()
		cfg.Token.Issuer = issuers[i]
		cfg.Token.AccountIssuers = issuers
		app, err := New(t.Context(), cfg, config.Deps{Postgres: pg.Pool, OnPurge: func(context.Context, iam.UserDeletion) error {
			calls[i].Add(1)
			if i == 1 && failSecond.Load() {
				return errors.New("app storage unavailable")
			}
			return nil
		}})
		require.NoError(t, err)
		t.Cleanup(func() { _ = app.Close(context.Background()) })
		return app
	}
	a, b := makeApp(0), makeApp(1)
	user, err := a.createUser(t.Context(), "fanout@example.test", "fanout")
	require.NoError(t, err)
	deletion := expireDeletion(t, a, user.ID)
	exists := func() bool {
		var v bool
		require.NoError(t, pg.Pool.QueryRow(t.Context(), "SELECT EXISTS(SELECT 1 FROM profiles.users WHERE id=$1)", user.ID).Scan(&v))
		return v
	}
	completed := func(issuer string) bool {
		var n int
		err := pg.Pool.QueryRow(t.Context(), "SELECT count(*) FROM public.river_job WHERE kind='authkit_account_delete_due' AND args->>'issuer'=$1 AND state='completed'", issuer).Scan(&n)
		return err == nil && n > 0
	}
	// Both issuers intentionally share a River schema: scoped queue/unique args
	// must keep the first running client from swallowing the second's catch-up.
	require.NoError(t, a.Start(t.Context(), nil))
	require.Eventually(t, func() bool { return completed(issuers[0]) }, 10*time.Second, 25*time.Millisecond)
	require.EqualValues(t, 1, calls[0].Load())
	require.Zero(t, calls[1].Load())
	require.True(t, exists(), "offline required issuer prevents purge")
	require.Eventually(t, func() bool {
		var n int
		err := pg.Pool.QueryRow(t.Context(), "SELECT count(*) FROM public.river_job WHERE kind='authkit_account_delete_due' AND args->>'issuer'=$1 AND state IN ('available','pending','retryable','scheduled')", issuers[1]).Scan(&n)
		return err == nil && n == 1
	}, 10*time.Second, 25*time.Millisecond, "the elected leader schedules the offline sibling's coalesced batch")
	require.NoError(t, a.deleteDueAccounts(t.Context()))
	require.EqualValues(t, 1, calls[0].Load(), "successful cleanup is not replayed")
	require.NoError(t, b.Start(t.Context(), nil))
	require.Eventually(t, func() bool { return completed(issuers[1]) }, 10*time.Second, 25*time.Millisecond)
	require.EqualValues(t, 1, calls[1].Load())
	require.True(t, exists(), "failed cleanup remains durable")
	var pending bool
	require.NoError(t, pg.Pool.QueryRow(t.Context(), "SELECT completed_at IS NULL FROM profiles.account_deletion_deliveries WHERE deletion_id=$1 AND issuer=$2", deletion, issuers[1]).Scan(&pending))
	require.True(t, pending)
	failSecond.Store(false)
	require.NoError(t, b.deleteDueAccounts(t.Context()))
	require.False(t, exists(), "last required issuer completes the purge")
	require.NoError(t, a.deleteDueAccounts(t.Context()))
	require.NoError(t, b.deleteDueAccounts(t.Context()))
	require.EqualValues(t, 1, calls[0].Load())
	require.EqualValues(t, 2, calls[1].Load())
	var queued int
	require.NoError(t, pg.Pool.QueryRow(t.Context(), "SELECT count(*) FROM public.river_job WHERE kind='authkit_account_delivery'").Scan(&queued))
	require.Zero(t, queued, "cleanup has no per-account delivery jobs")
}
