package engine

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/config"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/riverqueue/river"
	"github.com/stretchr/testify/require"
)

func TestAccountPurgeWaitsForEveryTenantApp(t *testing.T) {
	pg := testdb.EmptyScratchPostgres(t)
	issuers := []string{"https://app-a.test", "https://app-b.test"}
	makeApp := func(index int, fail bool) *Engine {
		cfg := maintenanceConfig()
		cfg.Token.Issuer = issuers[index]
		cfg.Token.AccountIssuers = issuers
		app, err := New(t.Context(), cfg, config.Deps{Postgres: pg.Pool, OnPurge: func(context.Context, iam.UserDeletion) error {
			if fail {
				return errors.New("app storage unavailable")
			}
			return nil
		}})
		require.NoError(t, err)
		t.Cleanup(func() { _ = app.Close(context.Background()) })
		return app
	}
	a, b := makeApp(0, false), makeApp(1, true)
	user, err := a.createUser(t.Context(), "fanout@example.test", "fanout")
	require.NoError(t, err)
	deletion := expireDeletion(t, a, user.ID)
	require.NoError(t, a.finalizeAccountDeletion(t.Context(), deletion, false))
	ids := make([]int64, 2)
	for i, issuer := range issuers {
		require.NoError(t, pg.Pool.QueryRow(t.Context(), "SELECT id FROM profiles.account_deletion_deliveries WHERE deletion_id=$1 AND issuer=$2 AND stage='hard'", deletion, issuer).Scan(&ids[i]))
	}
	require.NoError(t, a.deliverAccountEvent(t.Context(), ids[0]))
	require.Error(t, b.deliverAccountEvent(t.Context(), ids[1]))
	var snooze *river.JobSnoozeError
	require.ErrorAs(t, a.finalizeAccountDeletion(t.Context(), deletion, true), &snooze)
	var exists bool
	require.NoError(t, pg.Pool.QueryRow(t.Context(), "SELECT EXISTS(SELECT 1 FROM profiles.users WHERE id=$1)", user.ID).Scan(&exists))
	require.True(t, exists, "account purged while one app still retained data")
	var completed *time.Time
	require.NoError(t, pg.Pool.QueryRow(t.Context(), "SELECT completed_at FROM profiles.account_deletion_deliveries WHERE id=$1", ids[1]).Scan(&completed))
	require.Nil(t, completed)
	require.NoError(t, b.Close(t.Context()))
	b = makeApp(1, false)
	require.NoError(t, b.deliverAccountEvent(t.Context(), ids[1]), "durable obligation was not retryable after restart")
	require.NoError(t, a.finalizeAccountDeletion(t.Context(), deletion, true))
	require.NoError(t, pg.Pool.QueryRow(t.Context(), "SELECT EXISTS(SELECT 1 FROM profiles.users WHERE id=$1)", user.ID).Scan(&exists))
	require.False(t, exists)
}
