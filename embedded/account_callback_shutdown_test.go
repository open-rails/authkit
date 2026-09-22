package embedded

import (
	"context"
	"testing"
	"time"

	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/stretchr/testify/require"
)

func TestAccountCallbackCanObserveBindingDuringManagedShutdown(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	entered := make(chan struct{})
	var runtime *Runtime
	var err error
	runtime, err = New(maintenanceConfig(), Deps{Postgres: pg.Pool, OnSoftDelete: func(ctx context.Context, _ authkit.UserDeletion) error {
		close(entered)
		<-ctx.Done()
		// A lifecycle worker may check its producer binding while shutdown is
		// waiting for it. closeRiver must not hold the binding mutex here.
		_, err := runtime.engine.deletionRiver()
		return err
	}})
	require.NoError(t, err)
	user, err := runtime.Client().CreateUser(t.Context(), "shutdown@example.test", "shutdown")
	require.NoError(t, err)
	require.NoError(t, runtime.engine.SoftDeleteUser(t.Context(), user.ID))
	require.NoError(t, runtime.Start(t.Context()))
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("callback did not start")
	}
	closed := make(chan struct{})
	go func() {
		runtime.Close()
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(10 * time.Second):
		t.Fatal("managed shutdown deadlocked against its active callback")
	}
	require.NoError(t, pg.Pool.Ping(t.Context()))
}
