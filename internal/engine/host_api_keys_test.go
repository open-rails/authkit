package engine

import (
	"bytes"
	"context"
	"runtime/pprof"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/puddle/v2"
	"github.com/open-rails/authkit/internal/db"
	"github.com/stretchr/testify/require"
)

func TestCloseWithPendingAPIKeyTouch(t *testing.T) {
	// A lazy pool needs no database connection. The touch starts only after
	// shutdown, modeling a goroutine delayed until its request has finished.
	pool, err := pgxpool.New(context.Background(), "postgres://unused:unused@localhost/unused?pool_min_conns=0")
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	client := &Engine{pg: pool, q: db.New(pool)}
	client.Close(context.Background())
	client.Close(context.Background())

	_, err = pool.Exec(context.Background(), "SELECT 1")
	require.ErrorIs(t, err, puddle.ErrClosedPool, "Close must still release the owned pool")

	const label = "authkit-pending-api-key-touch"
	pprof.Do(context.Background(), pprof.Labels(label, t.Name()), func(context.Context) {
		client.touchAccessTokenAsync("00000000-0000-0000-0000-000000000001")
	})
	require.Eventually(t, func() bool {
		var profile bytes.Buffer
		require.NoError(t, pprof.Lookup("goroutine").WriteTo(&profile, 1))
		return !strings.Contains(profile.String(), `"`+label+`":"`+t.Name()+`"`)
	}, time.Second, time.Millisecond, "pending touch must exit after pool shutdown")
}
