package embedded

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/stretchr/testify/require"
)

func TestRiverDatabaseIdentityPoolCopiesAndOneSlot(t *testing.T) {
	pg := testdb.EmptyScratchPostgres(t)
	config := pg.Pool.Config().Copy()
	config.MaxConns = 1
	first, err := pgxpool.NewWithConfig(t.Context(), config)
	require.NoError(t, err)
	t.Cleanup(first.Close)
	tx, err := first.Begin(t.Context())
	require.NoError(t, err)
	require.NoError(t, requireSameRiverDatabase(t.Context(), first, first))
	require.NoError(t, tx.Rollback(t.Context()))
	copy, err := schemaPool(first, "profiles")
	require.NoError(t, err)
	t.Cleanup(copy.Close)
	require.NotSame(t, first, copy)
	require.NoError(t, requireSameRiverDatabase(t.Context(), first, copy))
	require.NoError(t, requireSameRiverDatabase(t.Context(), copy, first))
	other := testdb.EmptyScratchPostgres(t)
	require.ErrorContains(t, requireSameRiverDatabase(t.Context(), first, other.Pool), "same PostgreSQL database")
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	require.ErrorIs(t, requireSameRiverDatabase(cancelled, first, copy), context.Canceled)
	require.NoError(t, first.Ping(t.Context()))
	require.NoError(t, copy.Ping(t.Context()))
	require.NoError(t, other.Pool.Ping(t.Context()))
}
