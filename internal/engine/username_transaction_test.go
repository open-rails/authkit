package engine

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/open-rails/authkit/internal/config"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/stretchr/testify/require"
)

func TestGeneratedImportUsesCurrentTransaction(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	poolConfig := pg.Pool.Config()
	poolConfig.MinConns, poolConfig.MaxConns = 0, 1
	pool, err := pgxpool.NewWithConfig(t.Context(), poolConfig)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	cfg := testConfig()
	cfg.Username.RandomNames = []string{"anime"}
	e := newTestEngine(t, cfg, config.Deps{Postgres: pool})

	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	tx, err := e.pg.Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(t.Context())
	u, err := e.importGeneratedUser(ctx, tx, newAccount{Email: "generated@example.test"})
	require.NoError(t, err, "availability must use the already-held transaction connection")
	require.Regexp(t, `^anime[0-9]{3}$`, deref(u.Username))
	require.NoError(t, tx.Rollback(t.Context()))
	_, err = e.q.UserByID(t.Context(), u.ID)
	require.ErrorIs(t, err, pgx.ErrNoRows, "the enclosing transaction owns the generated account")
}
