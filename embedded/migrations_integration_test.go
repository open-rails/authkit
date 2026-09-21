package embedded

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/open-rails/authkit/internal/testdb"
	"github.com/stretchr/testify/require"
)

func TestApplyMigrationsCreatesSchemaBeforeClientConstruction(t *testing.T) {
	ctx := context.Background()
	pg := testdb.EmptyScratchPostgres(t)

	require.NoError(t, ApplyMigrations(ctx, pg.Pool, ""))
	var usersTable bool
	require.NoError(t, pg.Pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM information_schema.tables
			WHERE table_schema = 'profiles' AND table_name = 'users'
		)`).Scan(&usersTable))
	require.True(t, usersTable)

	client, err := NewWithKeys(
		Config{Token: TokenConfig{Issuer: "https://migrations.test"}},
		Keyset{},
		Deps{Postgres: pg.Pool},
	)
	require.NoError(t, err)
	client.Close()
}

func TestApplyMigrationsSerializesManagedRiverWithSingleConnectionPool(t *testing.T) {
	for _, schema := range []string{"public", "shared_jobs"} {
		t.Run(schema, func(t *testing.T) {
			pg := testdb.EmptyScratchPostgres(t)
			runtimePool := migrationRuntimePool(t, pg)
			cfg := pg.Pool.Config()
			cfg.MaxConns = 1
			pool, err := pgxpool.NewWithConfig(t.Context(), cfg)
			require.NoError(t, err)
			defer pool.Close()
			// This test deadline catches holding a pooled advisory-lock connection
			// while waiting for another connection from that same single-slot pool.
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			defer cancel()
			start := make(chan struct{})
			results := make(chan error, 6)
			for range 6 {
				go func() {
					<-start
					results <- ApplyMigrations(ctx, pool, "profiles", MigrationOptions{RiverSchema: schema, RuntimePool: runtimePool})
				}()
			}
			close(start)
			for range 6 {
				require.NoError(t, <-results)
			}
			var exists bool
			require.NoError(t, pool.QueryRow(ctx, "SELECT to_regclass($1) IS NOT NULL", schema+".river_job").Scan(&exists))
			require.True(t, exists)
			require.NoError(t, ApplyMigrations(ctx, pool, "profiles", MigrationOptions{RiverSchema: schema, RuntimePool: runtimePool}))
			assertMigrationRuntimeUser(t, runtimePool)
		})
	}
}
