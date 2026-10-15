package engine

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/open-rails/authkit/internal/config"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/stretchr/testify/require"
)

func TestSkipMigrations(t *testing.T) {
	ctx := t.Context()
	pg := testdb.EmptyScratchPostgres(t)
	cfg := maintenanceConfig()
	cfg.Database = config.DatabaseConfig{Schema: "profiles", RiverSchema: "auth_jobs", SkipMigrations: true}
	client, err := New(ctx, cfg, config.Deps{Postgres: pg.Pool})
	require.Nil(t, client)
	require.ErrorIs(t, err, ErrMigrationsRequired)
	var exists bool
	require.NoError(t, pg.Pool.QueryRow(ctx, "SELECT to_regclass('public.migrations') IS NOT NULL OR to_regclass('profiles.users') IS NOT NULL OR to_regclass('auth_jobs.river_job') IS NOT NULL").Scan(&exists))
	require.False(t, exists, "failed startup created schema objects")
	// Explicit migration works even when the runtime configuration opts out.
	require.NoError(t, Migrate(ctx, pg.Pool, cfg.Database, MigrationOptions{LegacyTenantID: testdb.DefaultTenantID}))
	readonlyConfig := pg.Pool.Config()
	readonlyConfig.ConnConfig.RuntimeParams["default_transaction_read_only"] = "on"
	readonly, err := pgxpool.NewWithConfig(ctx, readonlyConfig)
	require.NoError(t, err)
	t.Cleanup(readonly.Close)
	require.NoError(t, validateMigrations(ctx, readonly, cfg.Database), "validation performed DDL or DML")
	_, err = pg.Pool.Exec(ctx, `CREATE FUNCTION public.forbid_runtime_ddl() RETURNS event_trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'runtime attempted DDL'; END $$;
CREATE EVENT TRIGGER forbid_runtime_ddl ON ddl_command_start EXECUTE FUNCTION public.forbid_runtime_ddl()`)
	require.NoError(t, err)
	client, err = New(ctx, cfg, config.Deps{Postgres: pg.Pool})
	require.NoError(t, err)
	require.NoError(t, client.Close(ctx))
	missingRiver := cfg.Database
	missingRiver.RiverSchema = "not_prepared"
	require.ErrorIs(t, validateMigrations(ctx, pg.Pool, missingRiver), ErrMigrationsRequired)
	require.NoError(t, pg.Pool.QueryRow(ctx, "SELECT to_regclass('not_prepared.river_job') IS NOT NULL").Scan(&exists))
	require.False(t, exists)
	_, err = pg.Pool.Exec(ctx, "UPDATE public.migrations SET status='failed' WHERE app='authkit' AND schema='profiles' AND sequence=(SELECT max(sequence) FROM public.migrations WHERE app='authkit' AND schema='profiles')")
	require.NoError(t, err)
	require.ErrorIs(t, validateMigrations(ctx, pg.Pool, cfg.Database), ErrMigrationsRequired)
	client, err = New(ctx, cfg, config.Deps{Postgres: pg.Pool})
	require.Nil(t, client)
	require.ErrorIs(t, err, ErrMigrationsRequired)
	var failed int
	require.NoError(t, pg.Pool.QueryRow(ctx, "SELECT count(*) FROM public.migrations WHERE app='authkit' AND schema='profiles' AND status='failed'").Scan(&failed))
	require.Equal(t, 1, failed, "validation repaired the ledger")
}

func TestMigrationValidationConnectivityIsNotPending(t *testing.T) {
	for _, cause := range []error{context.Canceled, context.DeadlineExceeded, &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("offline")}, &pgconn.PgError{Code: "57P01", Message: "restarting"}} {
		err := migrationValidationError(cause)
		require.ErrorIs(t, err, cause)
		require.NotErrorIs(t, err, ErrMigrationsRequired)
	}
	missing := &pgconn.PgError{Code: "42P01", Message: "missing relation"}
	err := migrationValidationError(missing)
	require.ErrorIs(t, err, ErrMigrationsRequired)
	require.ErrorIs(t, err, missing)
}
