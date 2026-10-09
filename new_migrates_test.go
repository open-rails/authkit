package authkit_test

import (
	"context"
	"testing"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/iam"
	pgmigrations "github.com/open-rails/authkit/internal/migrations/postgres"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/open-rails/migratekit"
	"github.com/stretchr/testify/require"
)

// minimalConfig is the least a host configures: who issues the tokens, and a
// second factor root's owner can enroll.
func minimalConfig() authkit.Config {
	return authkit.Config{
		Token:     authkit.TokenConfig{Issuer: "https://example.com", IssuedAudiences: []string{"app"}},
		TwoFactor: authkit.TwoFactorConfig{TOTPSecretKey: testTOTPKey},
	}
}

func requireTable(t *testing.T, pg *testdb.Postgres, table string) {
	t.Helper()
	var exists bool
	require.NoError(t, pg.Pool.QueryRow(t.Context(), "SELECT to_regclass($1) IS NOT NULL", table).Scan(&exists))
	require.True(t, exists, table)
}

// New creates AuthKit's and River's tables on an empty database, with the
// least configuration, and the client works.
func TestNewMigratesAnEmptyDatabase(t *testing.T) {
	pg := testdb.EmptyScratchPostgres(t)
	auth, err := authkit.New(t.Context(), minimalConfig(), authkit.Deps{Postgres: pg.Pool, KeySource: testKeys()})
	require.NoError(t, err)
	t.Cleanup(func() { _ = auth.Close(context.Background()) })
	requireTable(t, pg, "profiles.users")
	requireTable(t, pg, "public.river_job")
	u, err := auth.CreateUser(t.Context(), iam.NewUser{Username: "first"})
	require.NoError(t, err)
	require.NotEmpty(t, u.ID)
}

// Replicas booting together on a fresh schema migrate it once and all start.
func TestConcurrentNewOnAFreshSchema(t *testing.T) {
	pg := testdb.EmptyScratchPostgres(t)
	cfg := minimalConfig()
	cfg.Database = authkit.DatabaseConfig{Schema: "accounts", RiverSchema: "jobs"}
	const replicas = 6
	start := make(chan struct{})
	results := make(chan error, replicas)
	for range replicas {
		go func() {
			<-start
			auth, err := authkit.New(t.Context(), cfg, authkit.Deps{Postgres: pg.Pool, KeySource: testKeys()})
			if err == nil {
				err = auth.Close(context.Background())
			}
			results <- err
		}()
	}
	close(start)
	for range replicas {
		require.NoError(t, <-results)
	}
	requireTable(t, pg, "accounts.users")
	requireTable(t, pg, "jobs.river_job")
	var applied int
	require.NoError(t, pg.Pool.QueryRow(t.Context(), "SELECT count(*) FROM public.migrations WHERE app = 'authkit' AND schema = 'accounts'").Scan(&applied))
	all, err := migratekit.LoadFromFS(pgmigrations.FS)
	require.NoError(t, err)
	require.Equal(t, len(all), applied, "each migration applied once")
}

// Rolling back: this build boots against a schema a newer build already
// migrated (one AuthKit database shared by two apps upgraded one at a time),
// and leaves the newer migrations' work in place.
func TestNewBootsOnASchemaANewerBuildMigrated(t *testing.T) {
	pg := testdb.EmptyScratchPostgres(t)
	ctx := t.Context()
	first, err := authkit.New(ctx, minimalConfig(), authkit.Deps{Postgres: pg.Pool, KeySource: testKeys()})
	require.NoError(t, err)
	require.NoError(t, first.Close(context.Background()))

	// A newer build adds an AuthKit migration and a River one.
	ours, err := migratekit.LoadFromFS(pgmigrations.FS)
	require.NoError(t, err)
	newer := append(ours, migratekit.Migration{Name: "9000_from_a_newer_build.up.sql", Content: "CREATE TABLE newer_build_table (id bigint PRIMARY KEY);\n"})
	migrator, err := migratekit.NewPostgresFromPGXPool(pg.Pool, "authkit")
	require.NoError(t, err)
	t.Cleanup(func() { _ = migrator.Close() })
	require.NoError(t, migrator.WithSchema("profiles").ApplyMigrations(ctx, newer))
	_, err = pg.Pool.Exec(ctx, "INSERT INTO public.river_migration (line, version) VALUES ('main', 9000)")
	require.NoError(t, err)

	older, err := authkit.New(ctx, minimalConfig(), authkit.Deps{Postgres: pg.Pool, KeySource: testKeys()})
	require.NoError(t, err, "an older build boots on a newer-migrated schema")
	t.Cleanup(func() { _ = older.Close(context.Background()) })
	_, err = older.CreateUser(ctx, iam.NewUser{Username: "after-rollback"})
	require.NoError(t, err)
	requireTable(t, pg, "profiles.newer_build_table")
	var kept bool
	require.NoError(t, pg.Pool.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM public.migrations WHERE app = 'authkit' AND schema = 'profiles' AND filename = $1)", "9000_from_a_newer_build.up.sql").Scan(&kept))
	require.True(t, kept, "the newer build's ledger row stays")
}
