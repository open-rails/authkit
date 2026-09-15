package authkitmigrate_test

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authkitmigrate"
	"github.com/open-rails/authkit/embedded"
	"github.com/open-rails/authkit/internal/testdb"
	migrations "github.com/open-rails/authkit/migrations/postgres"
	"github.com/open-rails/migratekit"
	"github.com/stretchr/testify/require"
)

// One fresh database exercises concurrent install, repeat/startup validation,
// host-pool isolation, raw-FS/custom-schema interoperability, and real identity
// operations. Unknown ledgers and pre-v1 tables are refused without touching
// unrelated host records. No test depends on a historical migration number.
func TestFreshSchemaWorkflow(t *testing.T) {
	pg := testdb.EmptyScratchPostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	config := pg.Pool.Config()
	config.MaxConns = 1
	pool, err := pgxpool.NewWithConfig(ctx, config)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	_, err = pool.Exec(ctx, `CREATE SCHEMA tenant_a; CREATE TABLE tenant_a.host_records(value text); INSERT INTO tenant_a.host_records VALUES ('keep')`)
	require.NoError(t, err)
	migrator := authkitmigrate.New(pool, nil)
	require.Error(t, migrator.Validate(ctx))

	// Holding the entire host pool proves migrations use separate connections;
	// concurrent replicas must still install exactly one consistent schema.
	held, err := pool.Acquire(ctx)
	require.NoError(t, err)
	defer held.Release()
	ready := make(chan struct{})
	results := make([]error, 2)
	var group sync.WaitGroup
	for i := range results {
		group.Add(1)
		go func() { defer group.Done(); <-ready; results[i] = authkitmigrate.New(pool, nil).Migrate(ctx) }()
	}
	close(ready)
	group.Wait()
	for _, err := range results {
		require.NoError(t, err)
	}
	for _, setting := range []string{"lock_timeout", "statement_timeout"} {
		var value string
		require.NoError(t, held.QueryRow(ctx, "SHOW "+setting).Scan(&value))
		require.Equal(t, "0", value)
	}
	held.Release()
	require.NoError(t, migrator.Validate(ctx))
	require.NoError(t, migrator.Migrate(ctx))

	// Raw-FS runners keep the canonical app/schema ledger namespace. The wrapper
	// validates their receipt, including the rendered custom-schema digest.
	rawDB := stdlib.OpenDB(*config.ConnConfig.Copy())
	defer rawDB.Close()
	fsys, err := migrations.FSForSchema("tenant_a")
	require.NoError(t, err)
	chain, err := migratekit.LoadFromFS(fsys)
	require.NoError(t, err)
	raw := migratekit.NewPostgres(rawDB, "authkit").WithSchema("tenant_a", "profiles")
	require.NoError(t, raw.ApplyMigrations(ctx, chain))
	custom := authkitmigrate.New(pool, &authkitmigrate.Config{Schema: "tenant_a"})
	require.NoError(t, custom.Validate(ctx))
	require.NoError(t, custom.Migrate(ctx))

	for _, schema := range []string{"profiles", "tenant_a"} {
		client, err := embedded.NewWithKeys(embedded.Config{Schema: schema}, embedded.Keyset{}, embedded.Deps{Postgres: pool})
		require.NoError(t, err)
		user, err := client.CreateUser(ctx, "baseline@example.test", "baseline_user")
		require.NoError(t, err)
		require.NoError(t, client.ChangePassword(ctx, user.ID, "", "Baseline-password-123", nil))
		require.NoError(t, client.CheckUserPassword(ctx, user.ID, "Baseline-password-123"))
		require.NoError(t, client.UpdateUsername(ctx, user.ID, "baseline_renamed"))
		alias, err := client.ResolveUsername(ctx, "baseline_user")
		require.NoError(t, err)
		require.Equal(t, user.ID, alias.ID)
		require.True(t, alias.IsAlias)
		require.ErrorIs(t, client.UpdateUsername(ctx, user.ID, "another_name"), authkit.ErrRenameRateLimited)
	}
	var retained string
	require.NoError(t, pool.QueryRow(ctx, `SELECT value FROM tenant_a.host_records`).Scan(&retained))
	require.Equal(t, "keep", retained)
	var removedTables int
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM information_schema.tables WHERE table_schema IN ('profiles','tenant_a') AND table_name IN ('remote_application_attribute_defs','user_renames','permission_group_slug_tombstones','group_membership_invites')`).Scan(&removedTables))
	require.Zero(t, removedTables)

	original := chain[0]
	key := migratekit.Prefix(original.Name)
	for _, mutation := range []string{"filename = ''", "filename = 'old_schema.up.sql'", "content_sha256 = ''", "content_sha256 = repeat('0',64)", "semantic_sha256 = ''", "status = 'failed'"} {
		_, err := pool.Exec(ctx, `UPDATE public.migrations SET `+mutation+` WHERE app='authkit' AND database='postgres' AND schema='tenant_a' AND name=$1`, key)
		require.NoError(t, err)
		require.ErrorContains(t, custom.Validate(ctx), "unsupported schema ledger")
		require.ErrorContains(t, custom.Migrate(ctx), "unsupported schema ledger")
		_, err = pool.Exec(ctx, `UPDATE public.migrations SET filename=$2, content_sha256=$3, semantic_sha256=$4, status='applied' WHERE app='authkit' AND database='postgres' AND schema='tenant_a' AND name=$1`, key, original.Name, migratekit.ContentDigest(original.Content), migratekit.SemanticContentDigest(original.Content))
		require.NoError(t, err)
	}
	require.NoError(t, custom.Validate(ctx))

	// Raw-FS runners also hit the DDL guard rather than adopting old tables.
	_, err = pool.Exec(ctx, `CREATE SCHEMA old_auth; CREATE TABLE old_auth.users(value text); INSERT INTO old_auth.users VALUES ('retain'); INSERT INTO public.migrations(app,database,schema,name,filename,content_sha256) VALUES ('authkit','postgres','old_auth','1','0001_auth_schema.up.sql','old')`)
	require.NoError(t, err)
	old := authkitmigrate.New(pool, &authkitmigrate.Config{Schema: "old_auth"})
	require.ErrorContains(t, old.Migrate(ctx), "unsupported schema ledger")
	require.ErrorContains(t, old.Validate(ctx), "unsupported schema ledger")
	fsys, err = migrations.FSForSchema("old_auth")
	require.NoError(t, err)
	oldChain, err := migratekit.LoadFromFS(fsys)
	require.NoError(t, err)
	require.ErrorContains(t, migratekit.NewPostgres(rawDB, "authkit").WithSchema("old_auth", "profiles").ApplyMigrations(ctx, oldChain), "unsupported AuthKit schema")
	require.NoError(t, pool.QueryRow(ctx, `SELECT value FROM old_auth.users`).Scan(&retained))
	require.Equal(t, "retain", retained)
	require.NoError(t, pool.QueryRow(ctx, `SELECT value FROM tenant_a.host_records`).Scan(&retained))
	require.Equal(t, "keep", retained)

	for _, schema := range []string{"Bad-Schema", "public; DROP SCHEMA profiles", strings.Repeat("a", 64)} {
		require.Error(t, authkitmigrate.New(pool, &authkitmigrate.Config{Schema: schema}).Migrate(ctx))
	}
	var nilPool *pgxpool.Pool
	require.Error(t, authkitmigrate.New(nilPool, nil).Migrate(ctx))
}
