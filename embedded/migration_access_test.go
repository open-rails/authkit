package embedded

import (
	"context"
	"crypto"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/open-rails/authkit/jwtkit"
	"github.com/stretchr/testify/require"
)

func TestApplyMigrationsProvisionsRuntimePool(t *testing.T) {
	for _, schema := range []string{"profiles", "shop_profiles"} {
		t.Run(schema, func(t *testing.T) {
			pg := testdb.EmptyScratchPostgres(t)
			runtimePool := migrationRuntimePool(t, pg)
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			defer cancel()
			_, err := pg.Pool.Exec(ctx, "CREATE TABLE public.host_data(id bigserial); CREATE TABLE public.river_job(id bigserial)")
			require.NoError(t, err)
			adminCfg := pg.Pool.Config()
			adminCfg.MaxConns = 1
			admin, err := pgxpool.NewWithConfig(ctx, adminCfg)
			require.NoError(t, err)
			t.Cleanup(admin.Close)
			opts := MigrationOptions{RuntimePool: runtimePool, River: RiverFromHost()}
			start := make(chan struct{})
			results := make(chan error, 6)
			for range 6 {
				go func() {
					<-start
					results <- ApplyMigrations(ctx, admin, schema, opts)
				}()
			}
			close(start)
			for range 6 {
				select {
				case err := <-results:
					if err != nil {
						t.Errorf("concurrent provisioning failed: %v", err)
					}
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
			}
			if t.Failed() {
				t.FailNow()
			}
			// Hosts may harden PUBLIC defaults. Reinitialization must explicitly
			// supply the function permission used by canonical-name triggers.
			_, err = admin.Exec(ctx, "REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA "+pgx.Identifier{schema}.Sanitize()+" FROM PUBLIC")
			require.NoError(t, err)
			require.NoError(t, ApplyMigrations(ctx, admin, schema, opts))
			assertMigrationRuntimeUser(t, runtimePool)
			for _, table := range []string{"public.host_data", "public.river_job", "public.migrations"} {
				var allowed bool
				require.NoError(t, runtimePool.QueryRow(ctx, "SELECT has_table_privilege(current_user,$1,'SELECT,INSERT,UPDATE,DELETE')", table).Scan(&allowed))
				require.False(t, allowed, "host River and unrelated objects retain host-owned access: "+table)
			}
			var canCreate bool
			require.NoError(t, runtimePool.QueryRow(ctx, "SELECT has_schema_privilege(current_user,$1,'CREATE')", schema).Scan(&canCreate))
			require.False(t, canCreate)

			signer, err := jwtkit.NewRSASigner(2048, "runtime-access-test")
			require.NoError(t, err)
			cfg := maintenanceConfig()
			cfg.Schema = schema
			cfg.Keys.VerifyOnly = false
			client, err := newEngineWithKeys(cfg, Keyset{Active: signer, PublicKeys: map[string]crypto.PublicKey{signer.KID(): signer.PublicKey()}}, Deps{Postgres: runtimePool, River: opts.River})
			require.NoError(t, err)
			t.Cleanup(client.Close)
			registered, err := client.Register(ctx, RegisterInput{Identifier: "runtime@example.test", Username: "runtimeuser", Password: "Pool-Test-Password-49!"})
			require.NoError(t, err)
			require.Equal(t, RegisterSessionIssued, registered.Kind)
			require.NotEmpty(t, registered.Session.AccessToken)
			user, err := client.GetUserByEmail(ctx, "runtime@example.test")
			require.NoError(t, err)
			require.NotEmpty(t, user.ID)
			byName, err := client.GetUserByUsername(ctx, "runtimeuser")
			require.NoError(t, err)
			require.Equal(t, user.ID, byName.ID)
			client.Close()
			require.NoError(t, admin.Ping(ctx))
			require.NoError(t, runtimePool.Ping(ctx), "the initializer and client must leave the host pool open")
			var searchPath string
			require.NoError(t, runtimePool.QueryRow(ctx, "SHOW search_path").Scan(&searchPath))
			require.Equal(t, "public", searchPath)
		})
	}
}

func TestApplyMigrationsRuntimeIdentityValidation(t *testing.T) {
	pg := testdb.EmptyScratchPostgres(t)
	runtimePool := migrationRuntimePool(t, pg)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	t.Run("wrong_database", func(t *testing.T) {
		cfg := runtimePool.Config()
		cfg.ConnConfig.Database = "postgres"
		otherDatabase, err := pgxpool.NewWithConfig(ctx, cfg)
		require.NoError(t, err)
		defer otherDatabase.Close()
		err = ApplyMigrations(ctx, pg.Pool, "profiles", MigrationOptions{RuntimePool: otherDatabase})
		require.ErrorContains(t, err, "same database")
	})
	t.Run("unavailable_runtime", func(t *testing.T) {
		closed, err := pgxpool.NewWithConfig(ctx, runtimePool.Config())
		require.NoError(t, err)
		closed.Close()
		err = ApplyMigrations(ctx, pg.Pool, "profiles", MigrationOptions{RuntimePool: closed})
		require.ErrorContains(t, err, "identify runtime database user")
	})
	var exists bool
	require.NoError(t, pg.Pool.QueryRow(ctx, "SELECT to_regnamespace('profiles') IS NOT NULL").Scan(&exists))
	require.False(t, exists, "bad runtime configuration must fail before DDL or grants")
	// An omitted runtime pool retains the existing migration-only contract.
	require.NoError(t, ApplyMigrations(ctx, pg.Pool, "profiles", MigrationOptions{River: RiverFromHost()}))
	var allowed bool
	require.NoError(t, runtimePool.QueryRow(ctx, "SELECT has_schema_privilege(current_user,'profiles','USAGE')").Scan(&allowed))
	require.False(t, allowed)

	// The host may switch roles when connecting. Grant the actual session user,
	// not the privileged login stored in pgx's connection configuration.
	var runtimeUser string
	require.NoError(t, runtimePool.QueryRow(ctx, "SELECT current_user").Scan(&runtimeUser))
	cfg := pg.Pool.Config()
	cfg.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		_, err := conn.Exec(ctx, "SET ROLE "+pgx.Identifier{runtimeUser}.Sanitize())
		return err
	}
	rolePool, err := pgxpool.NewWithConfig(ctx, cfg)
	require.NoError(t, err)
	defer rolePool.Close()
	require.NoError(t, ApplyMigrations(ctx, pg.Pool, "profiles", MigrationOptions{RuntimePool: rolePool, River: RiverFromHost()}))
	require.NoError(t, runtimePool.QueryRow(ctx, "SELECT has_schema_privilege(current_user,'profiles','USAGE')").Scan(&allowed))
	require.True(t, allowed)
	assertMigrationRuntimeUser(t, runtimePool)
}

// The test host creates one real login. The library must discover its identity
// and grant directly; no memberships, SET ROLE, or host GRANTs are needed.
func migrationRuntimePool(t *testing.T, pg *testdb.Postgres) *pgxpool.Pool {
	t.Helper()
	role := "ak-runtime-\"" + uuid.NewString()
	quoted := pgx.Identifier{role}.Sanitize()
	_, err := pg.Pool.Exec(t.Context(), "CREATE ROLE "+quoted+" LOGIN PASSWORD 'runtime_test' NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION")
	require.NoError(t, err)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_, err := pg.Pool.Exec(ctx, "DROP OWNED BY "+quoted)
		require.NoError(t, err)
		_, err = pg.Pool.Exec(ctx, "DROP ROLE "+quoted)
		require.NoError(t, err)
	})
	cfg := pg.Pool.Config()
	cfg.ConnConfig.User, cfg.ConnConfig.Password = role, "runtime_test"
	cfg.ConnConfig.RuntimeParams["search_path"] = "public"
	cfg.MaxConns = 1
	pool, err := pgxpool.NewWithConfig(t.Context(), cfg)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	assertMigrationRuntimeUser(t, pool)
	return pool
}

func assertMigrationRuntimeUser(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	var login, privileged bool
	var memberships int
	require.NoError(t, pool.QueryRow(t.Context(), `SELECT rolcanlogin,
		rolsuper OR rolbypassrls OR rolcreatedb OR rolcreaterole OR rolreplication,
		(SELECT count(*) FROM pg_auth_members WHERE member = r.oid)
		FROM pg_roles r WHERE rolname = current_user`).Scan(&login, &privileged, &memberships))
	require.True(t, login)
	require.False(t, privileged)
	require.Zero(t, memberships, "runtime access must not create library-role memberships")
}
