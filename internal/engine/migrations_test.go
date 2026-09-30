package engine

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/open-rails/authkit/internal/config"
	pgmigrations "github.com/open-rails/authkit/internal/migrations/postgres"
	"github.com/open-rails/authkit/internal/migrations/retired"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/open-rails/migratekit"
	"github.com/stretchr/testify/require"
)

func TestMigrateSerializesManagedRiverWithSingleConnectionPool(t *testing.T) {
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
					results <- Migrate(ctx, pool, config.Config{Schema: "profiles", River: config.RiverConfig{Schema: schema}}, config.MigrateOptions{RuntimePool: runtimePool})
				}()
			}
			close(start)
			for range 6 {
				require.NoError(t, <-results)
			}
			var exists bool
			require.NoError(t, pool.QueryRow(ctx, "SELECT to_regclass($1) IS NOT NULL", schema+".river_job").Scan(&exists))
			require.True(t, exists)
			require.NoError(t, Migrate(ctx, pool, config.Config{Schema: "profiles", River: config.RiverConfig{Schema: schema}}, config.MigrateOptions{RuntimePool: runtimePool}))
			assertMigrationRuntimeUser(t, runtimePool)
		})
	}
}

// A database the v0.148 chain completed converts in place: the ledger records
// the baseline, the schema equals a fresh one, every row stays, and sessions
// and passwords written before the upgrade keep working.
func TestRetiredChainConvertsInPlace(t *testing.T) {
	ctx := t.Context()
	pg := testdb.EmptyScratchPostgres(t)
	db := sqlDB(t, pg.URL)
	require.NoError(t, migratekit.NewPostgres(db, "authkit").WithSchema("profiles").ApplyMigrations(ctx, retired.Chain()))

	// The baseline's schema is the chain's, so today's engine serves it as v0.148 did.
	f := newAccountFlow(t, pg.Pool, testConfig(), config.Deps{})
	owner, member := newUser(t, f.engine, "retired"), newUser(t, f.engine, "retired")
	session := f.expect(200, f.post("/password/login", map[string]any{"identifier": *owner.Email, "password": testPassword})).tokens()
	var group string
	require.NoError(t, pg.Pool.QueryRow(ctx, `INSERT INTO permission_groups(persona) VALUES ('channel') RETURNING id::text`).Scan(&group))
	for _, seed := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO group_user_roles(permission_group_id, user_id, role) VALUES ($1::uuid, $2::uuid, 'channel:owner'), ($1::uuid, $3::uuid, 'channel:member')`, []any{group, owner.ID, member.ID}},
		{`INSERT INTO api_keys(permission_group_id, key_id, secret_hash, name, created_by, role, catalog_issuer) VALUES ($1::uuid, 'ak_retired', '\x01', 'ci', $2::uuid, 'channel:member', 'https://example.com')`, []any{group, owner.ID}},
		{`INSERT INTO group_invite_links(permission_group_id, role, invited_by, code_hash) VALUES ($1::uuid, 'channel:member', $2::uuid, 'retired-code')`, []any{group, owner.ID}},
		{`INSERT INTO mfa_factors(user_id, method, totp_secret, is_default) VALUES ($1::uuid, 'totp', '\x02', true)`, []any{member.ID}},
		{`INSERT INTO user_device_keys(user_id, public_key) VALUES ($1::uuid, decode(repeat('ab', 32), 'hex'))`, []any{member.ID}},
	} {
		_, err := pg.Pool.Exec(ctx, seed.sql, seed.args...)
		require.NoError(t, err)
	}
	before := tableRows(t, db, "profiles")
	for _, table := range []string{"users", "user_passwords", "name_claims", "refresh_sessions", "permission_groups", "group_user_roles", "api_keys", "group_invite_links", "mfa_factors", "user_device_keys"} {
		require.NotRegexp(t, "^0 ", before[table], table)
	}

	cfg := config.Config{Schema: "profiles", River: config.RiverConfig{HostOwned: true}}
	require.NoError(t, Migrate(ctx, pg.Pool, cfg, config.MigrateOptions{}))
	require.NoError(t, Migrate(ctx, pg.Pool, cfg, config.MigrateOptions{}), "a second boot converts nothing")
	require.Equal(t, before, tableRows(t, db, "profiles"), "the conversion changes no row")

	baseline, err := migratekit.LoadFromFS(pgmigrations.FS)
	require.NoError(t, err)
	fresh := config.Config{Schema: "fresh_baseline", River: config.RiverConfig{HostOwned: true}}
	require.NoError(t, Migrate(ctx, pg.Pool, fresh, config.MigrateOptions{}))
	for schema, conversions := range map[string]bool{"profiles": true, "fresh_baseline": false} {
		require.Equal(t, []string{baseline[0].Name + " " + migratekit.ContentDigest(baseline[0].Content)}, ledger(t, db, schema), schema)
		var converted int
		require.NoError(t, db.QueryRowContext(ctx, `SELECT count(*) FROM public.migration_repairs WHERE app = 'authkit' AND schema = $1 AND verb = 'convert'`, schema).Scan(&converted))
		require.Equal(t, conversions, converted > 0, schema)
	}
	require.Empty(t, testdb.CatalogDiff(testdb.SchemaCatalog(t, db, "profiles"), testdb.SchemaCatalog(t, db, "fresh_baseline")))

	refreshed := f.expect(200, f.post("/token", map[string]any{"grant_type": "refresh_token", "refresh_token": session.RefreshToken})).tokens()
	f.session(refreshed, "pwd")
	f.session(f.expect(200, f.post("/password/login", map[string]any{"identifier": *owner.Username, "password": testPassword})).tokens(), "pwd")
}

// A schema the v0.148 chain left part-way, or an older chain built, is refused
// before anything changes, naming the release to upgrade through. A complete
// chain whose schema was edited by hand is not what the chain built, so the
// conversion refuses it too.
func TestRetiredChainRefusesWhatItCannotConvert(t *testing.T) {
	older := retired.Chain()[0]
	older.Content += "\nCREATE TABLE legacy_marker (id int);\n"
	for name, tc := range map[string]struct {
		chain []migratekit.Migration
		edit  string
		want  string
	}{
		"part-way": {chain: retired.Chain()[:10], want: "last 0010_account_events.up.sql"},
		"older":    {chain: []migratekit.Migration{older}, want: "last 0001_schema.up.sql"},
		"edited":   {chain: retired.Chain(), edit: `ALTER TABLE profiles.users ADD COLUMN nickname text`, want: "nickname"},
	} {
		t.Run(name, func(t *testing.T) {
			ctx := t.Context()
			pg := testdb.EmptyScratchPostgres(t)
			db := sqlDB(t, pg.URL)
			require.NoError(t, migratekit.NewPostgres(db, "authkit").WithSchema("profiles").ApplyMigrations(ctx, tc.chain))
			if tc.edit != "" {
				_, err := db.ExecContext(ctx, tc.edit)
				require.NoError(t, err)
			}
			schema, recorded := testdb.SchemaCatalog(t, db, "profiles"), ledger(t, db, "profiles")

			err := Migrate(ctx, pg.Pool, config.Config{Schema: "profiles", River: config.RiverConfig{HostOwned: true}}, config.MigrateOptions{})
			require.ErrorContains(t, err, tc.want)
			if tc.edit == "" {
				require.ErrorContains(t, err, "Upgrade through AuthKit v0.148.x, then this version")
			} else {
				require.ErrorIs(t, err, migratekit.ErrSchemaMismatch)
			}
			require.Equal(t, schema, testdb.SchemaCatalog(t, db, "profiles"), "the schema is untouched")
			require.Equal(t, recorded, ledger(t, db, "profiles"), "the ledger is untouched")
		})
	}
}

// ledger lists schema's AuthKit ledger rows as "filename digest", in order.
func ledger(t *testing.T, db *sql.DB, schema string) []string {
	t.Helper()
	rows, err := db.QueryContext(t.Context(), `SELECT filename || ' ' || content_sha256 FROM public.migrations WHERE app = 'authkit' AND schema = $1 ORDER BY sequence`, schema)
	require.NoError(t, err)
	defer rows.Close()
	var out []string
	for rows.Next() {
		var row string
		require.NoError(t, rows.Scan(&row))
		out = append(out, row)
	}
	require.NoError(t, rows.Err())
	return out
}

// tableRows fingerprints the rows of every table in schema: "<count> <md5>".
func tableRows(t *testing.T, db *sql.DB, schema string) map[string]string {
	t.Helper()
	ctx := t.Context()
	rows, err := db.QueryContext(ctx, `SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = $1 AND c.relkind = 'r'`, schema)
	require.NoError(t, err)
	var tables []string
	for rows.Next() {
		var table string
		require.NoError(t, rows.Scan(&table))
		tables = append(tables, table)
	}
	require.NoError(t, rows.Err())
	rows.Close()
	out := map[string]string{}
	for _, table := range tables {
		var print string
		require.NoError(t, db.QueryRowContext(ctx, `SELECT count(*)::text || ' ' || md5(COALESCE(string_agg(r::text, E'\n' ORDER BY r::text), '')) FROM `+
			pgx.Identifier{schema, table}.Sanitize()+` r`).Scan(&print))
		out[table] = print
	}
	return out
}

func sqlDB(t *testing.T, url string) *sql.DB {
	t.Helper()
	db, err := sql.Open("pgx", url)
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })
	return db
}
