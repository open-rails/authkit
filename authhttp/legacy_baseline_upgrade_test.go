package authhttp

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/internal/migrations/retired"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/open-rails/authkit/password"
	"github.com/open-rails/migratekit"
	"github.com/stretchr/testify/require"
)

// A database built by a retired baseline (v0.106.2–v0.124.0) upgrades in place:
// the schema ends equal to a fresh one and existing accounts still sign in.
//
// Each case builds the retired schema one way: by running the retired chain as
// those releases did, or by restoring a schema-only pg_dump of a real
// database. AUTHKIT_LEGACY_SCHEMA_DUMPS names such dumps (comma-separated
// paths); each must contain exactly one AuthKit schema.
func TestRetiredBaselineUpgradesInPlace(t *testing.T) {
	type source struct {
		name, schema string
		build        func(t *testing.T, pg *testdb.Postgres, schema string)
	}
	sources := []source{
		{name: "v0.106 chain", schema: "profiles", build: func(t *testing.T, pg *testdb.Postgres, schema string) {
			applyRetired(t, pg, schema, "0001_schema.up.sql")
		}},
		{name: "v0.124 chain", schema: "profiles_v1", build: func(t *testing.T, pg *testdb.Postgres, schema string) {
			applyRetired(t, pg, schema, "0001_schema.up.sql", "0002_recoverable_account_deletion.up.sql")
		}},
	}
	for _, path := range strings.Split(os.Getenv("AUTHKIT_LEGACY_SCHEMA_DUMPS"), ",") {
		if path = strings.TrimSpace(path); path == "" {
			continue
		}
		dump, err := os.ReadFile(path)
		require.NoError(t, err)
		schema := dumpSchema(t, string(dump))
		sources = append(sources, source{name: filepath.Base(path), schema: schema, build: func(t *testing.T, pg *testdb.Postgres, schema string) {
			restoreDump(t, pg, string(dump), schema)
		}})
	}

	for _, src := range sources {
		t.Run(src.name, func(t *testing.T) {
			ctx := t.Context()
			pg := testdb.EmptyScratchPostgres(t)
			src.build(t, pg, src.schema)
			userID, username := seedRetiredAccount(t, pg.Pool, src.schema)

			pool := schemaPool(t, pg.URL, src.schema)
			require.NoError(t, authkit.ApplyMigrations(ctx, pool, src.schema))
			require.NoError(t, authkit.ApplyMigrations(ctx, pool, "fresh_reference"))
			db := sqlDB(t, pg.URL)
			diff, err := migratekit.SchemaDiff(ctx, db, src.schema, "fresh_reference")
			require.NoError(t, err)
			require.Empty(t, diff, "upgraded schema differs from a fresh one")

			var recorded, converted int
			require.NoError(t, db.QueryRowContext(ctx, `SELECT count(*) FROM public.migrations WHERE app='authkit' AND schema=$1`, src.schema).Scan(&recorded))
			require.NoError(t, db.QueryRowContext(ctx, `SELECT count(*) FROM public.migration_repairs WHERE app='authkit' AND schema=$1 AND verb='convert'`, src.schema).Scan(&converted))
			require.Equal(t, 4, recorded)
			require.NotZero(t, converted)
			// A second boot converts nothing and applies nothing.
			require.NoError(t, authkit.ApplyMigrations(ctx, pool, src.schema))

			cfg := newServerTestConfig()
			cfg.Schema = src.schema
			f := newAccountFlow(t, pool, cfg)
			for _, spelling := range []string{username, strings.ToLower(username)} {
				login := f.expect(200, f.post("/password/login", map[string]any{"identifier": spelling, "password": retiredPassword}))
				claims, err := f.service.Verifier().Verify(ctx, login.AccessToken)
				require.NoError(t, err)
				require.Equal(t, userID, claims.UserID, "login as %s", spelling)
			}
			require.Equal(t, username, meUsername(t, f, f.expect(200, f.post("/password/login", map[string]any{"identifier": username, "password": retiredPassword})).AccessToken))
		})
	}
}

// Accounts inside the retired deletion lifecycle need River jobs a conversion
// cannot create, so the upgrade refuses, names the fix and changes nothing.
func TestRetiredBaselineRefusesInFlightDeletion(t *testing.T) {
	ctx := t.Context()
	pg := testdb.EmptyScratchPostgres(t)
	applyRetired(t, pg, "profiles", "0001_schema.up.sql")
	userID, _ := seedRetiredAccount(t, pg.Pool, "profiles")
	_, err := pg.Pool.Exec(ctx, `UPDATE profiles.users SET deleted_at = now() WHERE id = $1`, userID)
	require.NoError(t, err)

	err = authkit.ApplyMigrations(ctx, schemaPool(t, pg.URL, "profiles"), "profiles")
	require.Error(t, err)
	for _, want := range []string{"1 soft-deleted account(s)", "retired deletion lifecycle", "AuthKit v0.124.0", "nothing was changed"} {
		require.Contains(t, err.Error(), want)
	}
	var filename string
	require.NoError(t, pg.Pool.QueryRow(ctx, `SELECT filename FROM public.migrations WHERE app='authkit' AND schema='profiles'`).Scan(&filename))
	require.Equal(t, "0001_schema.up.sql", filename)
	var legacy bool
	require.NoError(t, pg.Pool.QueryRow(ctx, `SELECT to_regclass('profiles.account_erasure_obligations') IS NOT NULL`).Scan(&legacy))
	require.True(t, legacy, "the retired schema is untouched")
}

// A retired schema changed by hand is not what the retired chain built; the
// upgrade refuses with the difference instead of migrating it.
func TestRetiredBaselineRefusesHandEditedSchema(t *testing.T) {
	ctx := t.Context()
	pg := testdb.EmptyScratchPostgres(t)
	applyRetired(t, pg, "profiles", "0001_schema.up.sql")
	_, err := pg.Pool.Exec(ctx, `ALTER TABLE profiles.users ADD COLUMN nickname text`)
	require.NoError(t, err)
	err = authkit.ApplyMigrations(ctx, schemaPool(t, pg.URL, "profiles"), "profiles")
	require.ErrorIs(t, err, migratekit.ErrSchemaMismatch)
	require.Contains(t, err.Error(), "nickname")
}

const retiredPassword = "Retired-baseline-horse-7"

// seedRetiredAccount writes an account the way the retired runtime stored it.
func seedRetiredAccount(t *testing.T, pool *pgxpool.Pool, schema string) (string, string) {
	t.Helper()
	ctx := t.Context()
	id := uuid.NewString()
	username := "Fidika" + strings.ReplaceAll(uuid.NewString()[:8], "-", "")
	hash, err := password.HashArgon2id(retiredPassword)
	require.NoError(t, err)
	s := pgx.Identifier{schema}.Sanitize()
	_, err = pool.Exec(ctx, `INSERT INTO `+s+`.users (id, email, username, email_verified) VALUES ($1, $2, $3, true)`,
		id, strings.ToLower(username)+"@example.com", username)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `INSERT INTO `+s+`.user_passwords (user_id, password_hash) VALUES ($1, $2)`, id, hash)
	require.NoError(t, err)
	return id, username
}

// applyRetired builds a retired chain exactly as those releases recorded it.
func applyRetired(t *testing.T, pg *testdb.Postgres, schema string, names ...string) {
	t.Helper()
	var chain []migratekit.Migration
	for _, name := range names {
		chain = append(chain, retired.File(name))
	}
	require.NoError(t, migratekit.NewPostgres(sqlDB(t, pg.URL), "authkit").WithSchema(schema).ApplyMigrations(t.Context(), chain))
}

var restrictLine = regexp.MustCompile(`(?m)^\\(un)?restrict .*$`)
var dumpSchemaName = regexp.MustCompile(`(?m)^CREATE SCHEMA ([A-Za-z0-9_]+);$`)

func dumpSchema(t *testing.T, dump string) string {
	t.Helper()
	m := dumpSchemaName.FindAllStringSubmatch(dump, -1)
	require.Len(t, m, 1, "a legacy dump holds exactly one AuthKit schema")
	return m[0][1]
}

// restoreDump restores a schema-only pg_dump and records the ledger row the
// retired release wrote, since pg_dump -n does not carry public.migrations.
func restoreDump(t *testing.T, pg *testdb.Postgres, dump, schema string) {
	t.Helper()
	ctx := t.Context()
	db := sqlDB(t, pg.URL)
	_, err := db.ExecContext(ctx, `CREATE EXTENSION IF NOT EXISTS citext WITH SCHEMA public`)
	require.NoError(t, err)
	conn, err := pgx.Connect(ctx, pg.URL)
	require.NoError(t, err)
	defer conn.Close(context.Background())
	_, err = conn.Exec(ctx, restrictLine.ReplaceAllString(dump, ""))
	require.NoError(t, err)
	require.NoError(t, migratekit.NewPostgres(db, "authkit").ApplyMigrations(ctx, nil))
	baseline := retired.File("0001_schema.up.sql")
	_, err = db.ExecContext(ctx, `INSERT INTO public.migrations (app, database, schema, sequence, filename, content_sha256, semantic_sha256)
		VALUES ('authkit', 'postgres', $1, 1, $2, $3, $4)`, schema, baseline.Name,
		migratekit.ContentDigest(baseline.Content), migratekit.SemanticContentDigest(baseline.Content))
	require.NoError(t, err)
}

func schemaPool(t *testing.T, url, schema string) *pgxpool.Pool {
	t.Helper()
	cfg, err := pgxpool.ParseConfig(url)
	require.NoError(t, err)
	cfg.ConnConfig.RuntimeParams["search_path"] = pgx.Identifier{schema}.Sanitize() + ", public"
	pool, err := pgxpool.NewWithConfig(t.Context(), cfg)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	return pool
}

func sqlDB(t *testing.T, url string) *sql.DB {
	t.Helper()
	db, err := sql.Open("pgx", url)
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })
	return db
}
