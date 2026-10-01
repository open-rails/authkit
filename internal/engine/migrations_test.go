package engine

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/open-rails/authkit/internal/config"
	pgmigrations "github.com/open-rails/authkit/internal/migrations/postgres"
	"github.com/open-rails/authkit/internal/migrations/retired"
	"github.com/open-rails/authkit/internal/password"
	"github.com/open-rails/authkit/internal/secret"
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

// A database the whole v0.125–v0.148 chain built (v0.147.0 on) converts in
// place and migrates on: the ledger records the tree, the schema equals a fresh
// one, every row stays, and sessions and passwords written before the upgrade
// keep working.
func TestRetiredChainConvertsInPlace(t *testing.T) {
	ctx := t.Context()
	pg := testdb.EmptyScratchPostgres(t)
	db := sqlDB(t, pg.URL)
	require.NoError(t, migratekit.NewPostgres(db, "authkit").WithSchema("profiles").ApplyMigrations(ctx, retired.Chain()))

	// Rows as v0.148 wrote them.
	const issuer = "https://example.com" // testConfig's
	owner, member, username := uuid.NewString(), uuid.NewString(), "Retired"+uniqueSuffix()
	hash, err := password.HashArgon2id(ctx, testPassword)
	require.NoError(t, err)
	token := secret.Token(32)
	tokenHash := sha256.Sum256([]byte(token))
	var group string
	require.NoError(t, pg.Pool.QueryRow(ctx, `INSERT INTO permission_groups(persona) VALUES ('channel') RETURNING id::text`).Scan(&group))
	for _, seed := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO users(id, email, username, email_verified) VALUES ($1, $2, $3, true), ($4, $5, $6, true)`,
			[]any{owner, uniqueEmail("retired"), username, member, uniqueEmail("retired"), "Member" + uniqueSuffix()}},
		{`INSERT INTO user_passwords(user_id, password_hash) VALUES ($1, $2)`, []any{owner, hash}},
		{`INSERT INTO refresh_sessions(user_id, issuer, current_token_hash, auth_methods) VALUES ($1, $2, $3, '{pwd}')`, []any{owner, issuer, tokenHash[:]}},
		{`INSERT INTO group_user_roles(permission_group_id, user_id, role) VALUES ($1::uuid, $2::uuid, 'channel:owner'), ($1::uuid, $3::uuid, 'channel:member')`, []any{group, owner, member}},
		{`INSERT INTO api_keys(permission_group_id, key_id, secret_hash, name, created_by, role, catalog_issuer) VALUES ($1::uuid, 'ak_retired', '\x01', 'ci', $2::uuid, 'channel:member', $3)`, []any{group, owner, issuer}},
		{`INSERT INTO group_invite_links(permission_group_id, role, invited_by, code_hash) VALUES ($1::uuid, 'channel:member', $2::uuid, 'retired-code')`, []any{group, owner}},
		{`INSERT INTO mfa_factors(user_id, method, totp_secret, is_default) VALUES ($1::uuid, 'totp', '\x02', true)`, []any{member}},
		{`INSERT INTO mfa_settings(user_id, enabled) VALUES ($1::uuid, true)`, []any{member}},
		{`INSERT INTO user_device_keys(user_id, public_key) VALUES ($1::uuid, decode(repeat('ab', 32), 'hex'))`, []any{member}},
	} {
		_, err := pg.Pool.Exec(ctx, seed.sql, seed.args...)
		require.NoError(t, err)
	}
	for _, table := range []string{"users", "user_passwords", "name_claims", "refresh_sessions", "permission_groups", "group_user_roles", "api_keys", "group_invite_links", "mfa_factors", "mfa_settings", "user_device_keys"} {
		var n int
		require.NoError(t, db.QueryRowContext(ctx, `SELECT count(*) FROM profiles.`+table).Scan(&n))
		require.Positive(t, n, table)
	}
	requireRowsKept := keepRows(t, db, "profiles")

	cfg := config.Config{Schema: "profiles", River: config.RiverConfig{HostOwned: true}}
	require.NoError(t, Migrate(ctx, pg.Pool, cfg, config.MigrateOptions{}))
	require.NoError(t, Migrate(ctx, pg.Pool, cfg, config.MigrateOptions{}), "a second boot converts nothing")
	requireRowsKept()

	requireTree(t, pg, db, "profiles", true)

	f := newAccountFlow(t, pg.Pool, testConfig(), config.Deps{})
	f.session(f.expect(200, f.post("/token", map[string]any{"grant_type": "refresh_token", "refresh_token": token})).tokens(), "pwd")
	f.session(f.expect(200, f.post("/password/login", map[string]any{"identifier": username, "password": testPassword})).tokens(), "pwd")
}

// A schema a release left part-way through the chain (v0.141–v0.146 stopped
// at 0004) runs the rest of it as v0.148.x would have, then converts, in one
// Migrate. Its accounts, sessions, roles and keys stay, in the form the rest of
// the chain gives them.
func TestRetiredChainPrefixConvertsInPlace(t *testing.T) {
	ctx := t.Context()
	pg := testdb.EmptyScratchPostgres(t)
	db := sqlDB(t, pg.URL)
	require.NoError(t, migratekit.NewPostgres(db, "authkit").WithSchema("profiles").ApplyMigrations(ctx, retired.Chain()[:4]))

	// Rows as v0.144 wrote them.
	const issuer = "https://example.com" // testConfig's
	owner, email, username := uuid.NewString(), uniqueEmail("prefix"), "Prefix"+uniqueSuffix()
	hash, err := password.HashArgon2id(ctx, testPassword)
	require.NoError(t, err)
	token, mfaToken := secret.Token(32), secret.Token(32)
	tokenHash, mfaTokenHash := sha256.Sum256([]byte(token)), sha256.Sum256([]byte(mfaToken))
	seed := func(query string, args ...any) {
		_, err := pg.Pool.Exec(ctx, query, args...)
		require.NoError(t, err)
	}
	seed(`INSERT INTO users(id, email, username, email_verified) VALUES ($1, $2, $3, true)`, owner, email, username)
	seed(`INSERT INTO user_passwords(user_id, password_hash) VALUES ($1, $2)`, owner, hash)
	var root, group string
	require.NoError(t, pg.Pool.QueryRow(ctx, `INSERT INTO permission_groups(persona) VALUES ('root') RETURNING id::text`).Scan(&root))
	seed(`INSERT INTO group_persona_parents(persona, parent_persona) VALUES ('channel', 'root')`)
	require.NoError(t, pg.Pool.QueryRow(ctx, `INSERT INTO permission_groups(persona, parent_id, instance_slug, display_name) VALUES ('channel', $1, 'existing', 'Existing') RETURNING id::text`, root).Scan(&group))
	seed(`INSERT INTO group_user_roles(permission_group_id, user_id, role) VALUES ($1, $2, 'owner')`, group, owner)
	seed(`INSERT INTO api_keys(permission_group_id, key_id, secret_hash, name, created_by, role) VALUES ($1, 'ak_kept', '\x01', 'ci', $2, 'member'), ($1, 'ak_orphan', '\x02', 'ci', NULL, 'member')`, group, owner)
	seed(`INSERT INTO account_delivery_fleets(issuer, river_schema) VALUES ($1, 'public')`, issuer)
	seed(`INSERT INTO refresh_sessions(user_id, issuer, current_token_hash, auth_methods) VALUES ($1, $2, $3, '{pwd}'), ($1, $2, $4, '{pwd,mfa}')`, owner, issuer, tokenHash[:], mfaTokenHash[:])

	cfg := config.Config{Schema: "profiles", River: config.RiverConfig{HostOwned: true}}
	require.NoError(t, Migrate(ctx, pg.Pool, cfg, config.MigrateOptions{}))
	require.NoError(t, Migrate(ctx, pg.Pool, cfg, config.MigrateOptions{}), "a second boot converts nothing")
	requireTree(t, pg, db, "profiles", true)

	// 0006 revoked the creator-less key, 0008 dated the MFA session's proof,
	// 0011 released the group's name, 0014 qualified roles, 0015 bound the kept
	// key to the store's one app.
	var kept, orphanRevoked, mfaDated, groupNames, accounts string
	require.NoError(t, pg.Pool.QueryRow(ctx, `SELECT
		(SELECT role || ' ' || (revoked_at IS NULL) || ' ' || catalog_issuer FROM api_keys WHERE key_id = 'ak_kept'),
		(SELECT (revoked_at IS NOT NULL)::text FROM api_keys WHERE key_id = 'ak_orphan'),
		(SELECT (mfa_authenticated_at = created_at)::text FROM refresh_sessions WHERE current_token_hash = $1),
		(SELECT count(*)::text FROM name_claims WHERE name = 'existing'),
		(SELECT string_agg(email || ' ' || username, ',') FROM users)`, mfaTokenHash[:]).Scan(&kept, &orphanRevoked, &mfaDated, &groupNames, &accounts))
	require.Equal(t, []string{"channel:member true " + issuer, "true", "true", "0", email + " " + username},
		[]string{kept, orphanRevoked, mfaDated, groupNames, accounts})
	var role string
	require.NoError(t, pg.Pool.QueryRow(ctx, `SELECT role FROM group_user_roles WHERE permission_group_id = $1 AND user_id = $2`, group, owner).Scan(&role))
	require.Equal(t, "channel:owner", role)

	f := newAccountFlow(t, pg.Pool, testConfig(), config.Deps{})
	f.session(f.expect(200, f.post("/token", map[string]any{"grant_type": "refresh_token", "refresh_token": token})).tokens(), "pwd")
	f.session(f.expect(200, f.post("/password/login", map[string]any{"identifier": username, "password": testPassword})).tokens(), "pwd")
}

// Every other point a release stopped at converts too: v0.125–v0.126 (0001),
// v0.127–v0.136 (0002) and v0.137–v0.140 (0003).
func TestRetiredChainReleasePointsConvert(t *testing.T) {
	for _, n := range []int{1, 2, 3} {
		t.Run(retired.Chain()[n-1].Name, func(t *testing.T) {
			pg := testdb.EmptyScratchPostgres(t)
			db := sqlDB(t, pg.URL)
			require.NoError(t, migratekit.NewPostgres(db, "authkit").WithSchema("profiles").ApplyMigrations(t.Context(), retired.Chain()[:n]))
			require.NoError(t, Migrate(t.Context(), pg.Pool, config.Config{Schema: "profiles", River: config.RiverConfig{HostOwned: true}}, config.MigrateOptions{}))
			requireTree(t, pg, db, "profiles", true)
		})
	}
}

// A ledger that does not start the chain (an older chain, or rows the chain
// never had) is refused before anything changes, naming the way through. A
// schema edited by hand is not what its ledger's chain built, so the
// conversion refuses it too, whole or part-way.
func TestRetiredChainRefusesWhatItCannotConvert(t *testing.T) {
	older := retired.Chain()[0]
	older.Content += "\nCREATE TABLE legacy_marker (id int);\n"
	foreign := migratekit.Migration{Name: "0005_host_table.up.sql", Content: "CREATE TABLE host_table (id int);"}
	const edit = `ALTER TABLE profiles.users ADD COLUMN nickname text`
	for name, tc := range map[string]struct {
		chain []migratekit.Migration
		edit  string
		want  string
	}{
		"older":           {chain: []migratekit.Migration{older}, want: "last 0001_schema.up.sql"},
		"foreign":         {chain: append(retired.Chain()[:4], foreign), want: "last 0005_host_table.up.sql"},
		"edited":          {chain: retired.Chain(), edit: edit, want: "nickname"},
		"edited part-way": {chain: retired.Chain()[:4], edit: edit, want: "nickname"},
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
				require.ErrorContains(t, err, "upgrades through AuthKit v0.146.x first")
			} else {
				require.ErrorIs(t, err, migratekit.ErrSchemaMismatch)
			}
			require.Equal(t, schema, testdb.SchemaCatalog(t, db, "profiles"), "the schema is untouched")
			require.Equal(t, recorded, ledger(t, db, "profiles"), "the ledger is untouched")
		})
	}
}

// requireTree asserts schema was migrated to the tree, converted to its
// baseline first if converted: its ledger holds the tree (the baseline and
// every later migration), a conversion was audited exactly when converted, and
// its catalog equals a schema Migrate built from nothing.
func requireTree(t *testing.T, pg *testdb.Postgres, db *sql.DB, schema string, converted bool) {
	t.Helper()
	ctx := t.Context()
	tree, err := migratekit.LoadFromFS(pgmigrations.FS)
	require.NoError(t, err)
	var want []string
	for _, m := range tree {
		want = append(want, m.Name+" "+migratekit.ContentDigest(m.Content))
	}
	fresh := schema + "_fresh"
	require.NoError(t, Migrate(ctx, pg.Pool, config.Config{Schema: fresh, River: config.RiverConfig{HostOwned: true}}, config.MigrateOptions{}))
	for s, converted := range map[string]bool{schema: converted, fresh: false} {
		require.Equal(t, want, ledger(t, db, s), s)
		var audits int
		require.NoError(t, db.QueryRowContext(ctx, `SELECT count(*) FROM public.migration_repairs WHERE app = 'authkit' AND schema = $1 AND verb = 'convert'`, s).Scan(&audits))
		require.Equal(t, converted, audits > 0, s)
	}
	require.Empty(t, testdb.CatalogDiff(testdb.SchemaCatalog(t, db, schema), testdb.SchemaCatalog(t, db, fresh)))
}

// A database v1.0.2 built, or one converted from the retired chain, migrates
// on with its rows. 0003 drops refresh-token history past 90 days and makes
// banned_at the one mark of a ban, keeping banned what the sign-in gate
// refused. 0004 turns `reserved` into a permanent ban, keeps backup codes only
// beside a factor, and drops passkey tombstones. 0006 drops the old metadata:
// public metadata starts empty.
func TestUpgradeKeepsAndNormalizesRows(t *testing.T) {
	tree, err := migratekit.LoadFromFS(pgmigrations.FS)
	require.NoError(t, err)
	for name, prior := range map[string][]migratekit.Migration{
		"v1.0.2":        tree[:2],
		"retired chain": retired.Chain(),
	} {
		t.Run(name, func(t *testing.T) {
			ctx := t.Context()
			pg := testdb.EmptyScratchPostgres(t)
			db := sqlDB(t, pg.URL)
			require.NoError(t, migratekit.NewPostgres(db, "authkit").WithSchema("profiles").ApplyMigrations(ctx, prior))
			seed := func(query string, args ...any) {
				t.Helper()
				_, err := pg.Pool.Exec(ctx, query, args...)
				require.NoError(t, err)
			}
			// Bans written by hand: a reason without banned_at, the same
			// expired, and an expired ban nobody has signed in past.
			seed(`INSERT INTO users (username, ban_reason) VALUES ('handbanned', 'spam')`)
			seed(`INSERT INTO users (username, ban_reason, banned_until) VALUES ('handexpired', 'spam', now() - interval '1 day')`)
			seed(`INSERT INTO users (username, banned_at, banned_until) VALUES ('lapsed', now() - interval '2 days', now() - interval '1 day')`)
			var session string
			require.NoError(t, pg.Pool.QueryRow(ctx, `INSERT INTO refresh_sessions (user_id, issuer, current_token_hash)
 SELECT id, 'https://example.com', '\x00' FROM users WHERE username = 'lapsed' RETURNING id::text`).Scan(&session))
			seed(`INSERT INTO refresh_token_history (token_hash, session_id, consumed_at) VALUES ('\x01', $1, now() - interval '91 days'), ('\x02', $1, now())`, session)
			// State the removed columns carried: the reserved flag (once with a
			// ban in force), codes a disable left, a factor without its settings
			// row, a passkey tombstone and the Solana import flag.
			seed(`INSERT INTO users (username, metadata) VALUES ('reservedowner', '{"reserved": true, "tier": "gold"}'), ('unreserved', '{"reserved": false}')`)
			seed(`INSERT INTO users (username, metadata, banned_at, banned_until, ban_reason)
 VALUES ('reservedbanned', '{"reserved": true}', now() - interval '1 hour', now() + interval '1 day', 'spam')`)
			seed(`INSERT INTO mfa_settings (user_id, enabled, backup_codes) SELECT id, false, '{stale}' FROM users WHERE username = 'lapsed'`)
			seed(`INSERT INTO mfa_factors (user_id, method, totp_secret) SELECT id, 'totp', '\x01' FROM users WHERE username IN ('handexpired', 'unreserved')`)
			seed(`INSERT INTO mfa_settings (user_id, enabled, backup_codes) SELECT id, true, '{kept}' FROM users WHERE username = 'unreserved'`)
			seed(`INSERT INTO user_passkeys (user_id, rpid, credential_id, public_key, deleted_at)
 SELECT id, 'example.test', decode(k.c, 'hex'), '\x00', k.d FROM users, (VALUES ('01', NULL::timestamptz), ('02', now())) k(c, d) WHERE username = 'unreserved'`)
			seed(`INSERT INTO user_providers (user_id, issuer, subject, profile, verified_at)
 SELECT id, 'solana', 'wallet', '{"verification_required": true, "migration_source": "legacy"}', NULL FROM users WHERE username = 'unreserved'`)

			cfg := config.Config{Schema: "profiles", River: config.RiverConfig{HostOwned: true}}
			require.NoError(t, Migrate(ctx, pg.Pool, cfg, config.MigrateOptions{}))
			require.NoError(t, Migrate(ctx, pg.Pool, cfg, config.MigrateOptions{}), "a second boot changes nothing")
			requireTree(t, pg, db, "profiles", name == "retired chain")

			rows, err := pg.Pool.Query(ctx, `SELECT username || ' ' || (banned_at IS NOT NULL) || ' ' || COALESCE(ban_reason, '-') || ' ' ||
 EXISTS(SELECT 1 FROM usable_users v WHERE v.id = u.id) FROM users u ORDER BY username`)
			require.NoError(t, err)
			users, err := pgx.CollectRows(rows, pgx.RowTo[string])
			require.NoError(t, err)
			require.Equal(t, []string{"handbanned true spam false", "handexpired false - true", "lapsed true - true",
				"reservedbanned true spam false", "reservedowner true reserved false", "unreserved false - true"}, users)
			var state string
			require.NoError(t, pg.Pool.QueryRow(ctx, `SELECT concat_ws(' | ',
 (SELECT string_agg(username || ' ' || public_metadata::text || ' ' || (banned_until IS NULL), ', ' ORDER BY username) FROM users WHERE username LIKE '%reserved%'),
 (SELECT string_agg(u.username || ' ' || COALESCE(array_to_string(s.backup_codes, ','), '-'), ', ' ORDER BY u.username) FROM mfa_settings s JOIN users u ON u.id = s.user_id),
 (SELECT string_agg(encode(credential_id, 'hex'), ',') FROM user_passkeys),
 (SELECT profile::text FROM user_providers),
 (SELECT count(*) FILTER (WHERE canonical) || '/' || count(*) FROM name_claims))`).Scan(&state))
			require.Equal(t, `reservedbanned {} true, reservedowner {} true, unreserved {} true`+
				` | handexpired -, unreserved kept | 01 | {"migration_source": "legacy"} | 6/6`, state)
			var history []byte
			require.NoError(t, pg.Pool.QueryRow(ctx, `SELECT string_agg(token_hash, '') FROM refresh_token_history`).Scan(&history))
			require.Equal(t, []byte{2}, history, "history past 90 days is gone")
			_, err = pg.Pool.Exec(ctx, `UPDATE users SET banned_at = NULL WHERE username = 'handbanned'`)
			var refusal *pgconn.PgError
			require.ErrorAs(t, err, &refusal)
			require.Equal(t, "users_ban_chk", refusal.ConstraintName, "a ban's other columns need banned_at")
		})
	}
}

// 0006 drops users.metadata and avatar_url with what they held, and public
// metadata starts empty: a host's private keys never become public. After the
// upgrade no HTTP answer carries them.
func TestUpgradeDropsAppMetadata(t *testing.T) {
	ctx := t.Context()
	tree, err := migratekit.LoadFromFS(pgmigrations.FS)
	require.NoError(t, err)
	pg := testdb.EmptyScratchPostgres(t)
	db := sqlDB(t, pg.URL)
	require.NoError(t, migratekit.NewPostgres(db, "authkit").WithSchema("profiles").ApplyMigrations(ctx, tree[:5]))
	hash, err := password.HashArgon2id(ctx, testPassword)
	require.NoError(t, err)
	username := "Legacy" + uniqueSuffix()
	var id string
	require.NoError(t, pg.Pool.QueryRow(ctx, `INSERT INTO users (email, username, email_verified, metadata, avatar_url)
 VALUES ($1, $2, true, '{"legacy_ban": {"reason": "private-ban-reason"}, "biography": "private-until-published"}', 'https://cdn.example/private-avatar.png')
 RETURNING id::text`, uniqueEmail("legacy"), username).Scan(&id))
	_, err = pg.Pool.Exec(ctx, `INSERT INTO user_passwords (user_id, password_hash) VALUES ($1::uuid, $2)`, id, hash)
	require.NoError(t, err)

	require.NoError(t, Migrate(ctx, pg.Pool, config.Config{Schema: "profiles", River: config.RiverConfig{HostOwned: true}}, config.MigrateOptions{}))
	rows, err := pg.Pool.Query(ctx, `SELECT column_name FROM information_schema.columns
 WHERE table_schema = 'profiles' AND table_name = 'users' AND column_name IN ('metadata', 'avatar_url', 'public_metadata')`)
	require.NoError(t, err)
	columns, err := pgx.CollectRows(rows, pgx.RowTo[string])
	require.NoError(t, err)
	require.Equal(t, []string{"public_metadata"}, columns)
	var public string
	require.NoError(t, pg.Pool.QueryRow(ctx, `SELECT public_metadata::text FROM users WHERE id = $1::uuid`, id).Scan(&public))
	require.Equal(t, "{}", public)

	f := newAccountFlow(t, pg.Pool, testConfig(), config.Deps{})
	token := f.expect(200, f.post("/password/login", map[string]any{"identifier": username, "password": testPassword})).tokens().AccessToken
	for _, res := range []flowResponse{f.expect(200, f.request("GET", "/me", token, nil)), f.expect(200, f.request("GET", "/users?ids="+id, "", nil))} {
		require.Contains(t, res.raw, `"public_metadata":{}`)
		for _, private := range []string{"legacy_ban", "private-ban-reason", "private-until-published", "private-avatar"} {
			require.NotContains(t, res.raw, private)
		}
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

// keepRows copies every table of schema aside and returns a check that each
// still holds exactly those rows, compared on the columns it kept.
func keepRows(t *testing.T, db *sql.DB, schema string) func() {
	t.Helper()
	ctx := t.Context()
	snap := schema + "_before"
	_, err := db.ExecContext(ctx, `CREATE SCHEMA `+pgx.Identifier{snap}.Sanitize())
	require.NoError(t, err)
	rows, err := db.QueryContext(ctx, `SELECT c.relname FROM pg_class c WHERE c.relnamespace = $1::regnamespace AND c.relkind = 'r'`, schema)
	require.NoError(t, err)
	var tables []string
	for rows.Next() {
		var table string
		require.NoError(t, rows.Scan(&table))
		tables = append(tables, table)
	}
	require.NoError(t, rows.Err())
	rows.Close()
	for _, table := range tables {
		_, err := db.ExecContext(ctx, `CREATE TABLE `+pgx.Identifier{snap, table}.Sanitize()+` AS TABLE `+pgx.Identifier{schema, table}.Sanitize())
		require.NoError(t, err)
	}
	return func() {
		t.Helper()
		for _, table := range tables {
			var cols string
			require.NoError(t, db.QueryRowContext(ctx, `SELECT string_agg(quote_ident(a.attname), ', ' ORDER BY a.attnum)
 FROM pg_attribute a JOIN pg_attribute b ON b.attname = a.attname AND b.attrelid = $2::regclass AND b.attnum > 0 AND NOT b.attisdropped
 WHERE a.attrelid = $1::regclass AND a.attnum > 0 AND NOT a.attisdropped`,
				pgx.Identifier{snap, table}.Sanitize(), pgx.Identifier{schema, table}.Sanitize()).Scan(&cols))
			before := `SELECT ` + cols + ` FROM ` + pgx.Identifier{snap, table}.Sanitize()
			after := `SELECT ` + cols + ` FROM ` + pgx.Identifier{schema, table}.Sanitize()
			var changed int
			require.NoError(t, db.QueryRowContext(ctx, `SELECT count(*) FROM ((`+before+` EXCEPT ALL `+after+`) UNION ALL (`+after+` EXCEPT ALL `+before+`)) d`).Scan(&changed))
			require.Zero(t, changed, "rows of %s changed", table)
		}
	}
}

func sqlDB(t *testing.T, url string) *sql.DB {
	t.Helper()
	db, err := sql.Open("pgx", url)
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })
	return db
}
