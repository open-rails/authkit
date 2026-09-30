package engine

import (
	"context"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/config"
	"github.com/open-rails/authkit/internal/ident"
	"github.com/open-rails/authkit/internal/testdb"
)

// Deleting a row makes Postgres find every row that references it with
// `fk = $1`. Each foreign key has an index that lookup can use, so a purge
// never scans a referencing table.
func TestForeignKeysAreIndexed(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	ctx := t.Context()
	rows, err := pg.Pool.Query(ctx, `SELECT con.conname, format('SELECT 1 FROM %I WHERE %s', c.relname,
  (SELECT string_agg(format('%I = $%s', a.attname, k.i), ' AND ') FROM unnest(con.conkey) WITH ORDINALITY k(attnum, i)
   JOIN pg_attribute a ON a.attrelid = con.conrelid AND a.attnum = k.attnum))
FROM pg_constraint con JOIN pg_class c ON c.oid = con.conrelid
WHERE con.contype = 'f' AND con.connamespace = 'profiles'::regnamespace`)
	require.NoError(t, err)
	lookups, err := pgx.CollectRows(rows, pgx.RowToStructByPos[struct{ Name, SQL string }])
	require.NoError(t, err)
	require.NotEmpty(t, lookups)
	conn, err := pg.Pool.Acquire(ctx)
	require.NoError(t, err)
	defer conn.Release()
	_, err = conn.Exec(ctx, `SET enable_seqscan = off`)
	require.NoError(t, err)
	for _, l := range lookups {
		// The simple protocol, so $1 stays a placeholder of the generic plan.
		results, err := conn.Conn().PgConn().Exec(ctx, "EXPLAIN (GENERIC_PLAN) "+l.SQL).ReadAll()
		require.NoError(t, err)
		var plan strings.Builder
		for _, row := range results[0].Rows {
			plan.Write(row[0])
			plan.WriteByte('\n')
		}
		require.NotContains(t, plan.String(), "Seq Scan", "%s: %s", l.Name, plan.String())
	}
	_, err = conn.Exec(ctx, `RESET enable_seqscan`)
	require.NoError(t, err)
}

// An account purge and a group purge, with sequential scans off: auto_explain
// hands back the plan of every foreign-key lookup Postgres ran for them, and
// each one used an index.
func TestPurgeFindsReferencesByIndex(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	ctx := t.Context()
	var mu sync.Mutex
	var plans []string
	cfg := pg.Pool.Config()
	cfg.ConnConfig.OnNotice = func(_ *pgconn.PgConn, n *pgconn.Notice) {
		if strings.Contains(n.Message, "OPERATOR(pg_catalog.=)") { // how Postgres words a foreign-key lookup
			mu.Lock()
			plans = append(plans, n.Message)
			mu.Unlock()
		}
	}
	cfg.AfterConnect = func(ctx context.Context, c *pgx.Conn) error {
		_, err := c.Exec(ctx, `LOAD 'auto_explain'; SET auto_explain.log_min_duration = 0;
SET auto_explain.log_nested_statements = on; SET auto_explain.log_level = notice; SET enable_seqscan = off`)
		return err
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	engineCfg := maintenanceConfig()
	roles := config.NewRoles()
	roles.Persona("org", config.APIKeys)
	engineCfg.Roles = roles
	e := newTestEngine(t, engineCfg, config.Deps{Postgres: pool})
	_, err = e.ensureRootGroup(ctx)
	require.NoError(t, err)
	exec := func(sql string, args ...any) {
		t.Helper()
		_, err := pg.Pool.Exec(ctx, sql, args...)
		require.NoError(t, err)
	}
	table := regexp.MustCompile(`ONLY "profiles"\."(\w+)"`)
	purged := func(purge func()) []string {
		t.Helper()
		mu.Lock()
		plans = nil
		mu.Unlock()
		purge()
		mu.Lock()
		defer mu.Unlock()
		var tables []string
		for _, plan := range plans {
			require.NotContains(t, plan, "Seq Scan", plan)
			tables = append(tables, table.FindStringSubmatch(plan)[1])
		}
		return tables
	}

	user, err := e.createUser(ctx, uniqueEmail("purged"), "purged"+uniqueSuffix())
	require.NoError(t, err)
	other, err := e.createUser(ctx, uniqueEmail("other"), "other"+uniqueSuffix())
	require.NoError(t, err)
	_, _, err = e.issueRefreshSession(ctx, user.ID)
	require.NoError(t, err)
	exec(`UPDATE users SET banned_at = now(), banned_by = $1 WHERE id = $2`, user.ID, other.ID)
	exec(`INSERT INTO user_passkeys (user_id, rpid, credential_id, public_key) VALUES ($1, 'example.test', '\x01', '\x02')`, user.ID)
	exec(`INSERT INTO user_device_keys (user_id, public_key) VALUES ($1, decode(repeat('cd', 32), 'hex'))`, user.ID)
	generation := prepareExpiredDeletion(t, e, user.ID)
	tables := purged(func() { require.NoError(t, e.finalizeAccountDeletion(ctx, generation, true)) })
	require.Subset(t, tables, []string{"users", "refresh_sessions", "refresh_token_history", "user_passkeys", "user_device_keys",
		"group_invite_links", "account_registration_invites"})

	group, err := seedGroup(ctx, e, ident.Persona("org"), "")
	require.NoError(t, err)
	exec(`INSERT INTO group_invite_links (permission_group_id, role, code_hash) VALUES ($1, 'org:owner', $2)`, group, uniqueSuffix())
	exec(`INSERT INTO account_registration_invites (email, code_hash, expires_at, permission_group_id, role)
 VALUES ('invited@example.test', $2, now() + interval '1 day', $1, 'org:owner')`, group, uniqueSuffix())
	tables = purged(func() { require.NoError(t, e.PurgeGroup(ctx, iam.GroupByID(group))) })
	require.Subset(t, tables, []string{"group_user_roles", "api_keys", "remote_applications", "group_invite_links", "account_registration_invites"})
}
