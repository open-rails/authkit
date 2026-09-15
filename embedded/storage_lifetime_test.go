package embedded

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/stretchr/testify/require"
)

func TestStorageLifetimeWorkflow(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	ctx := context.Background()
	var cryptoInstalled bool
	require.NoError(t, pg.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_extension WHERE extname='pgcrypto')`).Scan(&cryptoInstalled))
	require.False(t, cryptoInstalled, "AuthKit does not install an unused extension")
	client := mustNewWithKeys(t, Config{Token: TokenConfig{Issuer: "https://storage.test"}, TwoFactor: TwoFactorConfig{Mode: TwoFactorDisabled}}, Keyset{}, WithPostgres(pg.Pool))
	group, err := client.EnsureRootGroup(ctx)
	require.NoError(t, err)
	user, err := client.CreateUser(ctx, "storage@example.test", "storage_user")
	require.NoError(t, err)
	st := client.groupStore()
	for i := 0; i < 8; i++ {
		require.NoError(t, st.AssignRole(ctx, group, authkit.UserSubject(user.ID), OwnerRoleName))
		require.NoError(t, st.UnassignRole(ctx, group, authkit.UserSubject(user.ID), OwnerRoleName))
	}
	var roles int
	require.NoError(t, pg.Pool.QueryRow(ctx, `SELECT count(*) FROM profiles.group_user_roles WHERE user_id=$1`, user.ID).Scan(&roles))
	require.Zero(t, roles, "grant/revoke cycles retain no historical rows")
	require.NoError(t, st.AssignRole(ctx, group, authkit.UserSubject(user.ID), OwnerRoleName))
	require.NoError(t, st.AssignRole(ctx, group, authkit.UserSubject(user.ID), OwnerRoleName))
	require.NoError(t, pg.Pool.QueryRow(ctx, `SELECT count(*) FROM profiles.group_user_roles WHERE user_id=$1`, user.ID).Scan(&roles))
	require.Equal(t, 1, roles)

	for _, target := range []struct{ table, columns, values, terminal, index string }{
		{"group_invite_links", "permission_group_id,role,invited_by,code_hash,expires_at", "$1,'owner',$2,'group-'||n,deadline", "LEAST(redeemed_at,revoked_at,expires_at)", "group_invite_links_terminal_idx"},
		{"account_registration_invites", "permission_group_id,role,invited_by,email,code_hash,expires_at", "$1,'owner',$2,'invite@example.test','account-'||n,deadline", "LEAST(consumed_at,revoked_at,expires_at)", "account_registration_invites_terminal_idx"},
		{"api_keys", "permission_group_id,role,created_by,name,key_id,secret_hash,expires_at", "$1,'owner',$2,'fixture','key-'||n,decode('aa','hex'),deadline", "LEAST(revoked_at,expires_at)", "api_keys_terminal_idx"},
	} {
		t.Run(target.table, func(t *testing.T) {
			// One more old row than a batch, one terminal row still inside the
			// retention period, and many live rows to exercise real index choice.
			_, err := pg.Pool.Exec(ctx, fmt.Sprintf(`INSERT INTO profiles.%s(%s)
 SELECT %s FROM (SELECT n,CASE WHEN n<=5001 THEN now()-interval '91 days'
 WHEN n=5002 THEN now()-interval '1 day' ELSE now()+interval '1 day' END deadline
 FROM generate_series(1,25002) n) seed`, target.table, target.columns, target.values), group, user.ID)
			require.NoError(t, err)
			_, err = pg.Pool.Exec(ctx, "ANALYZE profiles."+target.table)
			require.NoError(t, err)
			tx, err := pg.Pool.Begin(ctx)
			require.NoError(t, err)
			defer tx.Rollback(ctx)
			var held string
			require.NoError(t, tx.QueryRow(ctx, fmt.Sprintf(`SELECT id::text FROM profiles.%s ORDER BY %s,id LIMIT 1 FOR UPDATE`, target.table, target.terminal)).Scan(&held))
			require.NoError(t, client.CleanupExpiredAuthState(ctx))
			var remaining int
			require.NoError(t, pg.Pool.QueryRow(ctx, "SELECT count(*) FROM profiles."+target.table).Scan(&remaining))
			require.Equal(t, 20002, remaining, "one batch, locked row retained")
			require.NoError(t, client.CleanupExpiredAuthState(ctx))
			require.NoError(t, pg.Pool.QueryRow(ctx, "SELECT count(*) FROM profiles."+target.table).Scan(&remaining))
			require.Equal(t, 20002, remaining, "a locked candidate never stalls cleanup")
			require.NoError(t, tx.Commit(ctx))
			_, err = pg.Pool.Exec(ctx, "ANALYZE profiles."+target.table)
			require.NoError(t, err)
			rows, err := pg.Pool.Query(ctx, fmt.Sprintf(`EXPLAIN SELECT id FROM profiles.%s WHERE %s < now()-interval '90 days' ORDER BY %s,id LIMIT 5000 FOR UPDATE SKIP LOCKED`, target.table, target.terminal, target.terminal))
			require.NoError(t, err)
			plan, err := pgx.CollectRows(rows, pgx.RowTo[string])
			require.NoError(t, err)
			require.Contains(t, strings.Join(plan, "\n"), target.index)
			t.Log(strings.Join(plan, "\n"))
			require.NoError(t, client.CleanupExpiredAuthState(ctx))
			require.NoError(t, pg.Pool.QueryRow(ctx, "SELECT count(*) FROM profiles."+target.table).Scan(&remaining))
			require.Equal(t, 20001, remaining, "resumes while preserving live and recently terminal rows")
		})
	}
}
