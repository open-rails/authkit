package embedded

import (
	"testing"

	"github.com/jackc/pgx/v5"
	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/stretchr/testify/require"
)

// Advancing time is confined to disposable test state. There is no public
// immediate-delete operation or configurable shortened recovery period.
func prepareExpiredDeletion(t *testing.T, s *engine, userID string) string {
	t.Helper()
	require.NoError(t, s.SoftDeleteUser(t.Context(), userID))
	_, err := s.pg.Exec(t.Context(), "UPDATE users SET deleted_at=statement_timestamp()-interval '31 days' WHERE id=$1::uuid", userID)
	require.NoError(t, err)
	var generation string
	require.NoError(t, s.pg.QueryRow(t.Context(), `UPDATE account_deletions d SET deleted_at=u.deleted_at,purge_at=u.deleted_at+interval '720 hours'
 FROM users u WHERE d.user_id=$1::uuid AND d.state='deleted' AND u.id=d.user_id RETURNING d.id::text`, userID).Scan(&generation))
	deliver := func() {
		rows, err := s.pg.Query(t.Context(), "SELECT id FROM account_deletion_deliveries WHERE deletion_id=$1::uuid AND completed_at IS NULL ORDER BY id", generation)
		require.NoError(t, err)
		ids, err := pgx.CollectRows(rows, pgx.RowTo[int64])
		require.NoError(t, err)
		for _, id := range ids {
			require.NoError(t, s.deliverAccountEvent(t.Context(), id))
		}
	}
	deliver()
	require.NoError(t, s.finalizeAccountDeletion(t.Context(), generation, false))
	deliver()
	return generation
}

func TestAccountFinalizationPreservesForeignKeysAndCascadesMemberships(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	cfg := maintenanceConfig()
	cfg.RBAC = []PersonaDef{IntrinsicRootPersona(RoleDef{Name: "member"})}
	runtime, err := New(cfg, Deps{Postgres: pg.Pool})
	require.NoError(t, err)
	t.Cleanup(runtime.Close)
	client := runtime.Client()
	user, err := client.CreateUser(t.Context(), "finalize-fk@example.test", "finalizefk")
	require.NoError(t, err)
	require.NoError(t, client.OperatorAssignGroupRole(t.Context(), authkit.RootGroup(), authkit.UserSubject(user.ID), "member"))
	_, err = pg.Pool.Exec(t.Context(), "CREATE TABLE public.host_reference(user_id uuid REFERENCES profiles.users(id))")
	require.NoError(t, err)
	_, err = pg.Pool.Exec(t.Context(), "INSERT INTO public.host_reference VALUES ($1::uuid)", user.ID)
	require.NoError(t, err)
	generation := prepareExpiredDeletion(t, runtime.engine, user.ID)
	require.ErrorIs(t, runtime.engine.finalizeAccountDeletion(t.Context(), generation, true), ErrUserReferenced)
	var count int
	require.NoError(t, pg.Pool.QueryRow(t.Context(), "SELECT count(*) FROM profiles.group_user_roles WHERE user_id=$1::uuid", user.ID).Scan(&count))
	require.Equal(t, 1, count, "failed purge rolls back every cascade")
	_, err = pg.Pool.Exec(t.Context(), "DELETE FROM public.host_reference WHERE user_id=$1::uuid", user.ID)
	require.NoError(t, err)
	require.NoError(t, runtime.engine.finalizeAccountDeletion(t.Context(), generation, true))
	require.NoError(t, pg.Pool.QueryRow(t.Context(), "SELECT count(*) FROM profiles.group_user_roles WHERE user_id=$1::uuid", user.ID).Scan(&count))
	require.Zero(t, count)
	require.NoError(t, pg.Pool.QueryRow(t.Context(), "SELECT count(*) FROM profiles.users WHERE id=$1::uuid", user.ID).Scan(&count))
	require.Zero(t, count)
}
