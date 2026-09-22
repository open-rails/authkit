package embedded

import (
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/stretchr/testify/require"
)

func TestAccountFleetRebindRequiresQuiescenceAndFencesOldProducer(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	require.NoError(t, ApplyMigrations(t.Context(), pg.Pool, "", MigrationOptions{RiverSchema: "replacement_jobs"}))
	cfg := maintenanceConfig()
	old, err := New(cfg, Deps{Postgres: pg.Pool})
	require.NoError(t, err)
	t.Cleanup(old.Close)
	user, err := old.Client().CreateUser(t.Context(), "rebind@example.test", "rebind")
	require.NoError(t, err)
	require.NoError(t, old.engine.SoftDeleteUser(t.Context(), user.ID))
	cfg.River.Schema = "replacement_jobs"
	_, err = New(cfg, Deps{Postgres: pg.Pool})
	require.ErrorContains(t, err, "active account lifecycle work")
	results, err := old.Client().OperatorRestoreUsers(t.Context(), []string{user.ID})
	require.NoError(t, err)
	require.NoError(t, results[0].Err)
	_, err = New(cfg, Deps{Postgres: pg.Pool})
	require.ErrorContains(t, err, "active account lifecycle work", "pending restore callbacks must also block a move")
	rows, err := pg.Pool.Query(t.Context(), "SELECT id FROM profiles.account_deletion_deliveries WHERE user_id=$1::uuid ORDER BY id", user.ID)
	require.NoError(t, err)
	ids, err := pgx.CollectRows(rows, pgx.RowTo[int64])
	require.NoError(t, err)
	for _, id := range ids {
		require.NoError(t, old.engine.deliverAccountEvent(t.Context(), id))
	}
	replacement, err := New(cfg, Deps{Postgres: pg.Pool})
	require.NoError(t, err, "quiescent history does not permanently pin a schema")
	t.Cleanup(replacement.Close)
	err = old.engine.SoftDeleteUser(t.Context(), user.ID)
	require.ErrorContains(t, err, "fleet was rebound")
	var deleted *time.Time
	require.NoError(t, pg.Pool.QueryRow(t.Context(), "SELECT deleted_at FROM profiles.users WHERE id=$1::uuid", user.ID).Scan(&deleted))
	require.Nil(t, deleted, "stale producer rejection rolls back the account mutation")
	require.NoError(t, replacement.engine.SoftDeleteUser(t.Context(), user.ID))
	var jobs int
	require.NoError(t, pg.Pool.QueryRow(t.Context(), "SELECT count(*) FROM replacement_jobs.river_job WHERE kind='authkit_account_delivery'").Scan(&jobs))
	require.Equal(t, 1, jobs)
}
