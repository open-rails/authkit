package embedded

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/stretchr/testify/require"
)

func TestAccountLifecycleTerminalGCIsBoundedAndPreservesPendingWork(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	runtime, err := New(maintenanceConfig(), Deps{Postgres: pg.Pool})
	require.NoError(t, err)
	t.Cleanup(runtime.Close)
	ids := make([]string, 5)
	var completedReceipt int64
	for i := range ids {
		ids[i] = uuid.NewString()
		state := "restored"
		if i == 1 {
			state = "purged"
		}
		if i == 3 {
			state = "deleted"
		}
		terminal := time.Now().Add(-100 * 24 * time.Hour)
		if i == 4 {
			terminal = time.Now()
		}
		_, err := pg.Pool.Exec(t.Context(), `INSERT INTO profiles.account_deletions(id,user_id,deleted_at,purge_at,state,restored_at,purged_at)
 VALUES ($1::uuid,$2::uuid,$3,$3::timestamptz+interval '720 hours',$4,
 CASE WHEN $4='restored' THEN $3::timestamptz ELSE NULL END,CASE WHEN $4='purged' THEN $3::timestamptz ELSE NULL END)`, ids[i], uuid.NewString(), terminal, state)
		require.NoError(t, err)
		if i == 0 || i == 2 {
			var receipt int64
			require.NoError(t, pg.Pool.QueryRow(t.Context(), `INSERT INTO profiles.account_deletion_deliveries(deletion_id,user_id,issuer,stage,completed_at)
 SELECT id,user_id,$2,'soft',CASE WHEN $3 THEN statement_timestamp() ELSE NULL END FROM profiles.account_deletions WHERE id=$1::uuid RETURNING id`, ids[i], runtime.engine.cfg.Token.Issuer, i == 0).Scan(&receipt))
			if i == 0 {
				completedReceipt = receipt
			}
		}
	}
	for range 2 {
		removed, err := runtime.engine.gcTerminalAccountDeletions(t.Context(), time.Now().Add(-terminalRetention), 1)
		require.NoError(t, err)
		require.EqualValues(t, 1, removed)
	}
	removed, err := runtime.engine.gcTerminalAccountDeletions(t.Context(), time.Now().Add(-terminalRetention), 1)
	require.NoError(t, err)
	require.Zero(t, removed)
	var remaining int
	require.NoError(t, pg.Pool.QueryRow(t.Context(), "SELECT count(*) FROM profiles.account_deletions").Scan(&remaining))
	require.Equal(t, 3, remaining, "pending callbacks, active cycles and recent history are retained")
	require.NoError(t, runtime.engine.deliverAccountEvent(t.Context(), completedReceipt), "old retries no-op after completed receipts expire")
	require.NoError(t, runtime.engine.finalizeAccountDeletion(t.Context(), ids[1], true))
}
