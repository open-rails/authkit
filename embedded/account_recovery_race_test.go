package embedded

import (
	"sync"
	"testing"

	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/riverqueue/river"
	"github.com/stretchr/testify/require"
)

func TestAccountRecoveryAndFinalizerSerializeAtDeadline(t *testing.T) {
	for _, expired := range []bool{false, true} {
		name := "recoverable"
		if expired {
			name = "expired"
		}
		t.Run(name, func(t *testing.T) {
			pg := testdb.ScratchPostgres(t)
			runtime, err := New(maintenanceConfig(), Deps{Postgres: pg.Pool})
			require.NoError(t, err)
			t.Cleanup(runtime.Close)
			user, err := runtime.Client().CreateUser(t.Context(), name+"@example.test", name)
			require.NoError(t, err)
			require.NoError(t, runtime.engine.SoftDeleteUser(t.Context(), user.ID))
			var generation string
			require.NoError(t, pg.Pool.QueryRow(t.Context(), "SELECT id::text FROM profiles.account_deletions WHERE user_id=$1::uuid", user.ID).Scan(&generation))
			if expired {
				_, err = pg.Pool.Exec(t.Context(), "UPDATE profiles.users SET deleted_at=statement_timestamp()-interval '31 days' WHERE id=$1::uuid", user.ID)
				require.NoError(t, err)
				_, err = pg.Pool.Exec(t.Context(), `UPDATE profiles.account_deletions d SET deleted_at=u.deleted_at,purge_at=u.deleted_at+interval '720 hours'
 FROM profiles.users u WHERE d.id=$1::uuid AND d.user_id=u.id`, generation)
				require.NoError(t, err)
			}
			start := make(chan struct{})
			var restoreErr, finalizeErr error
			var wg sync.WaitGroup
			wg.Go(func() {
				<-start
				restoreErr = runtime.engine.restoreUser(t.Context(), "", user.ID)
			})
			wg.Go(func() {
				<-start
				finalizeErr = runtime.engine.finalizeAccountDeletion(t.Context(), generation, false)
			})
			close(start)
			wg.Wait()
			var state string
			require.NoError(t, pg.Pool.QueryRow(t.Context(), "SELECT state FROM profiles.account_deletions WHERE id=$1::uuid", generation).Scan(&state))
			if expired {
				require.ErrorIs(t, restoreErr, authkit.E(authkit.CodeAccountRecoveryExpired))
				require.NoError(t, finalizeErr)
				require.Equal(t, "finalizing", state)
			} else {
				require.NoError(t, restoreErr)
				if finalizeErr != nil {
					var snooze *river.JobSnoozeError
					require.ErrorAs(t, finalizeErr, &snooze)
				}
				require.Equal(t, "restored", state)
				var hard int
				require.NoError(t, pg.Pool.QueryRow(t.Context(), "SELECT count(*) FROM profiles.account_deletion_deliveries WHERE deletion_id=$1::uuid AND stage='hard'", generation).Scan(&hard))
				require.Zero(t, hard, "an early finalizer cannot dispatch irreversible host cleanup")
			}
		})
	}
}
