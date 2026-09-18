package embedded

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/open-rails/authkit/internal/testdb"
	"github.com/stretchr/testify/require"
)

func TestCredentialChangesHaveOneConcurrentWinner(t *testing.T) {
	for _, kind := range []string{"reset", "current_password"} {
		t.Run(kind, func(t *testing.T) {
			svc, _ := newHardeningService(t)
			ctx := context.Background()
			u, email := newHardeningUser(t, ctx, svc, "parallel")
			require.NoError(t, svc.AdminSetPassword(ctx, u.ID, "Original-password-12345"))
			for _, token := range []string{"reset-a", "reset-b"} {
				require.NoError(t, svc.storePasswordReset(ctx, sha256Hex(token), u.ID, "email", email, time.Minute))
			}
			lock, err := svc.pg.Begin(ctx)
			require.NoError(t, err)
			defer lock.Rollback(ctx)
			_, err = svc.qtx(lock).UserCredentialVersionForUpdate(ctx, u.ID)
			require.NoError(t, err)
			// The fixture lock, blocker and two workers occupy four connections.
			// Observe through a separate pool so CI's four-connection pool cannot
			// starve the query that proves both workers reached the database lock.
			observer := testdb.UnlockedPool(t)
			result := make(chan error, 2)
			for i := range 2 {
				go func() {
					newPassword := fmt.Sprintf("Replacement-password-%d", i)
					if kind == "reset" {
						_, err := svc.ConfirmPasswordReset(ctx, []string{"reset-a", "reset-b"}[i], newPassword)
						result <- err
					} else {
						result <- svc.ChangePassword(ctx, u.ID, "Original-password-12345", newPassword, nil)
					}
				}()
			}
			require.Eventually(t, func() bool {
				var n int
				err := observer.QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE '%UserCredentialVersionForUpdate%'`).Scan(&n)
				return err == nil && n == 2
			}, 10*time.Second, 10*time.Millisecond)
			require.NoError(t, lock.Commit(ctx))
			successes := 0
			for range 2 {
				if <-result == nil {
					successes++
				}
			}
			require.Equal(t, 1, successes)
		})
	}
}
