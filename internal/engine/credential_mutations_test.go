package engine

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/config"
	"github.com/open-rails/authkit/internal/secret"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/open-rails/authkit/internal/testoutbox"
	"github.com/stretchr/testify/require"
)

func TestCredentialTransactionsPasswordMutationRollsBackOnFailure(t *testing.T) {
	for _, stage := range []struct{ name, table, columns string }{
		{"password", "user_passwords", "password_hash"},
		{"version", "users", "credential_version"},
		{"revocation", "refresh_sessions", "revoked_at"},
	} {
		for _, method := range []string{"change", "fresh", "admin", "reset"} {
			t.Run(stage.name+"/"+method, func(t *testing.T) {
				ctx := context.Background()
				// The injected trigger is DDL: give it a database of its own.
				sender := &testoutbox.Outbox{}
				pool := testdb.ScratchPostgres(t).Pool
				e := newTestEngine(t, testConfig(), config.Deps{Postgres: pool, Email: sender.Email})
				user := newUser(t, e, "atomic")
				uid := user.ID
				require.NoError(t, e.RequestPasswordReset(ctx, *user.Email, time.Hour, nil, nil))
				reset := sender.Last(t, iam.MessagePasswordReset, "").Token
				_, refresh, err := e.issueRefreshSession(ctx, uid)
				require.NoError(t, err)
				var before, after int64
				require.NoError(t, pool.QueryRow(ctx, `SELECT credential_version FROM users WHERE id=$1`, uid).Scan(&before))
				_, err = pool.Exec(ctx, `CREATE FUNCTION credential_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected credential failure'; END $$; CREATE TRIGGER credential_failure BEFORE UPDATE OF `+stage.columns+` ON `+stage.table+` FOR EACH ROW EXECUTE FUNCTION credential_failure()`)
				require.NoError(t, err)
				t.Cleanup(func() {
					_, _ = pool.Exec(ctx, `DROP TRIGGER IF EXISTS credential_failure ON `+stage.table+`; DROP FUNCTION IF EXISTS credential_failure()`)
				})
				var changeErr error
				switch method {
				case "change":
					changeErr = e.ChangePassword(ctx, uid, testPassword, "Replacement-password-12345", nil)
				case "fresh":
					changeErr = e.SetPasswordAfterFreshAuth(ctx, uid, "Replacement-password-12345", nil)
				case "admin":
					changeErr = e.adminSetPassword(ctx, uid, "Replacement-password-12345")
				case "reset":
					_, changeErr = e.ConfirmPasswordReset(ctx, reset, "Replacement-password-12345")
				}
				require.ErrorContains(t, changeErr, "injected credential failure")
				require.NoError(t, pool.QueryRow(ctx, `SELECT credential_version FROM users WHERE id=$1`, uid).Scan(&after))
				require.Equal(t, before, after, "failed operation cannot invalidate grants")
				require.NoError(t, e.CheckUserPassword(ctx, uid, testPassword))
				require.Error(t, e.CheckUserPassword(ctx, uid, "Replacement-password-12345"))
				_, _, _, err = e.ExchangeRefreshToken(ctx, refresh, "test", nil)
				require.NoError(t, err, "the rollback retains the old session")
			})
		}
	}
}

func TestCredentialChangesHaveOneConcurrentWinner(t *testing.T) {
	for _, kind := range []string{"reset", "current_password"} {
		t.Run(kind, func(t *testing.T) {
			cfg := maintenanceConfig()
			cfg.TwoFactor.Mode = iam.TwoFactorOptional
			svc := newTestEngine(t, cfg, config.Deps{Postgres: testdb.Pool(t), Email: (&testoutbox.Outbox{}).Email})
			ctx := context.Background()
			u := newUser(t, svc, "parallel")
			for _, token := range []string{"reset-a", "reset-b"} {
				require.NoError(t, svc.storePasswordReset(ctx, secret.Hash(token), u.ID, "email", *u.Email, time.Minute))
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
						result <- svc.ChangePassword(ctx, u.ID, testPassword, newPassword, nil)
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
