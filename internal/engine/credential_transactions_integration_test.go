package engine

import (
	"context"
	"testing"
	"time"

	"github.com/open-rails/authkit/internal/testoutbox"

	"github.com/stretchr/testify/require"
)

func TestCredentialTransactionsResetGrantsExpireOnCredentialChanges(t *testing.T) {
	for _, change := range []string{"password_change", "contact_change", "other_reset"} {
		t.Run(change, func(t *testing.T) {
			ctx := context.Background()
			srv, sender, _ := passwordlessTestServer(t, true)
			pool := fixtureBackend(srv.Backend()).pg
			email := uniqueEmail("audit-old-reset")
			u, err := fixtureBackend(srv.Backend()).createUser(ctx, email, "auditreset"+uniqueSuffix())
			require.NoError(t, err)
			t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM users WHERE id=$1`, u.ID) })
			require.NoError(t, srv.Backend().RequestPasswordReset(ctx, email, time.Hour, nil, nil))
			stale := sender.Last(t, testoutbox.PasswordReset, "").Token
			switch change {
			case "password_change":
				require.NoError(t, srv.Backend().ChangePassword(ctx, u.ID, "", "Defender-password-12345", nil))
			case "contact_change":
				newEmail := uniqueEmail("audit-new-email")
				require.NoError(t, srv.Backend().RequestEmailChange(ctx, u.ID, newEmail))
				require.NoError(t, fixtureBackend(srv.Backend()).confirmEmailChange(ctx, u.ID, newEmail, sentCode(t, sender, testoutbox.Verification), nil))
			case "other_reset":
				require.NoError(t, srv.Backend().RequestPasswordReset(ctx, email, time.Hour, nil, nil))
				current := sender.Last(t, testoutbox.PasswordReset, "").Token
				require.NotEqual(t, stale, current)
				_, err = srv.Backend().ConfirmPasswordReset(ctx, current, "Defender-password-12345")
				require.NoError(t, err)
			}
			uid, resetErr := srv.Backend().ConfirmPasswordReset(ctx, stale, "Attacker-password-12345")
			if resetErr == nil {
				t.Logf("stale grant changed password after %s for user %s; new password check=%v", change, uid, srv.Backend().CheckUserPassword(ctx, u.ID, "Attacker-password-12345"))
			}
			require.Error(t, resetErr, "credential change must invalidate previously issued recovery grants")
		})
	}
}

func TestCredentialTransactionsPasswordMutationRollsBackOnFailure(t *testing.T) {
	for _, stage := range []struct{ name, table, columns string }{
		{"password", "user_passwords", "password_hash"},
		{"version", "users", "credential_version"},
		{"revocation", "refresh_sessions", "revoked_at"},
	} {
		for _, method := range []string{"change", "fresh", "admin", "reset"} {
			t.Run(stage.name+"/"+method, func(t *testing.T) {
				ctx := context.Background()
				srv, sender, _ := passwordlessTestServer(t, true)
				pool := fixtureBackend(srv.Backend()).pg
				uid := mustPasswordUser(t, srv, "atomic-password")
				user, err := fixtureBackend(srv.Backend()).getUserByID(ctx, uid)
				require.NoError(t, err)
				require.NoError(t, srv.Backend().RequestPasswordReset(ctx, *user.Email, time.Hour, nil, nil))
				reset := sender.Last(t, testoutbox.PasswordReset, "").Token
				_, refresh, _, err := fixtureBackend(srv.Backend()).issueRefreshSession(ctx, uid, "atomic", nil)
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
					changeErr = srv.Backend().ChangePassword(ctx, uid, "Correct-password-12345", "Replacement-password-12345", nil)
				case "fresh":
					changeErr = srv.Backend().SetPasswordAfterFreshAuth(ctx, uid, "Replacement-password-12345", nil)
				case "admin":
					changeErr = fixtureBackend(srv.Backend()).adminSetPassword(ctx, uid, "Replacement-password-12345")
				case "reset":
					_, changeErr = srv.Backend().ConfirmPasswordReset(ctx, reset, "Replacement-password-12345")
				}
				require.ErrorContains(t, changeErr, "injected credential failure")
				require.NoError(t, pool.QueryRow(ctx, `SELECT credential_version FROM users WHERE id=$1`, uid).Scan(&after))
				require.Equal(t, before, after, "failed operation cannot invalidate grants")
				require.NoError(t, srv.Backend().CheckUserPassword(ctx, uid, "Correct-password-12345"))
				require.Error(t, srv.Backend().CheckUserPassword(ctx, uid, "Replacement-password-12345"))
				_, _, _, err = srv.Backend().ExchangeRefreshToken(ctx, refresh, "atomic", nil)
				require.NoError(t, err, "the rollback retains the old session")
			})
		}
	}
}
