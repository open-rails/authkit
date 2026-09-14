package authhttp

import (
	"context"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestCredentialTransactionsResetGrantsExpireOnCredentialChanges(t *testing.T) {
	for _, change := range []string{"password_change", "contact_change", "other_reset"} {
		t.Run(change, func(t *testing.T) {
			ctx := context.Background()
			srv, sender, _ := passwordlessTestServer(t, true)
			pool := srv.svc.Postgres()
			email := uniqueEmail("audit-old-reset")
			u, err := srv.svc.CreateUser(ctx, email, "auditreset"+uniqueSuffix())
			require.NoError(t, err)
			t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE id=$1`, u.ID) })
			require.NoError(t, srv.svc.RequestPasswordReset(ctx, email, time.Hour, nil, nil))
			stale := sender.passwordResetToken(t)
			switch change {
			case "password_change":
				require.NoError(t, srv.svc.ChangePassword(ctx, u.ID, "", "Defender-password-12345", nil))
			case "contact_change":
				newEmail := uniqueEmail("audit-new-email")
				require.NoError(t, srv.svc.RequestEmailChange(ctx, u.ID, newEmail))
				require.NoError(t, srv.svc.ConfirmEmailChange(ctx, u.ID, newEmail, sender.verificationCode(t), nil))
			case "other_reset":
				require.NoError(t, srv.svc.RequestPasswordReset(ctx, email, time.Hour, nil, nil))
				current := sender.passwordResetToken(t)
				require.NotEqual(t, stale, current)
				_, err = srv.svc.ConfirmPasswordReset(ctx, current, "Defender-password-12345")
				require.NoError(t, err)
			}
			uid, resetErr := srv.svc.ConfirmPasswordReset(ctx, stale, "Attacker-password-12345")
			if resetErr == nil {
				t.Logf("stale grant changed password after %s for user %s; new password check=%v", change, uid, srv.svc.CheckUserPassword(ctx, u.ID, "Attacker-password-12345"))
			}
			require.Error(t, resetErr, "credential change must invalidate previously issued recovery grants")
		})
	}
}

func TestCredentialTransactionsPasswordMutationRollsBackWhenRevocationFails(t *testing.T) {
	for _, method := range []string{"change", "fresh", "admin"} {
		t.Run(method, func(t *testing.T) {
			ctx := context.Background()
			srv, _, _ := passwordlessTestServer(t, true)
			pool := srv.svc.Postgres()
			uid := mustPasswordUser(t, srv, "audit-atomic-password")
			_, refresh, _, err := srv.svc.IssueRefreshSession(ctx, uid, "audit", nil)
			require.NoError(t, err)
			_, err = pool.Exec(ctx, `CREATE FUNCTION profiles.audit_block_revoke() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'audit injected revocation failure'; END $$; CREATE TRIGGER audit_block_revoke BEFORE UPDATE OF revoked_at ON profiles.refresh_sessions FOR EACH ROW EXECUTE FUNCTION profiles.audit_block_revoke()`)
			require.NoError(t, err)
			t.Cleanup(func() {
				_, _ = pool.Exec(ctx, `DROP TRIGGER IF EXISTS audit_block_revoke ON profiles.refresh_sessions; DROP FUNCTION IF EXISTS profiles.audit_block_revoke()`)
			})
			var changeErr error
			switch method {
			case "change":
				changeErr = srv.svc.ChangePassword(ctx, uid, "Correct-password-12345", "Replacement-password-12345", nil)
			case "fresh":
				changeErr = srv.svc.SetPasswordAfterFreshAuth(ctx, uid, "Replacement-password-12345", nil)
			case "admin":
				changeErr = srv.svc.AdminSetPassword(ctx, uid, "Replacement-password-12345")
			}
			require.ErrorContains(t, changeErr, "audit injected revocation failure")
			_, _, _, refreshErr := srv.svc.ExchangeRefreshToken(ctx, refresh, "audit", nil)
			checkNew := srv.svc.CheckUserPassword(ctx, uid, "Replacement-password-12345")
			t.Logf("method=%s new password check=%v old refresh check=%v", method, checkNew, refreshErr)
			require.NoError(t, refreshErr, "old session remains usable after failed revocation")
			require.Error(t, checkNew, "password change must roll back with failed revocation")
		})
	}
}
