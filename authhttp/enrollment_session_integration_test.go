package authhttp

import (
	"testing"

	"github.com/open-rails/authkit/embedded"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/stretchr/testify/require"
)

const enrollPassword = "Correct-horse-battery-1"

// #389: a confirmed enrollment code verifies the enrolling session; other
// sessions still complete 2FA on refresh.
func TestEnrollmentVerifiesEnrollingSession(t *testing.T) {
	forEachStore(t, func(t *testing.T, store ephemeralStore) {
		pool := testdb.Pool(t)
		cfg := newServerTestConfig()
		cfg.Registration.PasswordlessLogin = true
		f := newAccountFlow(t, pool, store, cfg)
		ctx := t.Context()

		login := func(prefix string) (string, string, flowResponse, flowResponse) {
			t.Helper()
			email := uniqueEmail(prefix)
			user, err := f.service.svc.CreateUser(ctx, email, "enr"+uniqueSuffix())
			require.NoError(t, err)
			require.NoError(t, f.service.svc.AdminSetPassword(ctx, user.ID, enrollPassword))
			require.NoError(t, f.service.svc.MarkEmailVerified(ctx, user.ID))
			body := map[string]any{"identifier": email, "password": enrollPassword}
			return user.ID, email, f.expect(200, f.post("/password/login", body)), f.expect(200, f.post("/password/login", body))
		}
		refresh := func(rt string) flowResponse {
			return f.post("/token", map[string]any{"grant_type": "refresh_token", "refresh_token": rt})
		}
		requireVerified := func(enabled, enrolling flowResponse, method string) {
			t.Helper()
			require.NotEmpty(t, enabled.BackupCodes)
			require.Empty(t, enabled.Tokens.RefreshToken, "step-up style response never rotates the refresh token")
			claims := unverifiedAccessClaims(t, enabled.Tokens.AccessToken)
			require.ElementsMatch(t, []any{"pwd", method, "otp", "mfa"}, claims["amr"])
			require.Equal(t, embedded.AssuranceLevelMFA, claims["acr"])
			require.Equal(t, true, claims["mfa_enrolled"])
			require.Contains(t, enabled.raw, `"fresh_auth"`)
			refreshed := f.expect(200, refresh(enrolling.RefreshToken))
			f.session(refreshed.TokenSet, "pwd", method, "otp", "mfa")
			require.Equal(t, true, unverifiedAccessClaims(t, refreshed.AccessToken)["mfa_enrolled"])
		}
		requireChallenged := func(other flowResponse, method string) {
			t.Helper()
			challenged := f.expect(403, refresh(other.RefreshToken))
			require.Equal(t, "2fa_required", challenged.Error.Code)
			require.Equal(t, method, challenged.Error.Metadata.Method)
		}

		t.Run("totp", func(t *testing.T) {
			f.t = t
			_, _, enrolling, other := login("enroll-totp")
			started := f.expect(200, f.request("POST", "/user/2fa", enrolling.AccessToken, map[string]any{"method": "totp"}))
			enabled := f.expect(200, f.request("POST", "/user/2fa", enrolling.AccessToken, map[string]any{"method": "totp", "code": flowTOTP(t, started.Secret)}))
			requireVerified(enabled, enrolling, "totp")
			requireChallenged(other, "totp")
		})

		t.Run("email", func(t *testing.T) {
			f.t = t
			_, _, enrolling, other := login("enroll-email")
			f.expect(202, f.request("POST", "/user/2fa", enrolling.AccessToken, map[string]any{"method": "email"}))
			code := f.email.verificationCode(t)
			wrong := f.expect(400, f.request("POST", "/user/2fa", enrolling.AccessToken, map[string]any{"method": "email", "code": "000000x"}))
			require.Equal(t, "invalid_code", wrong.Error.Code)
			enabled := f.expect(200, f.request("POST", "/user/2fa", enrolling.AccessToken, map[string]any{"method": "email", "code": code}))
			requireVerified(enabled, enrolling, "email")
			requireChallenged(other, "email")
		})

		t.Run("sms", func(t *testing.T) {
			f.t = t
			_, _, enrolling, other := login("enroll-sms")
			phone := uniquePhone()
			f.expect(202, f.request("POST", "/user/2fa", enrolling.AccessToken, map[string]any{"method": "sms", "phone_number": phone}))
			enabled := f.expect(200, f.request("POST", "/user/2fa", enrolling.AccessToken, map[string]any{"method": "sms", "phone_number": phone, "code": f.sms.verificationCode(t)}))
			requireVerified(enabled, enrolling, "sms")
			requireChallenged(other, "sms")
		})

		t.Run("same channel is not a second factor", func(t *testing.T) {
			f.t = t
			userID, email, _, _ := login("enroll-same-channel")
			f.expect(202, f.post("/passwordless/start", map[string]any{"identifier": email, "mode": "code"}))
			session := f.expect(200, f.post("/passwordless/confirm", map[string]any{"identifier": email, "code": f.email.verificationCode(t)}))
			f.session(session.TokenSet, "email")
			f.expect(202, f.request("POST", "/user/2fa", session.AccessToken, map[string]any{"method": "email"}))
			enabled := f.expect(200, f.request("POST", "/user/2fa", session.AccessToken, map[string]any{"method": "email", "code": f.email.verificationCode(t)}))
			require.NotEmpty(t, enabled.BackupCodes)
			require.Empty(t, enabled.Tokens.AccessToken)
			var amr []string
			require.NoError(t, pool.QueryRow(ctx, `SELECT auth_methods FROM refresh_sessions WHERE id=$1`, unverifiedAccessClaims(t, session.AccessToken)["sid"]).Scan(&amr))
			require.ElementsMatch(t, []string{"email"}, amr)
			challenged := f.expect(403, refresh(session.RefreshToken))
			require.Equal(t, "2fa_required", challenged.Error.Code)
			require.Equal(t, userID, challenged.Error.Metadata.UserID)
			require.Equal(t, "backup_code", challenged.Error.Metadata.Method)
		})
	})
}

// Forced enrollment ends with a 2FA-verified session for every proven method.
func TestForcedEmailEnrollmentIssuesVerifiedSession(t *testing.T) {
	forEachStore(t, func(t *testing.T, store ephemeralStore) {
		cfg := newServerTestConfig()
		cfg.TwoFactor.Mode = embedded.TwoFactorRequired
		f := newAccountFlow(t, testdb.Pool(t), store, cfg)
		ctx := t.Context()
		email := uniqueEmail("forced-email")
		user, err := f.service.svc.CreateUser(ctx, email, "forced"+uniqueSuffix())
		require.NoError(t, err)
		require.NoError(t, f.service.svc.AdminSetPassword(ctx, user.ID, enrollPassword))
		require.NoError(t, f.service.svc.MarkEmailVerified(ctx, user.ID))

		grant := f.expect(403, f.post("/password/login", map[string]any{"identifier": email, "password": enrollPassword}))
		require.Equal(t, "2fa_enrollment_required", grant.Error.Code)
		require.Contains(t, grant.Error.Metadata.AllowedMethods, "email")
		restricted := grant.Error.Metadata.TokenSet.AccessToken
		f.expect(202, f.request("POST", "/user/2fa", restricted, map[string]any{"method": "email"}))
		enabled := f.expect(200, f.request("POST", "/user/2fa", restricted, map[string]any{"method": "email", "code": f.email.verificationCode(t)}))
		require.NotEmpty(t, enabled.BackupCodes)
		f.session(enabled.TokenSet, "pwd", "email", "otp", "mfa")
		refreshed := f.expect(200, f.post("/token", map[string]any{"grant_type": "refresh_token", "refresh_token": enabled.RefreshToken}))
		f.session(refreshed.TokenSet, "pwd", "email", "otp", "mfa")
	})
}
