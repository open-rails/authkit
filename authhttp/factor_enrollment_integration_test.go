package authhttp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/open-rails/authkit/embedded"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/stretchr/testify/require"
)

func TestFactorEnrollmentRequiresFreshAuthAndPreservesFactor(t *testing.T) {
	ctx := context.Background()
	pool := testdb.Pool(t)
	cfg := newServerTestConfig()
	cfg.TwoFactor.TOTPSecretKey = []byte("0123456789abcdef")
	srv, err := newServer(newServerClient(t, cfg, pool, withEmailSender(testEmailSender{})), WithoutRateLimiter())
	require.NoError(t, err)
	const pass = "Correct-password-12345"
	userID, stale := stalePasswordUserToken(t, srv, pool, "factor-enrollment", pass)
	for _, body := range []string{`{"method":"totp"}`, `{"method":"totp","code":"123456"}`, `{"method":"email"}`, `{"method":"sms","phone":"+15551234567"}`, `{"default":true,"factor_id":"anything"}`} {
		w := serveAuthJSON(srv, http.MethodPost, "/user/2fa", body, stale)
		require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
		require.Contains(t, w.Body.String(), "step_up_required")
	}
	w := serveAuthJSON(srv, http.MethodPost, "/step-up/password", `{"password":"`+pass+`"}`, stale)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var stepped nestedTokenBody
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &stepped))
	var beforeTime time.Time
	var beforeAMR []string
	require.NoError(t, pool.QueryRow(ctx, `SELECT last_authenticated_at, auth_methods FROM profiles.refresh_sessions WHERE user_id=$1`, userID).Scan(&beforeTime, &beforeAMR))
	w = serveAuthJSON(srv, http.MethodPost, "/user/2fa", `{"method":"totp"}`, stepped.AccessToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var pending struct {
		Secret string `json:"secret"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &pending))
	w = serveAuthJSON(srv, http.MethodPost, "/user/2fa", fmt.Sprintf(`{"method":"totp","code":%q}`, testTOTPCode(t, pending.Secret, time.Now().Unix()/30)), stepped.AccessToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.Contains(t, w.Body.String(), "backup_codes")
	original, err := srv.svc.Get2FASettings(ctx, userID)
	require.NoError(t, err)
	var afterTime time.Time
	var afterAMR []string
	require.NoError(t, pool.QueryRow(ctx, `SELECT last_authenticated_at, auth_methods FROM profiles.refresh_sessions WHERE user_id=$1`, userID).Scan(&afterTime, &afterAMR))
	require.Equal(t, beforeTime, afterTime, "enrollment must not refresh authentication")
	require.Equal(t, beforeAMR, afterAMR, "enrollment must not add MFA assurance")
	require.NotContains(t, afterAMR, "mfa")
	sessionID := unverifiedAccessClaims(t, stepped.AccessToken)["sid"]
	currentToken, _, err := srv.svc.MintAccessToken(ctx, userID, map[string]any{"sid": sessionID})
	require.NoError(t, err)
	w = serveAuthJSON(srv, http.MethodPost, "/user/2fa/backup-codes", `{}`, currentToken)
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
	require.Contains(t, w.Body.String(), "step_up_required")

	// Even the pre-enrollment fresh token now needs proof of the enrolled factor.
	w = serveAuthJSON(srv, http.MethodPost, "/user/2fa", `{"method":"totp"}`, stepped.AccessToken)
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
	// A real factor proof allows management, but enrollment still cannot replace it.
	w = serveAuthJSON(srv, http.MethodPost, "/step-up/2fa", fmt.Sprintf(`{"method":"totp","code":%q}`, testTOTPCode(t, pending.Secret, time.Now().Unix()/30+1)), stepped.AccessToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &stepped))
	w = serveAuthJSON(srv, http.MethodPost, "/user/2fa", `{"method":"totp"}`, stepped.AccessToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &pending))
	w = serveAuthJSON(srv, http.MethodPost, "/user/2fa", fmt.Sprintf(`{"method":"totp","code":%q}`, testTOTPCode(t, pending.Secret, time.Now().Unix()/30)), stepped.AccessToken)
	require.Equal(t, http.StatusConflict, w.Code, w.Body.String())
	require.Contains(t, w.Body.String(), "2fa_factor_exists")
	preserved, err := srv.svc.Get2FASettings(ctx, userID)
	require.NoError(t, err)
	require.Equal(t, original.Factors[0].ID, preserved.Factors[0].ID)
	require.Equal(t, original.TOTPSecret, preserved.TOTPSecret)
	require.Equal(t, original.BackupCodes, preserved.BackupCodes)
}

func TestRefreshEnrollmentTokenCanOnlyAddFirstFactor(t *testing.T) {
	pool := testdb.Pool(t)
	cfg := newServerTestConfig()
	cfg.TwoFactor = embedded.TwoFactorConfig{Mode: embedded.TwoFactorRequired, TOTPSecretKey: []byte("0123456789abcdef")}
	oldCfg := cfg
	oldCfg.TwoFactor.Mode = embedded.TwoFactorOptional
	sender := &captureEmailSender{}
	oldSrv, err := newServer(newServerClient(t, oldCfg, pool, withEmailSender(sender)), WithoutRateLimiter())
	require.NoError(t, err)
	srv, err := newServer(newServerClient(t, cfg, pool, withEmailSender(sender)), WithoutRateLimiter())
	require.NoError(t, err)
	for _, scenario := range []string{"email", "totp", "revoked"} {
		t.Run(scenario, func(t *testing.T) {
			userID := mustPasswordUser(t, oldSrv, "refresh-"+scenario)
			w := login(t, oldSrv, "refresh-"+scenario, userID)
			require.Equal(t, http.StatusOK, w.Code, w.Body.String())
			var tokens struct {
				AccessToken  string `json:"access_token"`
				RefreshToken string `json:"refresh_token"`
			}
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &tokens))
			w = serveJSON(srv, http.MethodPost, "/token", `{"grant_type":"refresh_token","refresh_token":"`+tokens.RefreshToken+`"}`)
			grant := requireEnrollmentToken(t, w)
			claims := unverifiedAccessClaims(t, grant)
			require.Equal(t, true, claims["2fa_enrollment"])
			require.Empty(t, claims["sid"])
			var access string
			if scenario == "email" {
				w = serveAuthJSON(srv, http.MethodPost, "/user/2fa", `{"method":"email"}`, grant)
				challenge := requireTwoFARequired(t, w)
				require.Contains(t, w.Body.String(), "backup_codes")
				w = serveJSON(srv, http.MethodPost, "/2fa/verify", fmt.Sprintf(`{"user_id":%q,"challenge":%q,"code":%q}`, userID, challenge.Challenge, sender.lastLoginCode()))
				require.Equal(t, http.StatusOK, w.Code, w.Body.String())
				require.NoError(t, json.Unmarshal(w.Body.Bytes(), &tokens))
				access = tokens.AccessToken
			} else {
				w = serveAuthJSON(srv, http.MethodPost, "/user/2fa", `{"method":"totp"}`, grant)
				require.Equal(t, http.StatusOK, w.Code, w.Body.String())
				var pending struct {
					Secret string `json:"secret"`
				}
				require.NoError(t, json.Unmarshal(w.Body.Bytes(), &pending))
				if scenario == "revoked" {
					require.NoError(t, srv.svc.RevokeAllSessions(t.Context(), userID, nil))
				}
				w = serveAuthJSON(srv, http.MethodPost, "/user/2fa", fmt.Sprintf(`{"method":"totp","code":%q}`, testTOTPCode(t, pending.Secret, time.Now().Unix()/30)), grant)
				if scenario == "revoked" {
					require.Equal(t, http.StatusUnauthorized, w.Code, w.Body.String())
					factors, err := srv.svc.List2FAFactors(t.Context(), userID)
					require.NoError(t, err)
					require.Empty(t, factors, "revoked source cannot persist a factor")
					return
				}
				require.Equal(t, http.StatusOK, w.Code, w.Body.String())
				require.Contains(t, w.Body.String(), "backup_codes")
				var completed nestedTokenBody
				require.NoError(t, json.Unmarshal(w.Body.Bytes(), &completed))
				access = completed.AccessToken
			}
			require.NotEmpty(t, access)
			w = serveAuthJSON(srv, http.MethodGet, "/me", `{}`, access)
			require.Equal(t, http.StatusOK, w.Code, w.Body.String())
			for _, body := range []string{`{"method":"email"}`, `{"method":"totp"}`, `{"default":true,"factor_id":"anything"}`} {
				w = serveAuthJSON(srv, http.MethodPost, "/user/2fa", body, grant)
				require.Equal(t, http.StatusConflict, w.Code, w.Body.String())
			}
			w = serveAuthJSON(srv, http.MethodPost, "/user/2fa/backup-codes", `{}`, grant)
			require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
		})
	}
}
