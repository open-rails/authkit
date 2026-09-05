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
	// Issue a session before the site enables mandatory enrollment.
	oldCfg := cfg
	oldCfg.TwoFactor.Mode = embedded.TwoFactorOptional
	oldSrv, err := newServer(newServerClient(t, oldCfg, pool), WithoutRateLimiter())
	require.NoError(t, err)
	userID := mustPasswordUser(t, oldSrv, "first-factor-token")
	w := login(t, oldSrv, "first-factor-token", userID)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var tokens struct {
		RefreshToken string `json:"refresh_token"`
		AccessToken  string `json:"access_token"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &tokens))
	srv, err := newServer(newServerClient(t, cfg, pool, withEmailSender(testEmailSender{})), WithoutRateLimiter())
	require.NoError(t, err)
	w = serveJSON(srv, http.MethodPost, "/token", `{"grant_type":"refresh_token","refresh_token":"`+tokens.RefreshToken+`"}`)
	require.Contains(t, w.Body.String(), "requires_2fa_enrollment")
	tokens.AccessToken = requireEnrollmentToken(t, w)
	claims := unverifiedAccessClaims(t, tokens.AccessToken)
	require.Equal(t, true, claims["2fa_enrollment"])
	require.Empty(t, claims["sid"])
	w = serveAuthJSON(srv, http.MethodPost, "/user/2fa", `{"method":"email"}`, tokens.AccessToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	for _, body := range []string{`{"method":"email"}`, `{"method":"totp"}`, `{"default":true,"factor_id":"anything"}`} {
		w = serveAuthJSON(srv, http.MethodPost, "/user/2fa", body, tokens.AccessToken)
		require.Equal(t, http.StatusConflict, w.Code, w.Body.String())
	}
	w = serveAuthJSON(srv, http.MethodPost, "/user/2fa/backup-codes", `{}`, tokens.AccessToken)
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
}
