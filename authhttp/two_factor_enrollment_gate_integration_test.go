package authhttp

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	authkit "github.com/open-rails/authkit"
	"github.com/stretchr/testify/require"
)

// #281: enrollment needs a fresh session, never overwrites a live factor, and is
// not itself an MFA proof for the enrolling session.
func TestTwoFactorEnrollmentRequiresFreshAuthAndNeverOverwrites(t *testing.T) {
	pool := newServerTestPool(t)
	ctx := context.Background()
	cfg := newServerTestConfig()
	cfg.TwoFactor.TOTPSecretKey = []byte("0123456789abcdef")
	srv, err := NewServer(newServerClient(t, cfg, pool), WithoutRateLimiter())
	require.NoError(t, err)

	const pass = "Correct-password-12345"
	userID, staleToken := stalePasswordUserToken(t, srv, pool, "2fa-enroll-gate", pass)

	w := serveAuthJSON(srv, http.MethodPost, "/user/2fa", `{"method":"totp"}`, staleToken)
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
	require.Contains(t, w.Body.String(), "step_up_required")

	w = serveAuthJSON(srv, http.MethodPost, "/step-up/password", `{"password":"`+pass+`"}`, staleToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var stepUp struct {
		AccessToken string `json:"access_token"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &stepUp))
	fresh := stepUp.AccessToken

	w = serveAuthJSON(srv, http.MethodPost, "/user/2fa", `{"method":"totp"}`, fresh)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var enrollment struct {
		Secret string `json:"secret"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &enrollment))
	code := testTOTPCode(t, enrollment.Secret, time.Now().Unix()/30)
	w = serveAuthJSON(srv, http.MethodPost, "/user/2fa", `{"method":"totp","code":"`+code+`"}`, fresh)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.Contains(t, w.Body.String(), `"backup_codes"`)

	// Enrolling proves nothing about identity: the session gains no otp/mfa
	// method, so a token minted afterwards does not clear an MFA-if-enrolled gate.
	sid := unverifiedAccessClaims(t, fresh)["sid"].(string)
	var authMethods []string
	require.NoError(t, pool.QueryRow(ctx, `SELECT auth_methods FROM profiles.refresh_sessions WHERE id=$1::uuid`, sid).Scan(&authMethods))
	require.NotContains(t, authMethods, "mfa")
	require.NotContains(t, authMethods, "otp")
	afterEnroll, _, err := srv.svc.MintAccessToken(ctx, userID, map[string]any{"sid": sid})
	require.NoError(t, err)
	require.Equal(t, true, unverifiedAccessClaims(t, afterEnroll)["mfa_enrolled"])
	w = serveAuthJSON(srv, http.MethodPost, "/user/2fa/backup-codes", `{}`, afterEnroll)
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
	require.Contains(t, w.Body.String(), "step_up_required")

	// A second enrollment of the same method never replaces the live factor.
	var secretBefore []byte
	require.NoError(t, pool.QueryRow(ctx, `SELECT totp_secret FROM profiles.mfa_factors WHERE user_id=$1::uuid AND method='totp'`, userID).Scan(&secretBefore))
	w = serveAuthJSON(srv, http.MethodPost, "/user/2fa", `{"method":"totp"}`, fresh)
	require.Equal(t, http.StatusConflict, w.Code, w.Body.String())
	require.Contains(t, w.Body.String(), "2fa_factor_exists")
	var secretAfter []byte
	require.NoError(t, pool.QueryRow(ctx, `SELECT totp_secret FROM profiles.mfa_factors WHERE user_id=$1::uuid AND method='totp'`, userID).Scan(&secretAfter))
	require.Equal(t, secretBefore, secretAfter)

	phone, otherPhone := "+15555550100", "+15555550199"
	_, err = srv.svc.Enable2FA(ctx, userID, "sms", &phone)
	require.NoError(t, err)
	_, err = srv.svc.Enable2FA(ctx, userID, "sms", &otherPhone)
	require.ErrorIs(t, err, authkit.ErrTwoFAFactorExists)
	var storedPhone string
	require.NoError(t, pool.QueryRow(ctx, `SELECT phone_number FROM profiles.mfa_factors WHERE user_id=$1::uuid AND method='sms'`, userID).Scan(&storedPhone))
	require.Equal(t, phone, storedPhone)

	// An enrollment-only token cannot add to an account that already has a factor.
	enrollToken, _, err := srv.svc.Mint2FAEnrollmentToken(ctx, userID)
	require.NoError(t, err)
	w = serveAuthJSON(srv, http.MethodPost, "/user/2fa", `{"method":"email"}`, enrollToken)
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
	require.NotContains(t, w.Body.String(), "step_up_required")
}

// The enrollment-only token minted after a password proof still enrolls the
// FIRST factor without a session, and is spent once one exists.
func TestTwoFactorEnrollmentTokenAddsFirstFactorOnly(t *testing.T) {
	pool := newServerTestPool(t)
	ctx := context.Background()
	cfg := newServerTestConfig()
	cfg.TwoFactor.TOTPSecretKey = []byte("0123456789abcdef")
	srv, err := NewServer(newServerClient(t, cfg, pool), WithoutRateLimiter())
	require.NoError(t, err)

	userID, _ := stalePasswordUserToken(t, srv, pool, "2fa-enroll-first", "Correct-password-12345")
	enrollToken, _, err := srv.svc.Mint2FAEnrollmentToken(ctx, userID)
	require.NoError(t, err)

	w := serveAuthJSON(srv, http.MethodPost, "/user/2fa", `{"method":"totp"}`, enrollToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var enrollment struct {
		Secret string `json:"secret"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &enrollment))
	code := testTOTPCode(t, enrollment.Secret, time.Now().Unix()/30)
	w = serveAuthJSON(srv, http.MethodPost, "/user/2fa", `{"method":"totp","code":"`+code+`"}`, enrollToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.Contains(t, w.Body.String(), `"backup_codes"`)

	w = serveAuthJSON(srv, http.MethodPost, "/user/2fa", `{"method":"totp"}`, enrollToken)
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
	w = serveAuthJSON(srv, http.MethodPost, "/user/2fa", `{"method":"email"}`, enrollToken)
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
}
