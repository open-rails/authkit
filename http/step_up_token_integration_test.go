package authhttp

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	core "github.com/open-rails/authkit/core"
	"github.com/open-rails/authkit/password"
	memorystore "github.com/open-rails/authkit/storage/memory"
	"github.com/stretchr/testify/require"
)

func TestPasswordReauthReturnsFreshAccessToken(t *testing.T) {
	ctx := context.Background()
	pool := newServerTestPool(t)
	srv, err := NewServer(newServerTestConfig(), pool, WithoutRateLimiter())
	require.NoError(t, err)

	email := uniqueEmail("reauth-password")
	username := "reauthpwd" + uniqueSuffix()
	const pass = "Correct-password-12345"
	user, err := srv.svc.CreateUser(ctx, email, username)
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE id=$1::uuid`, user.ID) })
	hash, err := password.HashArgon2id(pass)
	require.NoError(t, err)
	require.NoError(t, srv.svc.UpsertPasswordHash(ctx, user.ID, hash, "argon2id", nil))

	sid, _, _, err := srv.svc.IssueRefreshSession(ctx, user.ID, "test", nil)
	require.NoError(t, err)
	token, _, err := srv.svc.IssueAccessToken(ctx, user.ID, "", map[string]any{"sid": sid})
	require.NoError(t, err)

	w := serveAuthJSON(srv, http.MethodPost, "/reauth/password", `{"password":"`+pass+`"}`, token)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var body struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	require.NotEmpty(t, body.AccessToken)
	require.Equal(t, "Bearer", body.TokenType)
	require.Positive(t, body.ExpiresIn)

	claims := unverifiedAccessClaims(t, body.AccessToken)
	require.NotEmpty(t, claims["auth_time"])
	require.ElementsMatch(t, []any{"pwd"}, claims["amr"])
	require.Equal(t, core.AssuranceLevelPassword, claims["acr"])
}

func TestTOTPReauthReturnsFreshMFAAccessToken(t *testing.T) {
	pool := newServerTestPool(t)
	ctx := context.Background()
	cfg := newServerTestConfig()
	cfg.TwoFactor.TOTPSecretKey = []byte("0123456789abcdef")
	srv, err := NewServer(cfg, pool, WithEphemeralStore(memorystore.NewKV(), core.EphemeralMemory), WithoutRateLimiter())
	require.NoError(t, err)

	email := uniqueEmail("reauth-totp")
	username := "reauthotp" + uniqueSuffix()
	const pass = "Correct-password-12345"
	user, err := srv.svc.CreateUser(ctx, email, username)
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE id=$1::uuid`, user.ID) })
	hash, err := password.HashArgon2id(pass)
	require.NoError(t, err)
	require.NoError(t, srv.svc.UpsertPasswordHash(ctx, user.ID, hash, "argon2id", nil))

	sid, _, _, err := srv.svc.IssueRefreshSession(ctx, user.ID, "test", nil)
	require.NoError(t, err)
	setupToken, _, err := srv.svc.IssueAccessToken(ctx, user.ID, "", map[string]any{"sid": sid})
	require.NoError(t, err)

	w := serveAuthJSON(srv, http.MethodPost, "/user/2fa", `{"method":"totp"}`, setupToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var enrollment struct {
		Secret string `json:"secret"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &enrollment))
	require.NotEmpty(t, enrollment.Secret)

	code := testTOTPCode(t, enrollment.Secret, time.Now().Unix()/30)
	w = serveAuthJSON(srv, http.MethodPost, "/user/2fa", `{"method":"totp","code":"`+code+`"}`, setupToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	w = serveAuthJSON(srv, http.MethodPost, "/reauth/2fa", `{}`, setupToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	reauthCode := testTOTPCode(t, enrollment.Secret, time.Now().Unix()/30+1)
	w = serveAuthJSON(srv, http.MethodPost, "/reauth/2fa", `{"code":"`+reauthCode+`"}`, setupToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var body struct {
		AccessToken string `json:"access_token"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	require.NotEmpty(t, body.AccessToken)

	claims := unverifiedAccessClaims(t, body.AccessToken)
	require.NotEmpty(t, claims["auth_time"])
	require.ElementsMatch(t, []any{"pwd", "otp", "mfa"}, claims["amr"])
	require.Equal(t, core.AssuranceLevelMFA, claims["acr"])
}

func TestTwoFactorReauthMethodOptionsAndStaleMFARetry(t *testing.T) {
	pool := newServerTestPool(t)
	ctx := context.Background()
	cfg := newServerTestConfig()
	cfg.TwoFactor.TOTPSecretKey = []byte("0123456789abcdef")
	srv, err := NewServer(cfg, pool, WithEphemeralStore(memorystore.NewKV(), core.EphemeralMemory), WithoutRateLimiter())
	require.NoError(t, err)

	email := uniqueEmail("reauth-options")
	username := "reauthopts" + uniqueSuffix()
	const pass = "Correct-password-12345"
	user, err := srv.svc.CreateUser(ctx, email, username)
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE id=$1::uuid`, user.ID) })
	hash, err := password.HashArgon2id(pass)
	require.NoError(t, err)
	require.NoError(t, srv.svc.UpsertPasswordHash(ctx, user.ID, hash, "argon2id", nil))

	sid, _, _, err := srv.svc.IssueRefreshSession(ctx, user.ID, "test", nil)
	require.NoError(t, err)
	setupToken, _, err := srv.svc.IssueAccessToken(ctx, user.ID, "", map[string]any{"sid": sid})
	require.NoError(t, err)

	w := serveAuthJSON(srv, http.MethodPost, "/user/2fa", `{"method":"email"}`, setupToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	phone := "+15555550123"
	_, err = srv.svc.Enable2FA(ctx, user.ID, "sms", &phone)
	require.NoError(t, err)
	w = serveAuthJSON(srv, http.MethodPost, "/user/2fa", `{"method":"totp"}`, setupToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var enrollment struct {
		Secret string `json:"secret"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &enrollment))
	code := testTOTPCode(t, enrollment.Secret, time.Now().Unix()/30)
	w = serveAuthJSON(srv, http.MethodPost, "/user/2fa", `{"method":"totp","code":"`+code+`"}`, setupToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	w = serveAuthJSON(srv, http.MethodGet, "/me", `{}`, setupToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var me struct {
		ReauthMethods []string               `json:"reauth_methods"`
		Reauth2FA     reauthOptionsTestShape `json:"reauth_2fa"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &me))
	require.Contains(t, me.ReauthMethods, "2fa")
	requireReauth2FAOptions(t, me.Reauth2FA, []string{"email", "sms", "totp"}, "email")

	_, err = pool.Exec(ctx, `UPDATE profiles.refresh_sessions SET last_authenticated_at = now() - interval '1 hour', auth_methods = ARRAY['pwd','otp','mfa']::text[] WHERE id=$1::uuid`, sid)
	require.NoError(t, err)
	staleToken, _, err := srv.svc.IssueAccessToken(ctx, user.ID, "", map[string]any{"sid": sid})
	require.NoError(t, err)

	w = serveAuthJSON(srv, http.MethodPost, "/user/2fa/backup-codes", `{}`, staleToken)
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
	var reauthRequired struct {
		Error struct {
			Code     string `json:"code"`
			Metadata struct {
				ReauthMethods []string               `json:"reauth_methods"`
				Reauth2FA     reauthOptionsTestShape `json:"reauth_2fa"`
			} `json:"metadata"`
		} `json:"error"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &reauthRequired))
	require.Equal(t, "reauth_required", reauthRequired.Error.Code)
	require.Contains(t, reauthRequired.Error.Metadata.ReauthMethods, "2fa")
	requireReauth2FAOptions(t, reauthRequired.Error.Metadata.Reauth2FA, []string{"email", "sms", "totp"}, "email")

	w = serveAuthJSON(srv, http.MethodPost, "/reauth/2fa", `{"method":"totp"}`, staleToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.Contains(t, w.Body.String(), `"method":"totp"`)
	require.NotContains(t, w.Body.String(), "factor")
	w = serveAuthJSON(srv, http.MethodPost, "/reauth/2fa", `{"method":"bad"}`, staleToken)
	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
	w = serveAuthJSON(srv, http.MethodPost, "/reauth/2fa", `{"factor_id":"anything"}`, staleToken)
	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())

	reauthCode := testTOTPCode(t, enrollment.Secret, time.Now().Unix()/30+1)
	w = serveAuthJSON(srv, http.MethodPost, "/reauth/2fa", `{"method":"totp","code":"`+reauthCode+`"}`, staleToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var reauthBody struct {
		AccessToken string `json:"access_token"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &reauthBody))
	require.NotEmpty(t, reauthBody.AccessToken)

	w = serveAuthJSON(srv, http.MethodPost, "/user/2fa/backup-codes", `{}`, reauthBody.AccessToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.Contains(t, w.Body.String(), "backup_codes")
}

type reauthOptionsTestShape struct {
	Methods       []string `json:"methods"`
	DefaultMethod string   `json:"default_method"`
	Options       []struct {
		ID             string `json:"id"`
		Method         string `json:"method"`
		IsDefault      bool   `json:"is_default"`
		VerificationID string `json:"verification_id"`
	} `json:"options"`
}

func requireReauth2FAOptions(t *testing.T, got reauthOptionsTestShape, methods []string, defaultMethod string) {
	t.Helper()
	require.ElementsMatch(t, methods, got.Methods)
	require.Equal(t, defaultMethod, got.DefaultMethod)
	seen := map[string]bool{}
	for _, option := range got.Options {
		require.Empty(t, option.ID)
		require.NotEmpty(t, option.Method)
		seen[option.Method] = true
		if option.Method == defaultMethod {
			require.True(t, option.IsDefault)
		}
		if option.Method == "email" || option.Method == "sms" {
			require.NotEmpty(t, option.VerificationID)
		}
	}
	for _, method := range methods {
		require.True(t, seen[method], "missing 2FA option %q", method)
	}
}
