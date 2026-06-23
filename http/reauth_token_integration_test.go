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
	user, err := srv.Core().CreateUser(ctx, email, username)
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE id=$1::uuid`, user.ID) })
	hash, err := password.HashArgon2id(pass)
	require.NoError(t, err)
	require.NoError(t, srv.Core().UpsertPasswordHash(ctx, user.ID, hash, "argon2id", nil))

	sid, _, _, err := srv.Core().IssueRefreshSession(ctx, user.ID, "test", nil)
	require.NoError(t, err)
	token, _, err := srv.Core().IssueAccessToken(ctx, user.ID, "", map[string]any{"sid": sid})
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
	user, err := srv.Core().CreateUser(ctx, email, username)
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE id=$1::uuid`, user.ID) })
	hash, err := password.HashArgon2id(pass)
	require.NoError(t, err)
	require.NoError(t, srv.Core().UpsertPasswordHash(ctx, user.ID, hash, "argon2id", nil))

	sid, _, _, err := srv.Core().IssueRefreshSession(ctx, user.ID, "test", nil)
	require.NoError(t, err)
	setupToken, _, err := srv.Core().IssueAccessToken(ctx, user.ID, "", map[string]any{"sid": sid})
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
