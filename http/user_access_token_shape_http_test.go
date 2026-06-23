package authhttp

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"

	core "github.com/open-rails/authkit/core"
	"github.com/open-rails/authkit/password"
)

type staticHTTPEntitlementsProvider struct {
	names []string
}

func (p staticHTTPEntitlementsProvider) ListEntitlements(context.Context, string) ([]string, error) {
	return p.names, nil
}

func unverifiedAccessClaims(t *testing.T, token string) jwt.MapClaims {
	t.Helper()
	claims := jwt.MapClaims{}
	_, _, err := jwt.NewParser().ParseUnverified(token, claims)
	require.NoError(t, err)
	return claims
}

func assertSlimUserAccessClaims(t *testing.T, claims jwt.MapClaims) {
	t.Helper()
	require.NotEmpty(t, claims["sub"])
	require.NotEmpty(t, claims["sid"])
	require.ElementsMatch(t, []any{"premium"}, claims["entitlements"])
	for _, forbidden := range []string{
		"email",
		"email_verified",
		"username",
		"discord_username",
	} {
		_, ok := claims[forbidden]
		require.False(t, ok, "%s claim must not be minted on user access tokens", forbidden)
	}
}

func TestPasswordLoginAndRefreshMintSlimUserAccessTokens(t *testing.T) {
	ctx := context.Background()
	pool := newServerTestPool(t)
	const email = "slim-token-shape-http@example.com"
	const username = "slimtokenshapehttp"
	const pass = "correct-horse-battery-97"
	_, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE email=$1 OR username=$2`, email, username)

	cfg := core.Config{
		Token: core.TokenConfig{
			Issuer:            "https://example.com",
			IssuedAudiences:   []string{"test-app"},
			ExpectedAudiences: []string{"test-app"},
		},
		Frontend:     core.FrontendConfig{BaseURL: "https://example.com"},
		Registration: core.RegistrationConfig{Verification: core.RegistrationVerificationNone},
	}
	svc, err := NewServer(cfg, pool, WithEntitlements(staticHTTPEntitlementsProvider{names: []string{"premium"}}))
	require.NoError(t, err)

	user, err := svc.svc.CreateUser(ctx, email, username)
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE id=$1::uuid`, user.ID) })
	hash, err := password.HashArgon2id(pass)
	require.NoError(t, err)
	require.NoError(t, svc.svc.UpsertPasswordHash(ctx, user.ID, hash, "argon2id", nil))

	h := svc.APIHandler()
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/password/login", bytes.NewReader([]byte(`{"login":"`+email+`","password":"`+pass+`"}`)))
	r.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(w, r)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var loginResp struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &loginResp))
	require.NotEmpty(t, loginResp.AccessToken)
	require.NotEmpty(t, loginResp.RefreshToken)
	assertSlimUserAccessClaims(t, unverifiedAccessClaims(t, loginResp.AccessToken))

	w = httptest.NewRecorder()
	body := []byte(`{"grant_type":"refresh_token","refresh_token":"` + loginResp.RefreshToken + `"}`)
	r = httptest.NewRequest(http.MethodPost, "/token", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(w, r)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var refreshResp struct {
		AccessToken string `json:"access_token"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &refreshResp))
	require.NotEmpty(t, refreshResp.AccessToken)
	assertSlimUserAccessClaims(t, unverifiedAccessClaims(t, refreshResp.AccessToken))
}
