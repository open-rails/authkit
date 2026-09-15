package authhttp

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"

	"github.com/open-rails/authkit/embedded"
	"github.com/open-rails/authkit/internal/testdb"
)

type staticHTTPEntitlementsProvider struct {
	names []string
}

func (p staticHTTPEntitlementsProvider) ListEntitlements(_ context.Context, userIDs []string) (map[string][]string, error) {
	out := make(map[string][]string, len(userIDs))
	for _, id := range userIDs {
		out[id] = p.names
	}
	return out, nil
}

func unverifiedAccessClaims(t *testing.T, token string) jwt.MapClaims {
	t.Helper()
	claims := jwt.MapClaims{}
	parsed, _, err := jwt.NewParser().ParseUnverified(token, claims)
	require.NoError(t, err)
	assertWireGolden(t, "access-header", parsed.Header)
	return claims
}

func assertSlimUserAccessClaims(t *testing.T, claims jwt.MapClaims) {
	t.Helper()
	assertWireGolden(t, "access-claims", claims)
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

// Goldens require the documented fields and types while allowing additive keys.
// They inspect actual HTTP/JWT output, independently of Go DTO field names.
func assertWireGolden(t *testing.T, name string, value any) {
	t.Helper()
	fixture, err := os.ReadFile(filepath.Join("testdata", "wire", name+".json"))
	require.NoError(t, err)
	var expected, actual any
	require.NoError(t, json.Unmarshal(fixture, &expected))
	encoded, err := json.Marshal(value)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(encoded, &actual))
	var match func(any, any, string)
	match = func(want, got any, path string) {
		switch want := want.(type) {
		case map[string]any:
			require.IsType(t, want, got, path)
			fields := got.(map[string]any)
			for key, value := range want {
				require.Contains(t, fields, key, path)
				match(value, fields[key], path+"."+key)
			}
		case string:
			switch want {
			case "$string":
				require.IsType(t, "", got, path)
				require.NotEmpty(t, got, path)
			case "$number":
				require.IsType(t, float64(0), got, path)
				require.Greater(t, got.(float64), float64(0), path)
			default:
				require.Equal(t, want, got, path)
			}
		default:
			require.Equal(t, want, got, path)
		}
	}
	match(expected, actual, name)
}

func TestSessionWireWorkflow(t *testing.T) {
	ctx := context.Background()
	pool := testdb.Pool(t)
	const email = "slim-token-shape-http@example.com"
	const username = "slimtokenshapehttp"
	const pass = "correct-horse-battery-97"
	_, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE email=$1 OR username=$2`, email, username)

	cfg := embedded.Config{
		Keys: testKeys(),
		Token: embedded.TokenConfig{
			Issuer:            "https://example.com",
			IssuedAudiences:   []string{"test-app"},
			ExpectedAudiences: []string{"test-app"},
		},
		Frontend:     embedded.FrontendConfig{BaseURL: "https://example.com"},
		Registration: embedded.RegistrationConfig{Verification: embedded.RegistrationVerificationNone},
	}
	svc, err := newServer(newServerClient(t, cfg, pool, withEntitlements(staticHTTPEntitlementsProvider{names: []string{"premium"}})))
	require.NoError(t, err)
	defer svc.Close()

	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE email=$1`, email) })
	h, err := MountHandler(svc, MountOptions{})
	require.NoError(t, err)
	registration := postCookieJSON(h, "/api/v1/register", `{"identifier":"`+email+`","username":"`+username+`","password":"`+pass+`"}`)
	require.Equal(t, http.StatusAccepted, registration.Code, registration.Body.String())
	assertWireGolden(t, "registration", json.RawMessage(registration.Body.Bytes()))
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/password/login", bytes.NewReader([]byte(`{"identifier":"`+email+`","password":"`+pass+`"}`)))
	r.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(w, r)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assertWireGolden(t, "token-set", json.RawMessage(w.Body.Bytes()))
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
	r = httptest.NewRequest(http.MethodPost, "/api/v1/token", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(w, r)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assertWireGolden(t, "token-set", json.RawMessage(w.Body.Bytes()))
	var refreshResp struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &refreshResp))
	require.NotEmpty(t, refreshResp.AccessToken)
	assertSlimUserAccessClaims(t, unverifiedAccessClaims(t, refreshResp.AccessToken))

	w = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodDelete, "/api/v1/logout", nil)
	r.Header.Set("Authorization", "Bearer "+refreshResp.AccessToken)
	h.ServeHTTP(w, r)
	require.Equal(t, http.StatusNoContent, w.Code, w.Body.String())
	require.Empty(t, w.Body.String())
	replay := postCookieJSON(h, "/api/v1/token", `{"grant_type":"refresh_token","refresh_token":"`+refreshResp.RefreshToken+`"}`)
	require.Equal(t, http.StatusUnauthorized, replay.Code, replay.Body.String())
	assertWireGolden(t, "refresh-error", json.RawMessage(replay.Body.Bytes()))
}
