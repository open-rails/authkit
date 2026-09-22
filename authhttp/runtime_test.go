package authhttp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/open-rails/authkit/embedded"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/stretchr/testify/require"
)

func TestRuntimeConfiguredHTTPLoginAndLifecycle(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	cfg := newServerTestConfig()
	cfg.TwoFactor.Mode = embedded.TwoFactorDisabled
	runtime := newServerClient(t, cfg, pg.Pool)
	t.Cleanup(runtime.Close)
	user, err := runtime.Client().CreateUser(context.Background(), "runtime-boundary@example.test", "runtime-boundary")
	require.NoError(t, err)
	require.NoError(t, runtime.Client().AdminSetPassword(context.Background(), user.ID, "Correct-horse-battery-1"))
	policy := workflowHTTPConfig()
	policy.Mount.APIPrefix = "/auth"
	require.NoError(t, runtime.ConfigureHTTP(policy))
	require.NotNil(t, runtime.Verifier())
	routes, err := runtime.HTTPRoutes()
	require.NoError(t, err)
	require.NotEmpty(t, routes)
	handler := routes[0].Handler // every registration delegates to the same configured canonical mount
	call := func(method, path, body, token string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	require.Equal(t, http.StatusOK, call(http.MethodGet, JWKSPath, "", "").Code)
	require.Equal(t, http.StatusNotFound, call(http.MethodGet, "/auth"+JWKSPath, "", "").Code)
	require.Equal(t, http.StatusUnauthorized, call(http.MethodGet, "/auth/me", "", "").Code)
	login := call(http.MethodPost, "/auth/password/login", `{"identifier":"runtime-boundary@example.test","password":"Correct-horse-battery-1"}`, "")
	require.Equal(t, http.StatusOK, login.Code, login.Body.String())
	var tokens struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	require.NoError(t, json.Unmarshal(login.Body.Bytes(), &tokens))
	require.NotEmpty(t, tokens.AccessToken)
	require.Equal(t, http.StatusOK, call(http.MethodGet, "/auth/me", "", tokens.AccessToken).Code)
	require.Equal(t, http.StatusForbidden, call(http.MethodGet, "/auth/admin/users", "", tokens.AccessToken).Code)
	require.Equal(t, http.StatusOK, call(http.MethodGet, "/auth/user/sessions", "", tokens.AccessToken).Code)
	require.Error(t, runtime.ConfigureHTTP(policy))
	runtime.Close()
	runtime.Close()
	require.NoError(t, pg.Pool.Ping(context.Background()), "runtime closed host-owned pool")
	_, err = runtime.HTTPRoutes()
	require.Error(t, err)
}

func TestRuntimeHTTPBuildFailureKeepsOperationClient(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	runtime := newServerClient(t, newServerTestConfig(), pg.Pool)
	t.Cleanup(runtime.Close)
	err := runtime.ConfigureHTTP(Config{DirectPeerIP: true, Mount: MountOptions{APIPrefix: "bad prefix"}})
	require.Error(t, err)
	require.Nil(t, runtime.Verifier())
	_, err = runtime.Client().CreateUser(context.Background(), "after-http-failure@example.test", "after-http-failure")
	require.NoError(t, err)
	require.Error(t, runtime.ConfigureHTTP(Config{DirectPeerIP: true}))
}
