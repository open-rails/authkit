package authhttp

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"runtime/pprof"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	authkithttp "github.com/open-rails/authkit/adapters/http"
	"github.com/open-rails/authkit/embedded"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/stretchr/testify/require"
)

func TestRuntimeConfiguredHTTPLoginAndLifecycle(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	cfg := newServerTestConfig()
	cfg.TwoFactor.Mode = embedded.TwoFactorDisabled
	policy := workflowHTTPConfig()
	policy.Mount.APIPrefix = "/auth"
	cfg.HTTP = policy
	runtime := newPublicRuntime(t, cfg, pg.Pool)
	t.Cleanup(runtime.Close)
	user, err := runtime.Client().CreateUser(context.Background(), "runtime-boundary@example.test", "runtime-boundary")
	require.NoError(t, err)
	require.NoError(t, runtime.Client().AdminSetPassword(context.Background(), user.ID, "Correct-horse-battery-1"))
	require.NotNil(t, runtime.Verifier())
	routes, err := runtime.HTTPRoutes()
	require.NoError(t, err)
	require.NotEmpty(t, routes)
	bundle, err := authkithttp.Routes(runtime)
	require.NoError(t, err)
	handler := http.NewServeMux()
	require.NoError(t, bundle.Mount(handler))
	chiRouter := chi.NewRouter()
	require.NoError(t, bundle.Mount(chiRouter))
	chiResponse := httptest.NewRecorder()
	chiRouter.ServeHTTP(chiResponse, httptest.NewRequest(http.MethodGet, JWKSPath, nil))
	require.Equal(t, http.StatusOK, chiResponse.Code)
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
	runtime := newPublicRuntime(t, newServerTestConfig(), pg.Pool)
	t.Cleanup(runtime.Close)
	err := runtime.ConfigureHTTP(Config{DirectPeerIP: true, Mount: MountOptions{APIPrefix: "bad prefix"}})
	require.Error(t, err)
	require.Nil(t, runtime.Verifier())
	_, err = runtime.Client().CreateUser(context.Background(), "after-http-failure@example.test", "after-http-failure")
	require.NoError(t, err)
	require.Error(t, runtime.ConfigureHTTP(Config{DirectPeerIP: true}))
}

func TestRuntimeOwnsConfiguredHTTPWorkers(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(strconv.FormatBool(fail), func(t *testing.T) {
			pg := testdb.ScratchPostgres(t)
			runtime := newPublicRuntime(t, newServerTestConfig(), pg.Pool)
			t.Cleanup(runtime.Close)
			const label = "authkit-runtime-http"
			hasWorkers := func() bool {
				var profile bytes.Buffer
				require.NoError(t, pprof.Lookup("goroutine").WriteTo(&profile, 1))
				return strings.Contains(profile.String(), strconv.Quote(label)+":"+strconv.Quote(t.Name()))
			}
			cfg := Config{DirectPeerIP: true}
			if fail {
				cfg.Mount.APIPrefix = "invalid prefix"
			}
			var err error
			pprof.Do(t.Context(), pprof.Labels(label, t.Name()), func(context.Context) { err = runtime.ConfigureHTTP(cfg) })
			if fail {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.True(t, hasWorkers())
				runtime.Close()
			}
			require.Eventually(t, func() bool { return !hasWorkers() }, 5*time.Second, 10*time.Millisecond, "HTTP workers survived runtime cleanup")
			require.NoError(t, pg.Pool.Ping(t.Context()))
		})
	}
}

func newPublicRuntime(t *testing.T, cfg embedded.Config, pool *pgxpool.Pool) *embedded.Runtime {
	t.Helper()
	r, err := embedded.New(cfg, embedded.Deps{Postgres: pool})
	require.NoError(t, err)
	return r
}
