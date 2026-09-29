package authkit

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
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/stretchr/testify/require"
)

func testHTTPConfig() *HTTPConfig {
	limits := DefaultRateLimits()
	for bucket := range limits {
		limits[bucket] = RateLimit{Limit: 10000, Window: time.Minute}
	}
	return &HTTPConfig{DirectPeerIP: true, RateLimits: limits}
}

func TestRuntimeConfiguredHTTPLoginAndLifecycle(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	cfg := newServerTestConfig()
	cfg.TwoFactor.Mode = iam.TwoFactorDisabled
	cfg.HTTP = testHTTPConfig()
	cfg.HTTP.APIPrefix = "/auth"
	runtime := newPublicRuntime(t, cfg, pg.Pool)
	t.Cleanup(runtime.Close)
	user, err := runtime.Client().CreateUser(context.Background(), "runtime-boundary@example.test", "runtime-boundary")
	require.NoError(t, err)
	require.NoError(t, runtime.Client().AdminSetPassword(context.Background(), user.ID, "Correct-horse-battery-1"))
	require.NotNil(t, runtime.Verifier())
	require.Contains(t, runtime.Patterns(), "GET "+iam.JWKSPath)
	require.Contains(t, runtime.Patterns(), "POST /auth/password/login")

	handler := http.NewServeMux()
	require.NoError(t, runtime.Mount(handler))
	chiRouter := chi.NewRouter()
	for _, pattern := range runtime.Patterns() {
		method, path, _ := strings.Cut(pattern, " ")
		chiRouter.Method(method, path, runtime.Handler())
	}
	chiResponse := httptest.NewRecorder()
	chiRouter.ServeHTTP(chiResponse, httptest.NewRequest(http.MethodGet, iam.JWKSPath, nil))
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
	require.Equal(t, http.StatusOK, call(http.MethodGet, iam.JWKSPath, "", "").Code)
	require.Equal(t, http.StatusOK, call(http.MethodHead, iam.JWKSPath, "", "").Code)
	require.Equal(t, http.StatusNotFound, call(http.MethodGet, "/auth"+iam.JWKSPath, "", "").Code)
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
	runtime.Close()
	runtime.Close()
	require.NoError(t, pg.Pool.Ping(context.Background()), "runtime closed host-owned pool")
}

func TestRuntimeHTTPBuildFailureReleasesEverything(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	cfg := newServerTestConfig()
	cfg.HTTP = &HTTPConfig{DirectPeerIP: true, APIPrefix: "bad prefix"}
	_, err := New(cfg, Deps{Postgres: pg.Pool})
	require.ErrorContains(t, err, "APIPrefix")
	cfg.HTTP = &HTTPConfig{DirectPeerIP: true, Exclude: []string{"GET /nowhere"}}
	_, err = New(cfg, Deps{Postgres: pg.Pool})
	require.ErrorContains(t, err, "matches no mounted route")
	require.NoError(t, pg.Pool.Ping(t.Context()), "a failed construction closed the host-owned pool")

	headless := newPublicRuntime(t, newServerTestConfig(), pg.Pool)
	t.Cleanup(headless.Close)
	require.Nil(t, headless.Handler())
	require.Error(t, headless.Mount(http.NewServeMux()))
	require.NotNil(t, headless.Verifier(), "a headless runtime still verifies")
}

func TestRuntimeOwnsConfiguredHTTPWorkers(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(strconv.FormatBool(fail), func(t *testing.T) {
			pg := testdb.ScratchPostgres(t)
			const label = "authkit-runtime-http"
			hasWorkers := func() bool {
				var profile bytes.Buffer
				require.NoError(t, pprof.Lookup("goroutine").WriteTo(&profile, 1))
				return strings.Contains(profile.String(), strconv.Quote(label)+":"+strconv.Quote(t.Name()))
			}
			cfg := newServerTestConfig()
			cfg.HTTP = &HTTPConfig{DirectPeerIP: true}
			if fail {
				cfg.HTTP.APIPrefix = "invalid prefix"
			}
			var runtime *Runtime
			var err error
			pprof.Do(t.Context(), pprof.Labels(label, t.Name()), func(context.Context) {
				runtime, err = New(cfg, Deps{Postgres: pg.Pool, River: RiverFromHost()})
			})
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

func newPublicRuntime(t *testing.T, cfg Config, pool *pgxpool.Pool) *Runtime {
	t.Helper()
	r, err := New(cfg, Deps{Postgres: pool})
	require.NoError(t, err)
	return r
}
