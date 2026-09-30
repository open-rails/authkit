package authkit_test

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
	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/open-rails/authkit/internal/testkeys"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
)

func testHTTPConfig() authkit.HTTPConfig {
	limits := authkit.DefaultRateLimits()
	for bucket := range limits {
		limits[bucket] = authkit.RateLimit{Limit: 10000, Window: time.Minute}
	}
	return authkit.HTTPConfig{DirectPeerIP: true, RateLimits: limits}
}

func TestRuntimeConfiguredHTTPLoginAndLifecycle(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	cfg := testConfig(t)
	cfg.TwoFactor.Mode = iam.TwoFactorDisabled
	cfg.HTTP = testHTTPConfig()
	cfg.HTTP.APIPath = "/auth"
	runtime := newPublicRuntime(t, cfg, pg.Pool)
	t.Cleanup(runtime.Close)
	_, err := runtime.CreateUser(context.Background(), iam.NewUser{Email: "runtime-boundary@example.test", Username: "runtime-boundary", Password: "Correct-horse-battery-1"})
	require.NoError(t, err)
	require.Contains(t, patterns(runtime), "GET "+iam.JWKSPath)
	require.Contains(t, patterns(runtime), "POST /auth/password/login")

	handler := http.NewServeMux()
	require.NoError(t, runtime.Mount(handler))
	chiRouter := chi.NewRouter()
	for _, pattern := range patterns(runtime) {
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
	cfg := testConfig(t)
	cfg.HTTP = authkit.HTTPConfig{DirectPeerIP: true, APIPath: "bad prefix"}
	_, err := authkit.New(context.Background(), cfg, authkit.Deps{Postgres: pg.Pool})
	require.ErrorContains(t, err, "APIPath")
	cfg.HTTP = authkit.HTTPConfig{DirectPeerIP: true, Exclude: []string{"GET /nowhere"}}
	_, err = authkit.New(context.Background(), cfg, authkit.Deps{Postgres: pg.Pool})
	require.ErrorContains(t, err, "matches no mounted route")
	require.NoError(t, pg.Pool.Ping(t.Context()), "a failed construction closed the host-owned pool")

	headless := newPublicRuntime(t, testConfig(t), pg.Pool)
	t.Cleanup(headless.Close)
	require.Nil(t, headless.Handler())
	require.Error(t, headless.Mount(http.NewServeMux()))
	user, err := headless.CreateUser(context.Background(), iam.NewUser{Email: "headless@example.test", Username: "headless", Password: "Correct-horse-battery-1"})
	require.NoError(t, err)
	token, err := headless.MintAccessToken(context.Background(), user.ID, iam.AccessTokenOptions{})
	require.NoError(t, err)
	cl, err := headless.Verify(context.Background(), token.Value)
	require.NoError(t, err, "a headless runtime still verifies")
	require.Equal(t, user.ID, cl.UserID)
}

// The Client owns the HTTP layer's background workers: the memory limiter's
// sweep (Redis needs none) stops at Close, however often it runs, and a failed
// construction strands none. The host's pool and Redis stay usable.
func TestRuntimeOwnsConfiguredHTTPWorkers(t *testing.T) {
	for _, tc := range []struct {
		name      string
		redis     bool
		configure func(*authkit.Config)
		err       string
	}{
		{name: "memory limiter"},
		{name: "redis limiter", redis: true},
		{name: "invalid prefix", configure: func(c *authkit.Config) { c.HTTP.APIPath = "invalid prefix" }, err: "APIPath"},
		{name: "delegated route without its authorizer", configure: func(c *authkit.Config) {
			c.Delegated = authkit.DelegatedConfig{Audiences: []string{"resource.example"}}
		}, err: "Deps.DelegatedAuthorization"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pg := testdb.ScratchPostgres(t)
			const label = "authkit-runtime-http"
			// labelled reports a goroutine New started whose stack names frame.
			labelled := func(frame string) bool {
				var profile bytes.Buffer
				require.NoError(t, pprof.Lookup("goroutine").WriteTo(&profile, 1))
				for _, record := range strings.Split(profile.String(), "\n\n") {
					if strings.Contains(record, strconv.Quote(label)+":"+strconv.Quote(t.Name())) && strings.Contains(record, frame) {
						return true
					}
				}
				return false
			}
			hasWorkers := func() bool { return labelled("") }
			cfg := testConfig(t)
			cfg.HTTP = authkit.HTTPConfig{DirectPeerIP: true}
			var rdb *redis.Client
			if tc.redis {
				rdb = testdb.ScratchRedis(t)
				cfg.HTTP.Redis = rdb
			}
			if tc.configure != nil {
				tc.configure(&cfg)
			}
			var runtime *authkit.Client
			var err error
			pprof.Do(t.Context(), pprof.Labels(label, t.Name()), func(context.Context) {
				runtime, err = authkit.New(context.Background(), cfg, authkit.Deps{Postgres: pg.Pool, River: authkit.RiverFromHost()})
			})
			if tc.err != "" {
				require.ErrorContains(t, err, tc.err)
				require.Nil(t, runtime)
			} else {
				require.NoError(t, err)
				require.Equal(t, !tc.redis, labelled("internal/ratelimit/memory."), "only the memory limiter starts a sweep worker")
				runtime.Close()
				runtime.Close()
			}
			require.Eventually(t, func() bool { return !hasWorkers() }, 5*time.Second, 10*time.Millisecond, "HTTP workers survived runtime cleanup")
			require.NoError(t, pg.Pool.Ping(t.Context()))
			if rdb != nil {
				require.NoError(t, rdb.Ping(t.Context()).Err(), "the host's Redis client remains usable")
			}
		})
	}
}

func newPublicRuntime(t *testing.T, cfg authkit.Config, pool *pgxpool.Pool) *authkit.Client {
	t.Helper()
	r, err := authkit.New(context.Background(), cfg, authkit.Deps{Postgres: pool})
	require.NoError(t, err)
	return r
}

func TestRuntimeConstructorHTTPFailureKeepsBorrowedPool(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	// No client-IP posture: the HTTP layer refuses after the engine is built.
	cfg := testConfig(t)
	cfg.HTTP = authkit.HTTPConfig{APIPath: "/auth"}
	runtime, err := authkit.New(context.Background(), cfg, authkit.Deps{Postgres: pg.Pool, River: authkit.RiverFromHost()})
	require.ErrorContains(t, err, "client-IP posture")
	require.Nil(t, runtime)
	require.NoError(t, pg.Pool.Ping(t.Context()), "constructor cleanup must preserve the borrowed host pool")
}

func testConfig(t *testing.T) authkit.Config {
	t.Helper()
	signer := testkeys.RSA("runtime-test")
	return authkit.Config{
		Keys:         authkit.KeysConfig{Source: testkeys.Source(signer)},
		Token:        authkit.TokenConfig{Issuer: "https://example.com", IssuedAudiences: []string{"test-app"}},
		Registration: authkit.RegistrationConfig{Verification: iam.RegistrationVerificationNone},
	}
}
