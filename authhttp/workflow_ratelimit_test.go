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

	"github.com/open-rails/authkit/documents"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/open-rails/authkit/ratelimit"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
)

// forEachLimiter runs fn with the per-process limiter (rdb nil) and with the
// shared Redis limiter.
func forEachLimiter(t *testing.T, fn func(t *testing.T, rdb *redis.Client)) {
	t.Run("memory", func(t *testing.T) { fn(t, nil) })
	t.Run("redis", func(t *testing.T) { fn(t, testdb.ScratchRedis(t)) })
}

// The same mounted login runs with each production limiter. Password checks
// are limited per client address only: an exhausted address cannot log in even
// with the correct password, while the owner elsewhere is never locked out. A
// Redis command failure is an outage, never a successful login.
func TestWorkflowRateLimits(t *testing.T) {
	forEachLimiter(t, testWorkflowRateLimits)
}

func testWorkflowRateLimits(t *testing.T, rdb *redis.Client) {
	pg := testdb.ScratchPostgres(t)
	client := newServerClient(t, newServerTestConfig(), pg.Pool)
	email := uniqueEmail("limited")
	user, err := client.CreateUser(t.Context(), email, "limited"+uniqueSuffix())
	require.NoError(t, err)
	require.NoError(t, client.AdminSetPassword(t.Context(), user.ID, "Correct-password-12345"))
	cfg := workflowHTTPConfig()
	cfg.DirectPeerIP = false
	cfg.ClientIP = func(r *http.Request) string {
		return r.Header.Get("X-Forwarded-For")
	}
	cfg.RateLimits[RLPasswordLogin] = ratelimit.Limit{Limit: 2, Window: time.Minute}
	cfg.RateLimits[RLPasswordStepUp] = ratelimit.Limit{Limit: 2, Window: time.Minute}
	if rdb != nil {
		cfg.Redis, cfg.PerProcessRateLimits = rdb, false
	}
	svc, err := newTestService(client, cfg)
	require.NoError(t, err)
	t.Cleanup(svc.Close)
	mount, err := MountHandler(svc, MountOptions{})
	require.NoError(t, err)
	server := httptest.NewServer(mount)
	t.Cleanup(server.Close)
	post := func(path, token, forwarded string, payload map[string]string) (int, map[string]any) {
		raw, err := json.Marshal(payload)
		require.NoError(t, err)
		req, err := http.NewRequest(http.MethodPost, server.URL+DefaultAPIPrefix+path, strings.NewReader(string(raw)))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Forwarded-For", forwarded)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		response, err := server.Client().Do(req)
		require.NoError(t, err)
		defer response.Body.Close()
		var body map[string]any
		require.NoError(t, json.NewDecoder(response.Body).Decode(&body))
		return response.StatusCode, body
	}
	login := func(password, forwarded string) (int, map[string]any) {
		return post("/password/login", "", forwarded, map[string]string{"identifier": email, "password": password})
	}
	stepUp := func(token, password, forwarded string) (int, map[string]any) {
		return post("/step-up/password", token, forwarded, map[string]string{"password": password})
	}
	for range 2 {
		status, body := login("wrong-password", "198.51.100.1")
		require.Equal(t, http.StatusUnauthorized, status, body)
	}
	status, body := login("Correct-password-12345", "198.51.100.1")
	require.Equal(t, http.StatusTooManyRequests, status, body)
	require.Equal(t, "rate_limited", body["error"].(map[string]any)["code"])
	var sessions int
	require.NoError(t, pg.Pool.QueryRow(t.Context(), `SELECT count(*) FROM refresh_sessions WHERE user_id=$1`, user.ID).Scan(&sessions))
	require.Zero(t, sessions)
	status, body = login("Correct-password-12345", "198.51.100.2")
	require.Equal(t, http.StatusOK, status, "a stranger's failures locked the owner out: %v", body)
	require.NoError(t, pg.Pool.QueryRow(t.Context(), `SELECT count(*) FROM refresh_sessions WHERE user_id=$1`, user.ID).Scan(&sessions))
	require.Equal(t, 1, sessions)

	const stepUpPassword = "Correct-password-12345"
	_, staleToken := stalePasswordUserToken(t, svc, pg.Pool, "limited-step-up", stepUpPassword)
	for range 2 {
		status, body = stepUp(staleToken, "wrong-password", "198.51.100.5")
		require.Equal(t, http.StatusUnauthorized, status, body)
	}
	status, body = stepUp(staleToken, stepUpPassword, "198.51.100.5")
	require.Equal(t, http.StatusTooManyRequests, status, body)
	require.Equal(t, "rate_limited", body["error"].(map[string]any)["code"])
	status, body = post("/user/password", staleToken, "198.51.100.5", map[string]string{
		"current_password": stepUpPassword,
		"new_password":     "Another-password-12345",
	})
	require.Equal(t, http.StatusTooManyRequests, status, body)
	status, body = stepUp(staleToken, stepUpPassword, "198.51.100.7")
	require.Equal(t, http.StatusOK, status, body)

	if rdb != nil {
		cfg.RateLimits[RLPasswordLogin] = ratelimit.Limit{Limit: 10000, Window: time.Minute}
		_, outageToken := stalePasswordUserToken(t, svc, pg.Pool, "limited-step-up-outage", stepUpPassword)
		cfg.Redis = redis.NewClient(rdb.Options())
		outage, err := newTestService(client, cfg)
		require.NoError(t, err)
		t.Cleanup(outage.Close)
		mounted, err := MountHandler(outage, MountOptions{})
		require.NoError(t, err)
		server = httptest.NewServer(mounted)
		t.Cleanup(server.Close)
		// Closing only this test's client preserves the Redis server and other
		// fixtures while forcing the real limiter's backend-error path.
		require.NoError(t, cfg.Redis.Close())
		status, body = login("Correct-password-12345", "198.51.100.4")
		require.Equal(t, http.StatusTooManyRequests, status, body)
		require.NoError(t, pg.Pool.QueryRow(context.Background(), `SELECT count(*) FROM refresh_sessions WHERE user_id=$1`, user.ID).Scan(&sessions))
		require.Equal(t, 1, sessions)
		status, body = stepUp(outageToken, stepUpPassword, "198.51.100.9")
		require.Equal(t, http.StatusTooManyRequests, status, body)
	}
}

// Label the goroutines created by this constructor, so other services and the
// embedded engine cannot mask an HTTP-layer worker leak.
func TestServiceOwnsBackgroundWorkers(t *testing.T) {
	forEachLimiter(t, testServiceOwnsBackgroundWorkers)
}

func testServiceOwnsBackgroundWorkers(t *testing.T, rdb *redis.Client) {
	client := newServerClient(t, newServerTestConfig(), testdb.Pool(t))
	workerLabel := "authhttp-service"
	hasWorkers := func() bool {
		var profile bytes.Buffer
		require.NoError(t, pprof.Lookup("goroutine").WriteTo(&profile, 1))
		return strings.Contains(profile.String(), strconv.Quote(workerLabel)+":"+strconv.Quote(t.Name()))
	}
	construct := func(cfg Config) (*Service, error) {
		var svc *Service
		var err error
		pprof.Do(t.Context(), pprof.Labels(workerLabel, t.Name()), func(context.Context) {
			svc, err = newTestService(client, cfg)
		})
		return svc, err
	}

	// A valid HTTP config can still fail the cross-layer document policy.
	// Failed construction must not strand workers the caller cannot close.
	svc, err := construct(Config{DirectPeerIP: true, PerProcessRateLimits: true, Documents: []DocumentProvider{&documents.Service{}}})
	require.ErrorContains(t, err, "Readers is empty")
	require.Nil(t, svc)
	require.False(t, hasWorkers(), "failed construction leaked background workers")

	cfg := Config{DirectPeerIP: true, PerProcessRateLimits: true}
	if rdb != nil {
		cfg.Redis, cfg.PerProcessRateLimits = rdb, false
	}
	svc, err = construct(cfg)
	require.NoError(t, err)
	t.Cleanup(svc.Close)
	require.Equal(t, rdb == nil, hasWorkers(), "only the memory limiter should start a sweep worker")
	svc.Close()
	svc.Close()
	require.Eventually(t, func() bool { return !hasWorkers() }, 5*time.Second, 10*time.Millisecond,
		"Close must stop every worker started by the HTTP service")
	require.NoError(t, client.Postgres().Ping(t.Context()), "the host's pool remains usable")
	if rdb != nil {
		require.NoError(t, rdb.Ping(t.Context()).Err(), "the host's Redis client remains usable")
	}
}

func TestRateLimiterIsAnExplicitChoice(t *testing.T) {
	require.ErrorContains(t, Config{DirectPeerIP: true}.Validate(), "choose exactly one rate limiter")
	require.ErrorContains(t, Config{DirectPeerIP: true, PerProcessRateLimits: true, DisableRateLimiting: true}.Validate(), "choose exactly one rate limiter")
	require.NoError(t, Config{DirectPeerIP: true, PerProcessRateLimits: true}.Validate())
}
