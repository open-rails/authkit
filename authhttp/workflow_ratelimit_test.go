package authhttp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/open-rails/authkit/internal/testdb"
	"github.com/open-rails/authkit/ratelimit"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
)

// The same mounted login runs with each production limiter. A correct password
// cannot bypass an exhausted budget by forging the client IP; no session is
// created. A Redis command failure is an outage, never a successful login.
func TestWorkflowRateLimits(t *testing.T) {
	forEachStore(t, func(t *testing.T, store ephemeralStore) {
		pg := testdb.ScratchPostgres(t)
		client := newServerClient(t, newServerTestConfig(), pg.Pool, store.engineOpts()...)
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
		svc, err := New(client, cfg)
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
		for _, ip := range []string{"198.51.100.1", "198.51.100.2"} {
			status, body := login("wrong-password", ip)
			require.Equal(t, http.StatusUnauthorized, status, body)
		}
		status, body := login("Correct-password-12345", "198.51.100.3")
		require.Equal(t, http.StatusTooManyRequests, status, body)
		require.Equal(t, "rate_limited", body["error"].(map[string]any)["code"])
		var sessions int
		require.NoError(t, pg.Pool.QueryRow(t.Context(), `SELECT count(*) FROM refresh_sessions WHERE user_id=$1`, user.ID).Scan(&sessions))
		require.Zero(t, sessions)

		const stepUpPassword = "Correct-password-12345"
		_, staleToken := stalePasswordUserToken(t, svc, pg.Pool, "limited-step-up", stepUpPassword)
		for _, ip := range []string{"198.51.100.5", "198.51.100.6"} {
			status, body = stepUp(staleToken, "wrong-password", ip)
			require.Equal(t, http.StatusUnauthorized, status, body)
		}
		status, body = stepUp(staleToken, stepUpPassword, "198.51.100.7")
		require.Equal(t, http.StatusTooManyRequests, status, body)
		require.Equal(t, "rate_limited", body["error"].(map[string]any)["code"])
		status, body = post("/user/password", staleToken, "198.51.100.8", map[string]string{
			"current_password": stepUpPassword,
			"new_password":     "Another-password-12345",
		})
		require.Equal(t, http.StatusTooManyRequests, status, body)

		if store.rdb != nil {
			cfg.RateLimits[RLPasswordLogin] = ratelimit.Limit{Limit: 10000, Window: time.Minute}
			_, outageToken := stalePasswordUserToken(t, svc, pg.Pool, "limited-step-up-outage", stepUpPassword)
			cfg.Redis = redis.NewClient(store.rdb.Options())
			outage, err := New(client, cfg)
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
			require.Zero(t, sessions)
			status, body = stepUp(outageToken, stepUpPassword, "198.51.100.9")
			require.Equal(t, http.StatusTooManyRequests, status, body)
		}
	})
}
