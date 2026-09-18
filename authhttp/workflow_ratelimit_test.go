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
		cfg.RateLimits[RLPasswordLogin] = ratelimit.Limit{Limit: 2, Window: time.Minute}
		svc, err := New(client, cfg)
		require.NoError(t, err)
		t.Cleanup(svc.Close)
		mount, err := MountHandler(svc, MountOptions{})
		require.NoError(t, err)
		server := httptest.NewServer(mount)
		t.Cleanup(server.Close)
		login := func(password, forwarded string) (int, map[string]any) {
			raw, err := json.Marshal(map[string]string{"identifier": email, "password": password})
			require.NoError(t, err)
			req, err := http.NewRequest(http.MethodPost, server.URL+DefaultAPIPrefix+"/password/login", strings.NewReader(string(raw)))
			require.NoError(t, err)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Forwarded-For", forwarded)
			response, err := server.Client().Do(req)
			require.NoError(t, err)
			defer response.Body.Close()
			var body map[string]any
			require.NoError(t, json.NewDecoder(response.Body).Decode(&body))
			return response.StatusCode, body
		}
		for _, ip := range []string{"198.51.100.1", "198.51.100.2"} {
			status, body := login("wrong-password", ip)
			require.Equal(t, http.StatusUnauthorized, status, body)
		}
		status, body := login("Correct-password-12345", "198.51.100.3")
		require.Equal(t, http.StatusTooManyRequests, status, body)
		require.Equal(t, "rate_limited", body["error"].(map[string]any)["code"])
		var sessions int
		require.NoError(t, pg.Pool.QueryRow(t.Context(), `SELECT count(*) FROM profiles.refresh_sessions WHERE user_id=$1`, user.ID).Scan(&sessions))
		require.Zero(t, sessions)
		if store.rdb != nil {
			cfg.RateLimits[RLPasswordLogin] = ratelimit.Limit{Limit: 10000, Window: time.Minute}
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
			require.NoError(t, pg.Pool.QueryRow(context.Background(), `SELECT count(*) FROM profiles.refresh_sessions WHERE user_id=$1`, user.ID).Scan(&sessions))
			require.Zero(t, sessions)
		}
	})
}
