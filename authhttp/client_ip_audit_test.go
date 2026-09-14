package authhttp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/stretchr/testify/require"
)

type auditIPLimiter struct{ keys []string }

func (l *auditIPLimiter) AllowNamed(_ string, key string) (bool, error) {
	l.keys = append(l.keys, key)
	return true, nil
}

func TestConfiguredClientIPMatchesRateLimitSessionAndAudit(t *testing.T) {
	ctx := context.Background()
	pg := testdb.ScratchPostgres(t)
	core := newServerClient(t, newServerTestConfig(), pg.Pool)
	for _, tc := range []struct {
		name, peer, want string
		option           Option
	}{
		{"trusted proxy", "10.1.2.3:443", "203.0.113.7", WithTrustedProxies("10.0.0.0/8")},
		{"untrusted peer", "198.51.100.9:443", "198.51.100.9", WithTrustedProxies("10.0.0.0/8")},
		{"direct peer", "10.1.2.3:443", "10.1.2.3", WithDirectPeerIP()},
		{"explicit resolver", "10.1.2.3:443", "203.0.113.42", WithClientIPFunc(func(*http.Request) string { return "203.0.113.42" })},
	} {
		t.Run(tc.name, func(t *testing.T) {
			limiter := &auditIPLimiter{}
			srv, err := newServer(core, tc.option, WithRateLimiter(limiter))
			require.NoError(t, err)
			defer srv.Close()
			email, plain := newCookieTestUser(t, pg.Pool, srv, "auditip")
			h, err := MountHandler(srv, MountOptions{})
			require.NoError(t, err)
			post := func(path, body string) *httptest.ResponseRecorder {
				r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
				r.Header.Set("Content-Type", "application/json")
				r.RemoteAddr = tc.peer
				r.Header.Set("X-Forwarded-For", "203.0.113.7")
				r.Header.Set("CF-Connecting-IP", "203.0.113.99")
				w := httptest.NewRecorder()
				h.ServeHTTP(w, r)
				return w
			}
			login := post("/api/v1/password/login", `{"identifier":"`+email+`","password":"`+plain+`"}`)
			require.Equal(t, http.StatusOK, login.Code, login.Body.String())
			require.Contains(t, limiter.keys, RLPasswordLogin+":ip:"+tc.want)
			user, err := srv.svc.GetUserByEmail(ctx, email)
			require.NoError(t, err)
			var storedIP, eventIP string
			require.NoError(t, pg.Pool.QueryRow(ctx, `SELECT host(ip_addr) FROM profiles.refresh_sessions WHERE user_id=$1`, user.ID).Scan(&storedIP))
			require.NoError(t, pg.Pool.QueryRow(ctx, `SELECT ip_addr FROM profiles.session_events WHERE user_id=$1 AND event='session_created' ORDER BY id DESC LIMIT 1`, user.ID).Scan(&eventIP))
			require.Equal(t, tc.want, storedIP)
			require.Equal(t, tc.want, eventIP)
			var tokens authkit.TokenSet
			require.NoError(t, json.Unmarshal(login.Body.Bytes(), &tokens))
			refreshed := post("/api/v1/token", `{"grant_type":"refresh_token","refresh_token":"`+tokens.RefreshToken+`"}`)
			require.Equal(t, http.StatusOK, refreshed.Code, refreshed.Body.String())
			require.NoError(t, pg.Pool.QueryRow(ctx, `SELECT host(ip_addr) FROM profiles.refresh_sessions WHERE user_id=$1 AND revoked_at IS NULL`, user.ID).Scan(&storedIP))
			require.Equal(t, tc.want, storedIP)
		})
	}
}
