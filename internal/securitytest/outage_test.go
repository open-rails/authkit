package securitytest

import (
	"context"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/iam"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
)

// limiterDown is a replica of h whose rate limiter's Redis is unreachable.
func (h *host) limiterDown() *host {
	h.t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(h.t, err)
	addr := ln.Addr().String()
	require.NoError(h.t, ln.Close())
	rdb := redis.NewClient(&redis.Options{Addr: addr, MaxRetries: -1, DialTimeout: time.Second})
	h.t.Cleanup(func() { _ = rdb.Close() })
	cfg := h.cfg.engine
	cfg.HTTP.Redis = rdb
	r, err := authkit.New(context.Background(), cfg, h.cfg.deps)
	require.NoError(h.t, err)
	h.t.Cleanup(r.Close)
	return h.fork(r)
}

// TestSecurityLimiterOutageRefusesSecretChecks: when the rate limiter's backend
// fails, every route that checks a secret (a password, one-time or backup code,
// a link, refresh or invite token, or a signature over a challenge) is refused,
// so an outage never lifts the guessing budget. Routes that check none stay up.
// Every mounted route is classified here, so a new secret check cannot ship
// unproven.
func TestSecurityLimiterOutageRefusesSecretChecks(t *testing.T) {
	h := newHost(t, withHTTP(generousLimits), withEngine(withRBAC), withEngine(withDeviceKeys), withEngine(withPasskeys),
		withProviders(&stubProvider{name: "stub"}), withEngine(func(c *authkit.Config) {
			c.Registration.PasswordlessLogin = true
			c.SolanaNetwork = "devnet"
		}))
	down := h.limiterDown()
	a := h.newAccount("outage")
	_, claims := splitToken(t, h.login(a).AccessToken)
	sid, _ := claims["sid"].(string)
	require.NotEmpty(t, sid)
	// Past the fresh-auth window, the account routes ask for the password.
	_, err := h.pool.Exec(context.Background(), `UPDATE profiles.refresh_sessions SET last_authenticated_at=now()-interval '20 minutes', mfa_authenticated_at=now()-interval '20 minutes' WHERE id=$1::uuid`, sid)
	require.NoError(t, err)
	token := h.sessionToken(a.id, sid)

	post := func(path string, body any) request {
		return request{method: http.MethodPost, path: path, body: body, token: token}
	}
	code := map[string]string{"identifier": a.email, "code": "123456"}
	secretChecks := map[string]request{
		"POST /password/login":                    post("/password/login", map[string]string{"identifier": a.email, "password": password}),
		"POST /account/recovery/confirm":          post("/account/recovery/confirm", map[string]string{"token": "recovery-token"}),
		"POST /register":                          post("/register", map[string]string{"identifier": unique("outage") + "@security.test", "username": unique("outage"), "password": password, "account_invite_token": "invite-token"}),
		"POST /register/abandon":                  post("/register/abandon", map[string]string{"identifier": a.email, "password": password}),
		"POST /passwordless/start":                post("/passwordless/start", map[string]string{"identifier": a.email, "account_invite_token": "invite-token"}),
		"POST /passwordless/confirm":              post("/passwordless/confirm", code),
		"POST /verify/request":                    post("/verify/request", map[string]string{"identifier": unique("outagenew") + "@security.test", "password": password}),
		"POST /verify/confirm":                    post("/verify/confirm", code),
		"POST /password/reset/confirm":            post("/password/reset/confirm", map[string]string{"token": "reset-token", "new_password": "Outage-new-passphrase-1"}),
		"POST /token":                             post("/token", map[string]string{"grant_type": "refresh_token", "refresh_token": "refresh-token"}),
		"POST /2fa/challenge":                     post("/2fa/challenge", map[string]string{"user_id": a.id, "challenge": "challenge", "factor_id": "factor"}),
		"POST /2fa/verify":                        post("/2fa/verify", map[string]string{"user_id": a.id, "challenge": "challenge", "code": "123456"}),
		"POST /step-up/password":                  post("/step-up/password", map[string]string{"password": password}),
		"POST /step-up/2fa":                       post("/step-up/2fa", map[string]string{"code": "123456"}),
		"POST /user/password":                     post("/user/password", map[string]string{"current_password": password, "new_password": "Outage-new-passphrase-1"}),
		"POST /user/2fa":                          post("/user/2fa", map[string]string{"method": "email", "code": "123456"}),
		"DELETE /user":                            {method: http.MethodDelete, path: "/user", body: map[string]string{"password": password}, token: token},
		"DELETE /user/providers/{provider}":       {method: http.MethodDelete, path: "/user/providers/stub", body: map[string]string{"password": password}, token: token},
		"POST /passkeys/login/finish":             post("/passkeys/login/finish", map[string]string{"id": "credential"}),
		"POST /device-keys/enroll/finish":         post("/device-keys/enroll/finish", map[string]string{"enrollment_id": "enrollment", "code": "123456", "signature": "signature"}),
		"POST /device-keys/login/finish":          post("/device-keys/login/finish", map[string]string{"challenge_id": "challenge", "signature": "signature"}),
		"POST /solana/login":                      post("/solana/login", map[string]string{"message": "message", "signature": "signature"}),
		"POST /solana/link":                       post("/solana/link", map[string]string{"message": "message", "signature": "signature"}),
		"POST /invites/redeem":                    post("/invites/redeem", map[string]string{"code": "invite-code"}),
		"GET //oidc/{provider}/callback":          {method: http.MethodGet, path: "//oidc/stub/callback?state=state&code=code"},
		"POST //oidc/{provider}/callback":         {method: http.MethodPost, path: "//oidc/stub/callback?state=state&code=code"},
		"GET //oidc/{provider}/step-up/callback":  {method: http.MethodGet, path: "//oidc/stub/step-up/callback?state=state&code=code"},
		"POST //oidc/{provider}/step-up/callback": {method: http.MethodPost, path: "//oidc/stub/step-up/callback?state=state&code=code"},
	}
	// Routes that check no secret. Routes gated on a permission act on the
	// caller's live authority and are not listed.
	noSecret := []string{
		"GET //.well-known/jwks.json", "GET /capabilities", "DELETE /logout", "GET /me", "GET /me/groups", "GET /me/permissions",
		"GET /register/availability", "POST /password/reset/request",
		"GET /user/sessions", "DELETE /user/sessions", "DELETE /user/sessions/{id}",
		"PATCH /user/username", "PATCH /user/preferred-language",
		"GET /user/2fa", "DELETE /user/2fa", "POST /user/2fa/backup-codes",
		"POST /passkeys/login/begin", "POST /passkeys/register/begin", "POST /passkeys/register/finish",
		"GET /passkeys", "PATCH /passkeys/{id}", "DELETE /passkeys/{id}",
		"POST /device-keys/enroll/begin", "POST /device-keys/login/begin", "GET /device-keys",
		"DELETE /device-keys/{id}", "POST /device-keys/revoke-others",
		"POST /solana/challenge",
		"GET //oidc/{provider}/login", "POST //oidc/{provider}/login",
		"POST /oidc/{provider}/link/start", "POST /oidc/{provider}/step-up/start",
		"POST /admin/users/{user_id}/ban", "POST /admin/users/{user_id}/unban", "POST /admin/users/{user_id}/sessions/revoke",
		"DELETE /admin/users/{user_id}", "POST /admin/users/{user_id}/restore",
		"PUT /admin/users/{user_id}/roles/{role}", "DELETE /admin/users/{user_id}/roles/{role}",
	}
	full := func(pattern string) string {
		method, path, _ := strings.Cut(pattern, " ")
		if strings.HasPrefix(path, "//") {
			return method + " " + path[1:]
		}
		return method + " " + apiPrefix + path
	}

	t.Run("every mounted route is classified", func(t *testing.T) {
		mounted, classified := map[string]bool{}, map[string]bool{}
		for pattern := range secretChecks {
			classified[full(pattern)] = true
		}
		for _, pattern := range noSecret {
			classified[full(pattern)] = true
		}
		for _, r := range down.auth.Routes() {
			pattern := r.Method + " " + r.Path
			mounted[pattern] = true
			if r.Method == http.MethodHead || r.Auth == iam.AuthPermission {
				continue
			}
			require.True(t, classified[pattern], "%s is unclassified: add it to this test's secret checks or its noSecret list", pattern)
		}
		for pattern := range classified {
			require.True(t, mounted[pattern], "%s is not mounted", pattern)
		}
	})

	for pattern, req := range secretChecks {
		t.Run(pattern, func(t *testing.T) {
			resp := down.do(req)
			require.Equal(t, http.StatusTooManyRequests, resp.status, "a secret check ran with the limiter down: %s", resp)
			require.Equal(t, "rate_limited", resp.errorCode())
		})
	}

	t.Run("routes that check no secret stay up", func(t *testing.T) {
		require.Equal(t, http.StatusOK, down.get("/capabilities", "").status)
		me := down.get("/me", token)
		require.Equal(t, http.StatusOK, me.status, me.String())
		reset := down.post("/password/reset/request", map[string]string{"identifier": a.email}, "")
		require.Less(t, reset.status, 300, reset.String())
	})
}
