package securitytest

import (
	"context"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/testidp"
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
	return h.replica(withHTTP(func(c *authkit.HTTPConfig) { c.Redis = rdb }))
}

// TestSecurityLimiterOutageFailsClosed: when the rate limiter's backend fails,
// every route that checks or issues a secret (a password, one-time or backup
// code, a link, refresh, invite or OIDC state token, an API key, or a
// signature over a challenge) or sends an email or SMS is refused, so an
// outage never lifts a guessing or sending budget. Reads and changes that do
// none of that stay up. Every mounted route is classified here, so a new one
// cannot ship unproven.
func TestSecurityLimiterOutageFailsClosed(t *testing.T) {
	h := newHost(t, withHTTP(generousLimits), authtest.WithConfig(withRBAC), authtest.WithConfig(withDeviceKeys), authtest.WithConfig(withPasskeys),
		withProviders(testidp.New(t).OAuth2("idp")), authtest.WithConfig(func(c *authkit.Config) {
			c.Registration.PasswordlessLogin = true
			c.SolanaNetwork = "devnet"
			c.Delegated = authkit.DelegatedConfig{Audiences: []string{audience}}
		}), authtest.WithDeps(func(d *authkit.Deps) {
			d.DelegatedAuthorization = func(context.Context, iam.DelegationRequest) (iam.DelegationGrant, error) {
				return iam.DelegationGrant{}, nil
			}
		}))
	down := h.limiterDown()
	a := h.newAccount("outage")
	_, base := h.newOrg(a)
	// Past the fresh-auth window, the account routes ask for the password.
	token := authtest.StaleSession(t, h.auth, h.login(a).AccessToken)

	post := func(path string, body any) request {
		return request{method: http.MethodPost, path: path, body: body, token: token}
	}
	del := func(path string, body any) request {
		return request{method: http.MethodDelete, path: path, body: body, token: token}
	}
	callback := func(method, path string) request {
		return request{method: method, path: "//oidc/idp" + path + "?state=state&code=code"}
	}
	code := map[string]string{"identifier": a.email, "code": "123456"}
	newEmail := func() string { return unique("outagenew") + "@security.test" }
	refused := []struct {
		pattern, what string
		req           request
	}{
		{"POST /password/login", "checks a password", post("/password/login", map[string]string{"identifier": a.email, "password": password})},
		{"POST /account/recovery/confirm", "checks a token", post("/account/recovery/confirm", map[string]string{"token": "recovery-token"})},
		{"POST /register", "sends a code", post("/register", map[string]string{"identifier": newEmail(), "username": unique("outage"), "password": password})},
		{"POST /register", "checks an invitation", post("/register", map[string]string{"identifier": newEmail(), "username": unique("outage"), "password": password, "account_invite_token": "invite-token"})},
		{"POST /register/abandon", "checks a password", post("/register/abandon", map[string]string{"identifier": a.email, "password": password})},
		{"POST /passwordless/start", "sends a code", post("/passwordless/start", map[string]string{"identifier": a.email})},
		{"POST /passwordless/confirm", "checks a code", post("/passwordless/confirm", code)},
		{"POST /verify/request", "sends a code", post("/verify/request", map[string]string{"identifier": a.email})},
		{"POST /verify/request", "checks a password", post("/verify/request", map[string]string{"identifier": newEmail(), "password": password})},
		{"POST /verify/confirm", "checks a code", post("/verify/confirm", code)},
		{"POST /password/reset/request", "sends a link", post("/password/reset/request", map[string]string{"identifier": a.email})},
		{"POST /password/reset/confirm", "checks a token", post("/password/reset/confirm", map[string]string{"token": "reset-token", "new_password": "Outage-new-passphrase-1"})},
		{"POST /token", "checks a refresh token", post("/token", map[string]string{"grant_type": "refresh_token", "refresh_token": "refresh-token"})},
		{"POST /2fa/challenge", "checks a challenge and sends a code", post("/2fa/challenge", map[string]string{"user_id": a.id, "challenge": "challenge", "factor_id": "factor"})},
		{"POST /2fa/verify", "checks a code", post("/2fa/verify", map[string]string{"user_id": a.id, "challenge": "challenge", "code": "123456"})},
		{"POST /step-up/password", "checks a password", post("/step-up/password", map[string]string{"password": password})},
		{"POST /step-up/2fa", "checks a code", post("/step-up/2fa", map[string]string{"code": "123456"})},
		{"POST /user/password", "checks a password", post("/user/password", map[string]string{"current_password": password, "new_password": "Outage-new-passphrase-1"})},
		{"POST /user/2fa", "checks a code", post("/user/2fa", map[string]string{"method": "email", "code": "123456"})},
		{"POST /user/2fa", "sends an email code", post("/user/2fa", map[string]string{"method": "email"})},
		{"POST /user/2fa", "sends an SMS code", post("/user/2fa", map[string]string{"method": "sms", "phone": "+14155550143"})},
		{"POST /user/2fa", "issues a TOTP secret", post("/user/2fa", map[string]string{"method": "totp"})},
		{"POST /user/2fa/backup-codes", "issues backup codes", post("/user/2fa/backup-codes", nil)},
		{"DELETE /user", "checks a password", del("/user", map[string]string{"password": password})},
		{"DELETE /user/providers/{provider}", "checks a password", del("/user/providers/idp", map[string]string{"password": password})},
		{"POST /passkeys/login/finish", "checks a signature", post("/passkeys/login/finish", map[string]string{"id": "credential"})},
		{"POST /device-keys/enroll/begin", "sends a code", post("/device-keys/enroll/begin", map[string]string{"email": a.email, "public_key": newDeviceKey(t).public})},
		{"POST /device-keys/enroll/finish", "checks a code and a signature", post("/device-keys/enroll/finish", map[string]string{"enrollment_id": "enrollment", "code": "123456", "signature": "signature"})},
		{"POST /device-keys/login/finish", "checks a signature", post("/device-keys/login/finish", map[string]string{"challenge_id": "challenge", "signature": "signature"})},
		{"POST /solana/login", "checks a signature", post("/solana/login", map[string]string{"message": "message", "signature": "signature"})},
		{"POST /solana/link", "checks a signature", post("/solana/link", map[string]string{"message": "message", "signature": "signature"})},
		{"POST /invites/redeem", "checks an invite code", post("/invites/redeem", map[string]string{"code": "invite-code"})},
		{"POST /groups/{group_id}/members", "sends an invitation", post(base+"/members", map[string]string{"email": newEmail(), "role": "member"})},
		{"POST /groups/{group_id}/invites/links", "issues an invite code", post(base+"/invites/links", map[string]string{"role": "member"})},
		{"POST /groups/{group_id}/api-keys", "issues an API key", post(base+"/api-keys", map[string]string{"name": "ci", "role": "member"})},
		{"POST /delegated/token", "issues a token", post("/delegated/token", map[string]any{})},
		{"GET //oidc/{provider}/login", "issues a state", request{method: http.MethodGet, path: "//oidc/idp/login"}},
		{"POST //oidc/{provider}/login", "issues a state", request{method: http.MethodPost, path: "//oidc/idp/login", body: map[string]any{}}},
		{"POST /oidc/{provider}/link/start", "issues a state", post("/oidc/idp/link/start", map[string]any{})},
		{"POST /oidc/{provider}/step-up/start", "issues a state", post("/oidc/idp/step-up/start", map[string]any{})},
		{"GET //oidc/{provider}/callback", "checks a state and a code", callback(http.MethodGet, "/callback")},
		{"POST //oidc/{provider}/callback", "checks a state and a code", callback(http.MethodPost, "/callback")},
		{"GET //oidc/{provider}/step-up/callback", "checks a state and a code", callback(http.MethodGet, "/step-up/callback")},
		{"POST //oidc/{provider}/step-up/callback", "checks a state and a code", callback(http.MethodPost, "/step-up/callback")},
	}
	// Reads, and changes that check, issue and send nothing. A challenge the
	// caller must sign is not a secret.
	staysUp := []string{
		"GET //.well-known/jwks.json", "GET /capabilities", "DELETE /logout", "GET /me", "GET /me/groups", "GET /me/permissions",
		"GET /register/availability",
		"GET /user/sessions", "DELETE /user/sessions", "DELETE /user/sessions/{id}",
		"PATCH /user/username", "PATCH /user/preferred-language",
		"GET /user/2fa", "DELETE /user/2fa",
		"POST /passkeys/login/begin", "POST /passkeys/register/begin", "POST /passkeys/register/finish",
		"GET /passkeys", "PATCH /passkeys/{id}", "DELETE /passkeys/{id}",
		"POST /device-keys/login/begin", "GET /device-keys", "DELETE /device-keys/{id}", "POST /device-keys/revoke-others",
		"POST /solana/challenge",
		"GET /admin/users", "GET /admin/users/{user_id}", "GET /admin/users/{user_id}/signins", "GET /admin/roles",
		"POST /admin/users/{user_id}/ban", "POST /admin/users/{user_id}/unban", "POST /admin/users/{user_id}/sessions/revoke",
		"DELETE /admin/users/{user_id}", "POST /admin/users/{user_id}/restore",
		"PUT /admin/users/{user_id}/roles/{role}", "DELETE /admin/users/{user_id}/roles/{role}",
		"GET /groups/{group_id}/members", "DELETE /groups/{group_id}/members/{user}", "PUT /groups/{group_id}/members/{user}/roles/{role}",
		"GET /groups/{group_id}/roles", "GET /groups/{group_id}/api-keys", "DELETE /groups/{group_id}/api-keys/{key}",
		"GET /groups/{group_id}/invites/links", "DELETE /groups/{group_id}/invites/links/{link}",
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
		for _, c := range refused {
			classified[full(c.pattern)] = true
		}
		for _, pattern := range staysUp {
			classified[full(pattern)] = true
		}
		for _, r := range down.auth.Routes() {
			pattern := r.Method + " " + r.Path
			mounted[pattern] = true
			if r.Method != http.MethodHead {
				require.True(t, classified[pattern], "%s is unclassified: add it to this test's refused or staysUp list", pattern)
			}
		}
		for pattern := range classified {
			require.True(t, mounted[pattern], "%s is not mounted", pattern)
		}
	})

	for _, c := range refused {
		t.Run(c.pattern+" "+c.what, func(t *testing.T) {
			resp := down.do(c.req)
			require.Equal(t, http.StatusTooManyRequests, resp.status, "it ran with the limiter down: %s", resp)
			require.Equal(t, "rate_limited", resp.errorCode())
		})
	}

	t.Run("reads and plain changes stay up", func(t *testing.T) {
		require.Equal(t, http.StatusOK, down.get("/capabilities", "").status)
		for _, path := range []string{"/me", "/user/sessions", base + "/members"} {
			resp := down.get(path, token)
			require.Equal(t, http.StatusOK, resp.status, "%s: %s", path, resp)
		}
		resp := down.do(request{method: http.MethodPatch, path: "/user/preferred-language", body: map[string]string{"preferred_language": "en"}, token: token})
		require.Less(t, resp.status, 300, resp.String())
	})
}

// TestSecurityUnknownClientAddressIsLimited: a request whose client address
// cannot be determined is never exempt from the per-address budget. Every such
// request shares one budget, and AuthKit warns once that what sits in front of
// it is misdeclared.
func TestSecurityUnknownClientAddressIsLimited(t *testing.T) {
	logs := captureLogs(t)
	h := newHost(t, withHTTP(func(c *authkit.HTTPConfig) {
		c.DirectPeerIP = false
		c.ClientIP = func(*http.Request) string { return "" }
		c.RateLimits = map[string]authkit.RateLimit{"auth_password_login": {Limit: 3, Window: time.Hour}}
	}))
	a := h.newAccount("noaddress")
	for range 3 {
		resp := h.post("/password/login", map[string]string{"identifier": a.email, "password": "wrong-" + password}, "")
		require.Equal(t, http.StatusUnauthorized, resp.status, resp.String())
	}
	resp := h.post("/password/login", map[string]string{"identifier": a.email, "password": password}, "")
	require.Equal(t, http.StatusTooManyRequests, resp.status, "requests without an address went unlimited: %s", resp)
	require.Equal(t, 1, strings.Count(logs.String(), "a request has no client address"), logs.String())
}
