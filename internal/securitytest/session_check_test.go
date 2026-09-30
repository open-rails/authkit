package securitytest

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gofiber/fiber/v3"
	"github.com/open-rails/authkit"
	authkitfiber "github.com/open-rails/authkit/adapters/fiber"
	authkitgin "github.com/open-rails/authkit/adapters/gin"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/ident"
	"github.com/open-rails/authkit/internal/testidp"
	"github.com/open-rails/authkit/provider"
	"github.com/open-rails/authkit/verify"
	"github.com/stretchr/testify/require"
)

// withEveryRoute mounts every optional route: a provider, passkeys, device
// keys, Solana and the delegated-token mint.
func withEveryRoute(t *testing.T) []authtest.Option {
	idp := testidp.New(t)
	return []authtest.Option{authtest.WithConfig(func(c *authkit.Config) {
		withPasskeys(c)
		withDeviceKeys(c)
		c.SolanaNetwork = "devnet"
		c.Delegated = authkit.DelegatedConfig{Audiences: []string{"resource.security.test"}}
	}), authtest.WithDeps(func(d *authkit.Deps) {
		d.Providers = []provider.Provider{idp.OAuth2("idp")}
		d.DelegatedAuthorization = func(context.Context, iam.DelegationRequest) (iam.DelegationGrant, error) {
			return iam.DelegationGrant{Permissions: []string{"resource:read"}}, nil
		}
	})}
}

func mutating(route iam.Route) bool {
	return route.Method != http.MethodGet && route.Method != http.MethodHead
}

// TestSecurityMutatingRoutesCheckTheSession (#412): the session check is a
// route's declared tier, not a call each handler must remember. Every route
// that changes state for a signed-in caller declares AuthSession, or
// AuthPermission, whose check runs through the actor's session binding. Only
// logout, which ends the caller's own sign-in, stays AuthRequired: it must
// also work, idempotently, with an already revoked one.
func TestSecurityMutatingRoutesCheckTheSession(t *testing.T) {
	h := newHost(t, append(withEveryRoute(t), withHTTP(generousLimits), authtest.WithConfig(withRBAC))...)
	signOut := map[string]bool{
		"DELETE " + apiPrefix + "/logout": true,
	}
	declared := map[string]iam.RouteAuthTier{}
	for _, route := range h.auth.Routes() {
		key := route.Method + " " + route.Path
		declared[key] = route.Auth
		if mutating(route) && route.Auth == iam.AuthRequired {
			require.True(t, signOut[key], "%s changes state without the session check: declare iam.AuthSession", key)
		}
	}
	for key := range signOut {
		require.Equal(t, iam.AuthRequired, declared[key], key)
	}
	for _, key := range []string{
		"PUT /me/password", "DELETE /me/sessions", "DELETE /me/sessions/{id}", "PATCH /me", "DELETE /me",
		"PUT /me/email", "PUT /me/phone", "DELETE /me/phone", "DELETE /me/providers/{provider}",
		"PATCH /me/sign-in-keys/{id}", "DELETE /me/sign-in-keys/{id}", "POST /me/passkeys/register/begin",
		"POST /me/passkeys/register/finish", "POST /me/step-up/password", "POST /me/step-up/2fa", "POST /me/step-up/2fa/send",
		"POST /me/2fa/setup", "POST /me/2fa/factors", "PATCH /me/2fa/factors/{id}", "DELETE /me/2fa/factors/{id}",
		"DELETE /me/2fa", "POST /me/2fa/backup-codes", "PUT /me/solana-wallet",
		"DELETE /device-keys", "POST /delegated/token",
		"POST /invitations/redeem", "PATCH /admin/users/{user_id}", "PUT /admin/users/{user_id}/ban", "DELETE /admin/users/{user_id}/ban",
		"DELETE /admin/users/{user_id}/sessions",
	} {
		method, path, _ := strings.Cut(key, " ")
		require.Equal(t, iam.AuthSession, declared[method+" "+apiPrefix+path], key)
	}
}

// gateCall calls one host gate with a bearer token.
type gateCall func(t *testing.T, token string) response

func serveHTTP(handler http.Handler, method string) gateCall {
	return func(t *testing.T, token string) response {
		r := httptest.NewRequest(method, "https://host.security.test/resource", nil)
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return response{status: w.Code, body: w.Body.Bytes()}
	}
}

func serveFiber(app *fiber.App, method string) gateCall {
	return func(t *testing.T, token string) response {
		r := httptest.NewRequest(method, "https://host.security.test/resource", nil)
		r.Header.Set("Authorization", "Bearer "+token)
		resp, err := app.Test(r, fiber.TestConfig{Timeout: 30 * time.Second})
		require.NoError(t, err)
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		return response{status: resp.StatusCode, body: body}
	}
}

// TestSecurityRevokedSessionAtLiveGates (#412): the live check is the
// session. Logout, revoke-all, a password change, a ban and deletion each
// revoke it, and from then on its still-unexpired access token is refused by
// every live gate: every mutating account, admin and group route, host
// RequireSession, RequirePermission and Sensitive over net/http, Gin and
// Fiber, and Client operations taking the actor it names. Plain Required stays stateless and
// admits the token until it expires, and API keys are untouched.
func TestSecurityRevokedSessionAtLiveGates(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h := newHost(t, append(withEveryRoute(t), withHTTP(generousLimits), authtest.WithConfig(withRBAC))...)
	ctx := context.Background()
	founder := h.newAccount("scfounder")
	group, base := h.newOrg(founder)
	other := h.newAccount("scother")
	perm := ident.Perm("org:catalog:read")
	member := roleIn(t, h.auth, group, "member")

	noContent := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	ginNoContent := func(c *gin.Context) { c.Status(http.StatusNoContent) }
	fiberNoContent := func(c fiber.Ctx) error { return c.SendStatus(http.StatusNoContent) }
	ginSession, ginPermission, ginSensitive := gin.New(), gin.New(), gin.New()
	ginSession.GET("/resource", authkitgin.RequireSession(h.auth), ginNoContent)
	ginPermission.GET("/resource", authkitgin.RequirePermissionOn(h.auth, group, perm), ginNoContent)
	ginSensitive.POST("/resource", authkitgin.Sensitive(h.auth), ginNoContent)
	fiberSession, fiberPermission, fiberSensitive := fiber.New(), fiber.New(), fiber.New()
	fiberSession.Get("/resource", authkitfiber.RequireSession(h.auth), fiberNoContent)
	fiberPermission.Get("/resource", authkitfiber.RequirePermissionOn(h.auth, group, perm), fiberNoContent)
	fiberSensitive.Post("/resource", authkitfiber.Sensitive(h.auth), fiberNoContent)
	sessionGates := map[string]gateCall{
		"net/http RequireSession": serveHTTP(verify.RequireSession(h.auth)(noContent), http.MethodGet),
		"gin RequireSession":      serveHTTP(ginSession, http.MethodGet),
		"fiber RequireSession":    serveFiber(fiberSession, http.MethodGet),
	}
	permissionGates := map[string]gateCall{
		"net/http RequirePermission": serveHTTP(verify.RequirePermissionOn(h.auth, group, perm)(noContent), http.MethodGet),
		"gin RequirePermission":      serveHTTP(ginPermission, http.MethodGet),
		"fiber RequirePermission":    serveFiber(fiberPermission, http.MethodGet),
	}
	sensitiveGates := map[string]gateCall{
		"net/http Sensitive": serveHTTP(verify.Sensitive(h.auth)(noContent), http.MethodPost),
		"gin Sensitive":      serveHTTP(ginSensitive, http.MethodPost),
		"fiber Sensitive":    serveFiber(fiberSensitive, http.MethodPost),
	}
	required := serveHTTP(verify.Required(h.auth)(noContent), http.MethodGet)

	// Every mutating route of the session and permission tiers, its path
	// parameters filled in; the gate refuses before any of them is read.
	var routes []request
	for _, route := range h.auth.Routes() {
		if !mutating(route) || route.Auth != iam.AuthSession && route.Auth != iam.AuthPermission {
			continue
		}
		path := strings.ReplaceAll(route.Path, "{group_id}", group.ID())
		path = strings.ReplaceAll(path, "{provider}", "idp")
		for strings.Contains(path, "{") {
			open, end := strings.Index(path, "{"), strings.Index(path, "}")
			path = path[:open] + "0190a0a0-0000-7000-8000-000000000000" + path[end+1:]
		}
		routes = append(routes, request{method: route.Method, path: "/" + path, body: map[string]any{}})
	}
	require.NotEmpty(t, routes)

	actorOf := func(t *testing.T, token string) iam.Actor {
		t.Helper()
		cl, err := h.auth.Verify(ctx, token)
		require.NoError(t, err)
		actor, ok := verify.ActorFromClaims(cl)
		require.True(t, ok)
		_, bound := actor.Session()
		require.True(t, bound, "an actor from a token is bound to its session")
		return actor
	}
	refused := func(t *testing.T, name string, resp response) {
		t.Helper()
		require.Equal(t, http.StatusUnauthorized, resp.status, "%s: %s", name, resp)
		require.Equal(t, "session_revoked", resp.errorCode(), name)
	}
	// requireRevoked asserts every live gate refuses token and plain Required
	// still admits it.
	requireRevoked := func(t *testing.T, token string) {
		t.Helper()
		for name, call := range sessionGates {
			refused(t, name, call(t, token))
		}
		for name, call := range permissionGates {
			refused(t, name, call(t, token))
		}
		for name, call := range sensitiveGates {
			refused(t, name, call(t, token))
		}
		actor := actorOf(t, token)
		_, err := h.auth.Can(ctx, actor, group, perm)
		require.ErrorIs(t, err, iam.ErrSessionRevoked, "Client.Can")
		err = setRole(h.auth, ctx, actor, group, iam.UserSubject(other.id), member)
		require.ErrorIs(t, err, iam.ErrSessionRevoked, "an actor-authorized Client mutation")
		for _, req := range routes {
			req.token = token
			refused(t, req.method+" "+req.path, h.do(req))
		}
		require.Equal(t, http.StatusNoContent, required(t, token).status, "plain Required is stateless until exp")
	}
	// requireLive asserts a live, fresh session passes the same gates.
	requireLive := func(t *testing.T, token string) {
		t.Helper()
		for name, call := range sessionGates {
			resp := call(t, token)
			require.Equal(t, http.StatusNoContent, resp.status, "%s: %s", name, resp)
		}
		for name, call := range permissionGates {
			resp := call(t, token)
			require.Equal(t, http.StatusNoContent, resp.status, "%s: %s", name, resp)
		}
		for name, call := range sensitiveGates {
			resp := call(t, token)
			require.Equal(t, http.StatusNoContent, resp.status, "%s: %s", name, resp)
		}
		allowed, err := h.auth.Can(ctx, actorOf(t, token), group, perm)
		require.NoError(t, err)
		require.True(t, allowed)
	}
	// manager signs up an account holding catalog read and member management
	// in the org (not its owner, so a ban or deletion is not refused), with an
	// API key of its own.
	manager := func(t *testing.T) (account, issued) {
		t.Helper()
		a := h.newAccount("scmanager")
		h.grant(group, a, "manager")
		key := h.issue(base+"/api-keys", h.login(a).AccessToken, map[string]any{"name": "ci", "role": "org:member"})
		return a, key
	}

	for _, tc := range []struct {
		name string
		// revoke ends stolen's session; keepsKeys is whether the account's
		// API keys outlive it (a ban or deletion sweeps them).
		revoke    func(t *testing.T, a account, stolen tokens)
		keepsKeys bool
	}{
		{"logout", func(t *testing.T, _ account, stolen tokens) {
			require.Equal(t, http.StatusNoContent, h.do(request{method: http.MethodDelete, path: "/logout", token: stolen.AccessToken}).status)
		}, true},
		{"revoke one session", func(t *testing.T, a account, stolen tokens) {
			_, claims := splitToken(t, stolen.AccessToken)
			sid, _ := claims["sid"].(string)
			require.NotEmpty(t, sid)
			resp := h.do(request{method: http.MethodDelete, path: "/me/sessions/" + sid, token: h.login(a).AccessToken})
			require.Equal(t, http.StatusNoContent, resp.status, resp.String())
		}, true},
		{"sign out every other session", func(t *testing.T, a account, _ tokens) {
			resp := h.do(request{method: http.MethodDelete, path: "/me/sessions", token: h.login(a).AccessToken})
			require.Equal(t, http.StatusNoContent, resp.status, resp.String())
		}, true},
		{"password change", func(t *testing.T, a account, _ tokens) {
			resp := h.do(request{method: http.MethodPut, path: "/me/password", body: map[string]string{"current_password": password, "new_password": "Another-long-passphrase-7"}, token: h.login(a).AccessToken})
			require.Less(t, resp.status, 300, resp.String())
		}, true},
		{"account-wide revocation", func(t *testing.T, a account, _ tokens) {
			_, err := h.auth.RevokeAccountSessions(ctx, iam.SystemActor(), a.id)
			require.NoError(t, err)
		}, true},
		{"ban", func(t *testing.T, a account, _ tokens) {
			require.NoError(t, h.auth.Ban(ctx, iam.SystemActor(), a.id, iam.Ban{}))
		}, false},
		{"deletion", func(t *testing.T, a account, _ tokens) {
			require.NoError(t, opErr(h.auth.DeleteUsers(ctx, iam.SystemActor(), []string{a.id})))
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, key := manager(t)
			stolen := h.login(a)
			requireLive(t, stolen.AccessToken)
			tc.revoke(t, a, stolen)
			requireRevoked(t, stolen.AccessToken)
			require.Equal(t, http.StatusUnauthorized, h.refresh(stolen.RefreshToken).status, "the session mints no more tokens")
			keyStatus := permissionGates["net/http RequirePermission"](t, key.Secret).status
			if tc.keepsKeys {
				require.Equal(t, http.StatusNoContent, keyStatus, "an API key is not a session")
			} else {
				require.Contains(t, []int{http.StatusUnauthorized, http.StatusForbidden}, keyStatus, "a banned or deleted creator's keys die with it")
			}
		})
	}

	t.Run("device key", func(t *testing.T) {
		for _, revoke := range []struct {
			name string
			run  func(t *testing.T, a account, token string)
		}{
			{"signed out", func(t *testing.T, _ account, token string) {
				_, claims := splitToken(t, token)
				require.NotEmpty(t, claims["device_key_id"])
				require.Equal(t, http.StatusNoContent, h.do(request{method: http.MethodDelete, path: "/logout", token: token}).status)
			}},
			{"revoked by its own token", func(t *testing.T, _ account, token string) {
				_, claims := splitToken(t, token)
				id, _ := claims["device_key_id"].(string)
				require.NotEmpty(t, id)
				require.Equal(t, http.StatusNoContent, h.do(request{method: http.MethodDelete, path: "/me/sign-in-keys/" + id, token: token}).status)
			}},
			{"revoked from a browser session", func(t *testing.T, a account, token string) {
				_, claims := splitToken(t, token)
				id, _ := claims["device_key_id"].(string)
				require.NotEmpty(t, id)
				require.Equal(t, http.StatusNoContent, h.do(request{method: http.MethodDelete, path: "/me/sign-in-keys/" + id, token: h.login(a).AccessToken}).status)
			}},
			{"password change", func(t *testing.T, a account, _ string) {
				resp := h.do(request{method: http.MethodPut, path: "/me/password", body: map[string]string{"current_password": password, "new_password": "Another-long-passphrase-7"}, token: h.login(a).AccessToken})
				require.Less(t, resp.status, 300, resp.String())
			}},
		} {
			t.Run(revoke.name, func(t *testing.T) {
				a, _ := manager(t)
				k := newDeviceKey(t)
				require.Equal(t, http.StatusOK, h.deviceEnroll(k, a.email, nil).status)
				login := h.deviceLogin(k)
				require.Equal(t, http.StatusOK, login.status, login.String())
				token := session(t, login).AccessToken
				requireLive(t, token)
				revoke.run(t, a, token)
				requireRevoked(t, token)
			})
		}
	})

	t.Run("a hand-built actor is checked at account level only", func(t *testing.T) {
		a, _ := manager(t)
		allowed, err := h.auth.Can(ctx, iam.UserActor(a.id), group, perm)
		require.NoError(t, err)
		require.True(t, allowed, "trusted server code acts without a session")
		require.NoError(t, h.auth.Ban(ctx, iam.SystemActor(), a.id, iam.Ban{}))
		allowed, err = h.auth.Can(ctx, iam.UserActor(a.id), group, perm)
		require.NoError(t, err)
		require.False(t, allowed, "a banned account has no authority")
	})
}

// allow is whether the actor verified claims act as holds perm in ref,
// checked live.
func allow(ctx context.Context, auth *authkit.Client, cl verify.Claims, perm iam.Perm, ref iam.GroupRef) (bool, error) {
	actor, ok := verify.ActorFromClaims(cl)
	if !ok {
		return false, nil
	}
	return auth.Can(ctx, actor, ref, perm)
}

// TestSecurityDelegatedTokenSessionCheck (#418): a delegated token minted
// from a sign-in carries that session (#412), so RequireSession and
// CheckSession admit it while the session stands and refuse it, 401
// session_revoked, once it is revoked, over net/http, Gin and Fiber. One
// minted without a session (by the host, or for an unbound actor) is always
// refused. It never reaches AuthKit's own account routes, and never passes
// Sensitive, which wants the user's own recent sign-in.
func TestSecurityDelegatedTokenSessionCheck(t *testing.T) {
	gin.SetMode(gin.TestMode)
	const resource = "resource.security.test"
	h := newHost(t, withHTTP(generousLimits), authtest.WithConfig(withRBAC))
	ctx := context.Background()
	verifier, err := h.auth.NewVerifier([]string{resource})
	require.NoError(t, err)
	noContent := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	ginSession, fiberSession := gin.New(), fiber.New()
	ginSession.GET("/resource", authkitgin.RequireSession(verifier), func(c *gin.Context) { c.Status(http.StatusNoContent) })
	fiberSession.Get("/resource", authkitfiber.RequireSession(verifier), func(c fiber.Ctx) error { return c.SendStatus(http.StatusNoContent) })
	gates := map[string]gateCall{
		"net/http RequireSession": serveHTTP(verify.RequireSession(verifier)(noContent), http.MethodGet),
		"gin RequireSession":      serveHTTP(ginSession, http.MethodGet),
		"fiber RequireSession":    serveFiber(fiberSession, http.MethodGet),
	}
	sensitive := serveHTTP(verify.Sensitive(verifier)(noContent), http.MethodPost)
	requireGates := func(t *testing.T, token string, status int, code string) {
		t.Helper()
		for name, call := range gates {
			resp := call(t, token)
			require.Equal(t, status, resp.status, "%s: %s", name, resp)
			if code != "" {
				require.Equal(t, code, resp.errorCode(), name)
			}
		}
		cl, err := verifier.Verify(ctx, token)
		require.NoError(t, err)
		if status == http.StatusNoContent {
			require.NoError(t, h.auth.CheckSession(ctx, cl))
		} else {
			require.ErrorIs(t, h.auth.CheckSession(ctx, cl), iam.ErrSessionRevoked)
		}
	}
	mint := func(t *testing.T, actor iam.Actor, d iam.DelegatedAccess) string {
		t.Helper()
		if len(d.Audiences) == 0 {
			d.Audiences = []string{resource}
		}
		token, err := h.auth.MintDelegatedAccessToken(ctx, actor, d)
		require.NoError(t, err)
		return token.Value
	}

	a := h.newAccount("delegsession")
	signIn := h.login(a)
	cl, err := h.auth.Verify(ctx, signIn.AccessToken)
	require.NoError(t, err)
	actor, ok := verify.ActorFromClaims(cl)
	require.True(t, ok)
	delegated := mint(t, actor, iam.DelegatedAccess{})
	_, claims := splitToken(t, delegated)
	require.Equal(t, cl.SessionID, claims["sid"], "the token carries its minting session")

	requireGates(t, delegated, http.StatusNoContent, "")
	resp := sensitive(t, delegated)
	require.Equal(t, http.StatusForbidden, resp.status, resp.String())
	require.Equal(t, "forbidden", resp.errorCode())

	// AuthKit's account routes are the user's own.
	own := mint(t, actor, iam.DelegatedAccess{Audiences: []string{audience}})
	resp = h.do(request{method: http.MethodPatch, path: "/me", body: map[string]string{"preferred_language": "fr"}, token: own})
	require.Equal(t, http.StatusForbidden, resp.status, resp.String())
	require.Equal(t, "forbidden", resp.errorCode())

	// No minting session, nothing to check: refused by design.
	requireGates(t, mint(t, iam.SystemActor(), iam.DelegatedAccess{Subject: a.id}), http.StatusUnauthorized, "session_revoked")
	requireGates(t, mint(t, iam.UserActor(a.id), iam.DelegatedAccess{}), http.StatusUnauthorized, "session_revoked")

	// The user's own token behaves as before; another session's logout
	// leaves this one standing.
	other := h.login(a)
	resp = serveHTTP(verify.RequireSession(h.auth)(noContent), http.MethodGet)(t, h.login(a).AccessToken)
	require.Equal(t, http.StatusNoContent, resp.status, resp.String())
	require.Equal(t, http.StatusNoContent, h.do(request{method: http.MethodDelete, path: "/logout", token: other.AccessToken}).status)
	requireGates(t, delegated, http.StatusNoContent, "")

	require.Equal(t, http.StatusNoContent, h.do(request{method: http.MethodDelete, path: "/logout", token: signIn.AccessToken}).status)
	requireGates(t, delegated, http.StatusUnauthorized, "session_revoked")
	dcl, err := verifier.Verify(ctx, delegated)
	require.NoError(t, err, "stateless verification admits it until it expires")
	_, err = allow(ctx, h.auth, dcl, ident.RootUsersRead, iam.RootGroup())
	require.ErrorIs(t, err, iam.ErrSessionRevoked, "its permission checks end with the session too")
}
