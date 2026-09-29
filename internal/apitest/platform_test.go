package apitest_test

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authprovider"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/open-rails/authkit/internal/testhttp"
)

type routeKey struct{ method, path string }

func routesOf(t *testing.T, auth *authkit.Client) map[routeKey]iam.Route {
	t.Helper()
	routes := map[routeKey]iam.Route{}
	for _, route := range auth.Routes() {
		key := routeKey{route.Method, route.Path}
		require.NotContains(t, routes, key, "duplicate method/path in the catalog")
		routes[key] = route
	}
	return routes
}

// The catalog a Client serves is the surface it mounts: each HTTPConfig
// variant is its own Client on the same accounts.
func TestMountCatalog(t *testing.T) {
	auth, _ := authtest.New(t, authtest.WithConfig(func(c *authkit.Config) { c.TwoFactor.Mode = iam.TwoFactorDisabled }))
	variant := func(fn func(*authkit.HTTPConfig)) (*authkit.Client, *api) {
		replica := authtest.Replica(t, auth, authtest.WithConfig(func(c *authkit.Config) { fn(&c.HTTP) }))
		return replica, newAPI(t, replica)
	}

	t.Run("default surface and authentication metadata", func(t *testing.T) {
		routes := routesOf(t, auth)
		require.Equal(t, iam.Route{Method: http.MethodPost, Path: "/api/v1/register", Group: iam.RouteRegistration, Auth: iam.AuthPublic},
			routes[routeKey{http.MethodPost, "/api/v1/register"}])
		require.Equal(t, iam.Route{Method: http.MethodGet, Path: "/api/v1/me", Group: iam.RouteAccount, Auth: iam.AuthRequired},
			routes[routeKey{http.MethodGet, "/api/v1/me"}])
		require.Equal(t, iam.Route{Method: http.MethodGet, Path: "/api/v1/admin/users/{user_id}", Group: iam.RouteAdmin,
			Auth: iam.AuthPermission, Permission: iam.PermRootUsersRead.String()}, routes[routeKey{http.MethodGet, "/api/v1/admin/users/{user_id}"}])
		require.Equal(t, iam.AuthOptional, routes[routeKey{http.MethodPost, "/api/v1/verify/request"}].Auth)
		for _, route := range auth.Routes() {
			if route.Method == http.MethodGet {
				head := route
				head.Method = http.MethodHead
				require.Equal(t, head, routes[routeKey{http.MethodHead, route.Path}], "a GET route advertises its implicit HEAD")
			}
		}
		a := newAPI(t, auth)
		for _, path := range []string{"/me", "/admin/users/some-user"} {
			res := a.get(path, "")
			require.Equal(t, http.StatusUnauthorized, res.status, res.String())
		}
	})

	t.Run("catalog callers cannot mutate the mount", func(t *testing.T) {
		expected := auth.Routes()
		require.NotEmpty(t, expected)
		changed := auth.Routes()
		changed[0] = iam.Route{Method: http.MethodDelete, Path: "/changed"}
		require.Equal(t, expected, auth.Routes())
		require.Equal(t, http.StatusOK, newAPI(t, auth).get("/"+iam.JWKSPath, "").status)
	})

	t.Run("JWKS is root anchored and supports HEAD", func(t *testing.T) {
		custom, a := variant(func(h *authkit.HTTPConfig) { h.APIPath = "/auth/custom" })
		routes := routesOf(t, custom)
		for _, method := range []string{http.MethodGet, http.MethodHead} {
			require.Equal(t, iam.Route{Method: method, Path: iam.JWKSPath, Group: iam.RouteAuth, Auth: iam.AuthPublic}, routes[routeKey{method, iam.JWKSPath}])
			require.Equal(t, http.StatusOK, a.do(request{method: method, path: "/" + iam.JWKSPath}).status)
		}
		require.Equal(t, http.StatusNotFound, a.get("//auth/custom"+iam.JWKSPath, "").status)
	})

	t.Run("custom prefix group selection and normalized exclusions", func(t *testing.T) {
		custom, a := variant(func(h *authkit.HTTPConfig) {
			h.APIPath = " /auth/custom/ "
			h.Groups = []iam.RouteGroup{iam.RouteRegistration}
			h.Exclude = []string{" get /auth/custom/register/availability ", "GET " + iam.JWKSPath}
		})
		require.ElementsMatch(t, []iam.Route{
			{Method: http.MethodPost, Path: "/auth/custom/register", Group: iam.RouteRegistration, Auth: iam.AuthPublic},
			{Method: http.MethodPost, Path: "/auth/custom/register/abandon", Group: iam.RouteRegistration, Auth: iam.AuthPublic},
		}, custom.Routes())
		for _, ref := range []routeKey{
			{http.MethodGet, "/auth/custom/register/availability"},
			{http.MethodHead, "/auth/custom/register/availability"},
			{http.MethodGet, iam.JWKSPath},
			{http.MethodHead, iam.JWKSPath},
			{http.MethodPost, "/auth/custom/password/login"},
			{http.MethodPost, "/api/v1/register"},
		} {
			res := a.do(request{method: ref.method, path: "/" + ref.path})
			require.Equal(t, http.StatusNotFound, res.status, "%s %s", ref.method, ref.path)
		}
	})

	t.Run("root API prefix", func(t *testing.T) {
		root, a := variant(func(h *authkit.HTTPConfig) {
			h.APIPath = "/"
			h.Groups = []iam.RouteGroup{iam.RouteAuth}
		})
		routes := routesOf(t, root)
		require.Contains(t, routes, routeKey{http.MethodPost, "/password/login"})
		require.NotContains(t, routes, routeKey{http.MethodPost, "/api/v1/password/login"})
		require.Equal(t, http.StatusOK, a.get("//capabilities", "").status)
	})

	t.Run("disabled capabilities are absent from catalog and handler", func(t *testing.T) {
		routes := routesOf(t, auth)
		a := newAPI(t, auth)
		for _, ref := range []routeKey{
			{http.MethodPost, "/api/v1/device-keys/login/begin"},
			{http.MethodPost, "/api/v1/passwordless/start"},
			{http.MethodPost, "/api/v1/2fa/challenge"},
			{http.MethodGet, "/api/v1/user/2fa"},
			{http.MethodPost, "/api/v1/solana/challenge"},
			{http.MethodPost, "/api/v1/delegated/token"},
			{http.MethodGet, "/oidc/example/login"},
		} {
			require.NotContains(t, routes, ref)
			res := a.do(request{method: ref.method, path: "/" + ref.path})
			require.Equal(t, http.StatusNotFound, res.status, "%s %s: %s", ref.method, ref.path, res)
		}
	})

	t.Run("mount retains JSON and cookie behavior", func(t *testing.T) {
		_, a := variant(func(h *authkit.HTTPConfig) {
			h.APIPath = "/auth"
			h.RefreshCookie = true
		})
		u := authtest.NewUser(t, auth)
		credentials := `{"identifier":"` + u.Email + `","password":"` + u.Password + `"}`
		badJSON := a.do(request{method: http.MethodPost, path: "/password/login", body: credentials, header: http.Header{"Content-Type": {"text/plain"}}})
		require.Equal(t, http.StatusBadRequest, badJSON.status, badJSON.String())
		login := a.post("/password/login", "", credentials)
		require.Equal(t, http.StatusOK, login.status, login.String())
		var tokens map[string]any
		login.decode(t, &tokens)
		require.NotEmpty(t, tokens["access_token"])
		require.NotContains(t, tokens, "refresh_token")
		require.Len(t, login.cookies, 1)
		require.Equal(t, iam.RefreshCookieName, login.cookies[0].Name)
		require.Equal(t, "/", login.cookies[0].Path)
		require.True(t, login.cookies[0].HttpOnly)
		require.Equal(t, http.SameSiteLaxMode, login.cookies[0].SameSite)
	})

	t.Run("custom prefix retains MFA enrollment exemptions", func(t *testing.T) {
		mfa := authtest.Replica(t, auth, authtest.WithConfig(func(c *authkit.Config) {
			c.TwoFactor.Mode = iam.TwoFactorRequired
			c.HTTP.APIPath = "/custom/auth"
		}))
		a := newAPI(t, mfa)
		u := authtest.NewUser(t, mfa)
		login := a.post("/password/login", "", map[string]string{"identifier": u.Email, "password": u.Password})
		require.Equal(t, http.StatusForbidden, login.status, login.String())
		require.Equal(t, "2fa_enrollment_required", login.code())
		var continuation struct {
			Error struct {
				Metadata struct {
					TokenSet iam.TokenSet `json:"token_set"`
				} `json:"metadata"`
			} `json:"error"`
		}
		login.decode(t, &continuation)
		token := continuation.Error.Metadata.TokenSet.AccessToken
		require.NotEmpty(t, token)
		for path, status := range map[string]int{"//custom/auth/me": http.StatusForbidden, "//custom/auth/user/2fa": http.StatusOK} {
			res := a.get(path, token)
			require.Equal(t, status, res.status, "%s: %s", path, res)
		}
	})
}

// Browser OIDC stays at the root under a custom API prefix, and Groups and
// Exclude remove it.
func TestMountCatalogOIDC(t *testing.T) {
	const idp = "https://idp.example"
	provider := authprovider.OAuth2("catalog", idp, authprovider.Endpoint{AuthorizeURL: idp + "/authorize", TokenURL: idp + "/token"},
		"client", "secret", func(context.Context, *http.Client) (authprovider.Identity, error) {
			return authprovider.Identity{}, errors.New("the catalog test never completes a sign-in")
		})
	auth, _ := authtest.New(t, authtest.WithConfig(func(c *authkit.Config) {
		c.TwoFactor.Mode = iam.TwoFactorDisabled
		c.Identity.Providers = []authprovider.Provider{provider}
		c.HTTP.APIPath = "/auth/custom"
	}))
	routes := routesOf(t, auth)
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		require.Equal(t, iam.Route{Method: method, Path: "/oidc/{provider}/login", Group: iam.RouteBrowserOIDC, Auth: iam.AuthPublic},
			routes[routeKey{method, "/oidc/{provider}/login"}])
	}
	for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodPost} {
		require.Contains(t, routes, routeKey{method, "/oidc/{provider}/callback"})
	}
	login := newAPI(t, auth).get("//oidc/catalog/login", "")
	require.Equal(t, http.StatusFound, login.status, login.String())
	require.Contains(t, login.header.Get("Location"), idp+"/")

	for _, fn := range []func(*authkit.HTTPConfig){
		func(h *authkit.HTTPConfig) { h.Groups = []iam.RouteGroup{iam.RouteRegistration} },
		func(h *authkit.HTTPConfig) {
			h.Exclude = []string{"GET /oidc/{provider}/login", "POST /oidc/{provider}/login"}
		},
	} {
		filtered := authtest.Replica(t, auth, authtest.WithConfig(func(c *authkit.Config) {
			c.HTTP.APIPath = ""
			fn(&c.HTTP)
		}))
		filteredRoutes := routesOf(t, filtered)
		for _, method := range []string{http.MethodGet, http.MethodHead} {
			require.NotContains(t, filteredRoutes, routeKey{method, "/oidc/{provider}/login"})
			require.Equal(t, http.StatusNotFound, newAPI(t, filtered).do(request{method: method, path: "//oidc/catalog/login"}).status)
		}
	}
}

// New builds the HTTP surface a Config describes, or refuses it whole.
func TestHTTPConfigValidation(t *testing.T) {
	cfg, deps := bareConfig(t)
	for name, h := range map[string]authkit.HTTPConfig{
		"memory limiter by default": {DirectPeerIP: true},
		"a host limiter":            {DirectPeerIP: true, Limiter: testhttp.Unlimited{}},
	} {
		cfg.HTTP = h
		_, err := newClient(t, cfg, deps)
		require.NoError(t, err, name)
	}
	for _, tc := range []struct {
		http authkit.HTTPConfig
		err  string
	}{
		{authkit.HTTPConfig{DirectPeerIP: true, APIPath: "auth"}, "APIPath"},
		{authkit.HTTPConfig{DirectPeerIP: true, Exclude: []string{"/api/v1/me"}}, "Exclude"},
		{authkit.HTTPConfig{DirectPeerIP: true, Exclude: []string{"GET /api/v1/nowhere"}}, "matches no mounted route"},
		{authkit.HTTPConfig{DirectPeerIP: true, Redis: redis.NewClient(&redis.Options{}), Limiter: testhttp.Unlimited{}}, "at most one"},
		{authkit.HTTPConfig{DirectPeerIP: true, RateLimits: map[string]authkit.RateLimit{"no_such_bucket": {Limit: 1, Window: time.Minute}}}, "unknown bucket"},
	} {
		cfg.HTTP = tc.http
		auth, err := newClient(t, cfg, deps)
		require.ErrorContains(t, err, tc.err)
		require.Nil(t, auth)
	}
}

// forEachLimiter runs fn with the per-process limiter (rdb nil) and with the
// shared Redis limiter.
func forEachLimiter(t *testing.T, fn func(t *testing.T, rdb *redis.Client)) {
	t.Run("memory", func(t *testing.T) { fn(t, nil) })
	t.Run("redis", func(t *testing.T) { fn(t, testdb.ScratchRedis(t)) })
}

// Password checks are limited per client address only, with each production
// limiter: an exhausted address cannot sign in even with the correct password,
// while the owner elsewhere is never locked out. A Redis failure is an outage,
// never a successful sign-in.
func TestWorkflowRateLimits(t *testing.T) {
	forEachLimiter(t, testWorkflowRateLimits)
}

func testWorkflowRateLimits(t *testing.T, rdb *redis.Client) {
	limits := func(login int) map[string]authkit.RateLimit {
		out := authkit.DefaultRateLimits()
		for bucket := range out {
			out[bucket] = authkit.RateLimit{Limit: 10000, Window: time.Minute}
		}
		out["auth_password_login"] = authkit.RateLimit{Limit: login, Window: time.Minute}
		out["auth_password_step_up"] = authkit.RateLimit{Limit: 2, Window: time.Minute}
		return out
	}
	forwarded := func(r *http.Request) string { return r.Header.Get("X-Forwarded-For") }
	auth, _ := authtest.New(t, authtest.WithConfig(func(c *authkit.Config) {
		c.HTTP = authkit.HTTPConfig{ClientIP: forwarded, RateLimits: limits(2)}
		if rdb != nil {
			c.HTTP.Redis = rdb
		}
	}))
	a := newAPI(t, auth)
	from := func(a *api, address, path, token string, body any) response {
		return a.do(request{method: http.MethodPost, path: path, body: body, token: token, header: http.Header{"X-Forwarded-For": {address}}})
	}
	signIn := func(a *api, u authtest.User, password, address string) response {
		return from(a, address, "/password/login", "", map[string]string{"identifier": u.Email, "password": password})
	}
	stepUp := func(a *api, token, password, address string) response {
		return from(a, address, "/step-up/password", token, map[string]string{"password": password})
	}
	sessions := func(u authtest.User) int {
		list, err := auth.Sessions(t.Context(), u.ID)
		require.NoError(t, err)
		return len(list)
	}
	// staleSession signs u in from address and ages the session, so a
	// sensitive change asks for the password again.
	staleSession := func(u authtest.User, address string) string {
		res := signIn(a, u, u.Password, address)
		require.Equal(t, http.StatusOK, res.status, res.String())
		var tokens iam.TokenSet
		res.decode(t, &tokens)
		authtest.StaleSession(t, auth, tokens.AccessToken)
		return tokens.AccessToken
	}

	owner := authtest.NewUser(t, auth)
	for range 2 {
		res := signIn(a, owner, "wrong-password", "198.51.100.1")
		require.Equal(t, http.StatusUnauthorized, res.status, res.String())
	}
	res := signIn(a, owner, owner.Password, "198.51.100.1")
	require.Equal(t, http.StatusTooManyRequests, res.status, res.String())
	require.Equal(t, "rate_limited", res.code())
	require.Zero(t, sessions(owner))
	res = signIn(a, owner, owner.Password, "198.51.100.2")
	require.Equal(t, http.StatusOK, res.status, "a stranger's failures locked the owner out: %s", res)
	require.Equal(t, 1, sessions(owner))

	stepper := authtest.NewUser(t, auth)
	stale := staleSession(stepper, "198.51.100.3")
	for range 2 {
		res = stepUp(a, stale, "wrong-password", "198.51.100.5")
		require.Equal(t, http.StatusUnauthorized, res.status, res.String())
	}
	res = stepUp(a, stale, stepper.Password, "198.51.100.5")
	require.Equal(t, http.StatusTooManyRequests, res.status, res.String())
	require.Equal(t, "rate_limited", res.code())
	res = from(a, "198.51.100.5", "/user/password", stale, map[string]string{"current_password": stepper.Password, "new_password": "Another-password-12345"})
	require.Equal(t, http.StatusTooManyRequests, res.status, "the password change shares the step-up budget: %s", res)
	res = stepUp(a, stale, stepper.Password, "198.51.100.7")
	require.Equal(t, http.StatusOK, res.status, res.String())

	if rdb == nil {
		return
	}
	outageToken := staleSession(authtest.NewUser(t, auth), "198.51.100.8")
	broken := redis.NewClient(rdb.Options())
	outage := authtest.Replica(t, auth, authtest.WithConfig(func(c *authkit.Config) {
		c.HTTP.Redis = broken
		c.HTTP.RateLimits = limits(10000)
	}))
	// Closing only this client keeps the Redis server and other tests' state,
	// and forces the limiter's backend-error path.
	require.NoError(t, broken.Close())
	down := newAPI(t, outage)
	res = signIn(down, owner, owner.Password, "198.51.100.4")
	require.Equal(t, http.StatusTooManyRequests, res.status, res.String())
	require.Equal(t, 1, sessions(owner), "an outage signs nobody in")
	res = stepUp(down, outageToken, authtest.Password, "198.51.100.9")
	require.Equal(t, http.StatusTooManyRequests, res.status, res.String())
}

// restart builds a Client on auth's schema after closing auth, as a new
// release boots.
func restart(t *testing.T, auth *authkit.Client, opts ...authtest.Option) *authkit.Client {
	t.Helper()
	auth.Close()
	return authtest.Replica(t, auth, opts...)
}

// editorRoles declare an application root permission and a root role holding it.
func editorRoles() (*authkit.Roles, iam.Perm, iam.Role) {
	rbac := authkit.NewRoles()
	edit := rbac.Root.Permission("posts", "edit")
	return rbac, edit, rbac.Root.Role("editor", edit)
}

// Booting installs the root group but never restores a role the system took
// away, with the same Roles or without any.
func TestBootNeverRestoresRoles(t *testing.T) {
	rbac, edit, editor := editorRoles()
	auth, _ := authtest.New(t, authtest.WithConfig(func(c *authkit.Config) {
		c.Roles = rbac
		c.TwoFactor.Mode = iam.TwoFactorDisabled
	}))
	ctx := t.Context()
	_, err := auth.Group(ctx, iam.RootGroup())
	require.NoError(t, err, "construction installs the root group")
	can := func(auth *authkit.Client, u authtest.User) bool {
		ok, err := auth.Can(ctx, iam.UserActor(u.ID), iam.RootGroup(), edit)
		require.NoError(t, err)
		return ok
	}

	revoked := authtest.NewUser(t, auth)
	authtest.GrantRole(t, auth, iam.RootGroup(), iam.UserSubject(revoked.ID), editor)
	res, err := auth.UnassignGroupRoles(ctx, iam.SystemActor(), iam.RootGroup(), []iam.Subject{iam.UserSubject(revoked.ID)}, editor)
	require.NoError(t, err)
	require.NoError(t, res[0].Err)
	kept := authtest.NewUser(t, auth)
	authtest.GrantRole(t, auth, iam.RootGroup(), iam.UserSubject(kept.ID), editor)

	next := restart(t, auth)
	require.False(t, can(next, revoked), "a restart never restores a role the system revoked")
	require.True(t, can(next, kept))

	withoutRoles := authtest.Replica(t, next, authtest.WithConfig(func(c *authkit.Config) { c.Roles = nil }))
	require.NotNil(t, withoutRoles)
	require.True(t, can(next, kept), "a Client built without Roles keeps the roles others granted")
}

// Two Clients constructed at once on a fresh database agree on one root group.
func TestConcurrentConstructionSharesRoot(t *testing.T) {
	cfg, deps := bareConfig(t)
	type result struct {
		auth *authkit.Client
		err  error
	}
	results := make(chan result, 2)
	for range 2 {
		go func() {
			auth, err := newClient(t, cfg, deps)
			results <- result{auth, err}
		}()
	}
	var rootID string
	for range 2 {
		r := <-results
		require.NoError(t, r.err)
		root, err := r.auth.Group(t.Context(), iam.RootGroup())
		require.NoError(t, err)
		if rootID == "" {
			rootID = root.ID
		}
		require.Equal(t, rootID, root.ID)
	}
}
