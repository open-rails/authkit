package authhttp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/open-rails/authkit/authprovider"
	"github.com/open-rails/authkit/documents"
	"github.com/open-rails/authkit/embedded"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/stretchr/testify/require"
)

func TestNewMountRequiresService(t *testing.T) {
	for _, svc := range []*Service{nil, {}} {
		mount, err := NewMount(svc, MountOptions{})
		require.Error(t, err)
		require.Nil(t, mount)
	}
}

func TestMountCatalog(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	cfg := newServerTestConfig()
	cfg.TwoFactor.Mode = embedded.TwoFactorDisabled
	cfg.DeviceKeys.Enabled = false
	client := newServerClient(t, cfg, pg.Pool)
	svc, err := newServer(client, WithoutRateLimiter())
	require.NoError(t, err)
	t.Cleanup(svc.Close)

	t.Run("default surface and authentication metadata", func(t *testing.T) {
		mount, err := NewMount(svc, MountOptions{})
		require.NoError(t, err)
		routes := mountCatalogByRoute(t, mount)
		require.Equal(t, MountedRoute{
			Method: http.MethodPost, Path: "/api/v1/register", Group: RouteRegistration, Auth: AuthPublic,
		}, routes[RouteRef{http.MethodPost, "/api/v1/register"}])
		require.Equal(t, MountedRoute{
			Method: http.MethodGet, Path: "/api/v1/me", Group: RouteAccount, Auth: AuthRequired,
		}, routes[RouteRef{http.MethodGet, "/api/v1/me"}])
		require.Equal(t, MountedRoute{
			Method: http.MethodGet, Path: "/api/v1/admin/users/{user_id}", Group: RouteAdmin,
			Auth: AuthPermission, Permission: embedded.PermRootResourcesRead,
		}, routes[RouteRef{http.MethodGet, "/api/v1/admin/users/{user_id}"}])
		require.Equal(t, AuthOptional, routes[RouteRef{http.MethodPost, "/api/v1/verify/request"}].Auth)
		for _, route := range mount.Routes() {
			if route.Method == http.MethodGet {
				head := route
				head.Method = http.MethodHead
				require.Equal(t, head, routes[RouteRef{http.MethodHead, route.Path}], "GET route must advertise its implicit HEAD")
			}
		}
		for _, path := range []string{"/api/v1/me", "/api/v1/admin/users/some-user"} {
			rec := mountCatalogRequest(mount, http.MethodGet, path, "", "")
			require.Equal(t, http.StatusUnauthorized, rec.Code, rec.Body.String())
		}
	})

	t.Run("catalog callers cannot mutate the mount", func(t *testing.T) {
		mount, err := NewMount(svc, MountOptions{})
		require.NoError(t, err)
		expected := mount.Routes()
		require.NotEmpty(t, expected)
		changed := mount.Routes()
		changed[0] = MountedRoute{Method: http.MethodDelete, Path: "/changed"}
		require.Equal(t, expected, mount.Routes())
		rec := mountCatalogRequest(mount, http.MethodGet, JWKSPath, "", "")
		require.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("JWKS is root anchored and supports HEAD", func(t *testing.T) {
		mount, err := NewMount(svc, MountOptions{APIPrefix: "/auth/custom"})
		require.NoError(t, err)
		routes := mountCatalogByRoute(t, mount)
		for _, method := range []string{http.MethodGet, http.MethodHead} {
			require.Equal(t, MountedRoute{Method: method, Path: JWKSPath, Group: RouteAuth, Auth: AuthPublic}, routes[RouteRef{method, JWKSPath}])
			rec := mountCatalogRequest(mount, method, JWKSPath, "", "")
			require.Equal(t, http.StatusOK, rec.Code)
		}
		require.Equal(t, http.StatusNotFound, mountCatalogRequest(mount, http.MethodGet, "/auth/custom"+JWKSPath, "", "").Code)
	})

	t.Run("custom prefix group selection and normalized exclusions", func(t *testing.T) {
		mount, err := NewMount(svc, MountOptions{
			APIPrefix: " /auth/custom/ ",
			Groups:    []RouteGroup{RouteRegistration},
			ExcludeRoutes: []RouteRef{
				{Method: " get ", Path: " /register/availability "},
				{Method: http.MethodGet, Path: JWKSPath},
			},
		})
		require.NoError(t, err)
		require.ElementsMatch(t, []MountedRoute{
			{Method: http.MethodPost, Path: "/auth/custom/register", Group: RouteRegistration, Auth: AuthPublic},
			{Method: http.MethodPost, Path: "/auth/custom/register/resend", Group: RouteRegistration, Auth: AuthPublic},
			{Method: http.MethodPost, Path: "/auth/custom/register/abandon", Group: RouteRegistration, Auth: AuthPublic},
		}, mount.Routes())
		for _, ref := range []RouteRef{
			{http.MethodGet, "/auth/custom/register/availability"},
			{http.MethodHead, "/auth/custom/register/availability"},
			{http.MethodGet, JWKSPath},
			{http.MethodHead, JWKSPath},
			{http.MethodPost, "/auth/custom/password/login"},
			{http.MethodPost, "/api/v1/register"},
		} {
			rec := mountCatalogRequest(mount, ref.Method, ref.Path, "", "")
			require.Equal(t, http.StatusNotFound, rec.Code, "%s %s", ref.Method, ref.Path)
		}
	})

	t.Run("root API prefix", func(t *testing.T) {
		mount, err := NewMount(svc, MountOptions{APIPrefix: "/", Groups: []RouteGroup{RouteAuth}})
		require.NoError(t, err)
		routes := mountCatalogByRoute(t, mount)
		require.Contains(t, routes, RouteRef{http.MethodPost, "/password/login"})
		require.NotContains(t, routes, RouteRef{http.MethodPost, "/api/v1/password/login"})
		require.Equal(t, http.StatusOK, mountCatalogRequest(mount, http.MethodGet, "/capabilities", "", "").Code)
	})

	t.Run("disabled capabilities are absent from catalog and handler", func(t *testing.T) {
		mount, err := NewMount(svc, MountOptions{})
		require.NoError(t, err)
		routes := mountCatalogByRoute(t, mount)
		for _, ref := range []RouteRef{
			{http.MethodPost, "/api/v1/device-keys/login/begin"},
			{http.MethodPost, "/api/v1/passwordless/start"},
			{http.MethodPost, "/api/v1/2fa/challenge"},
			{http.MethodGet, "/api/v1/user/2fa"},
			{http.MethodPost, "/api/v1/solana/challenge"},
			{http.MethodPost, "/api/v1/applications/register"},
			{http.MethodPost, "/api/v1/delegated/token"},
			{http.MethodGet, "/oidc/example/login"},
			{http.MethodGet, "/.well-known/authkit/documents/missing"},
		} {
			require.NotContains(t, routes, ref)
			rec := mountCatalogRequest(mount, ref.Method, ref.Path, "", "")
			require.Equal(t, http.StatusNotFound, rec.Code, "%s %s: %s", ref.Method, ref.Path, rec.Body.String())
		}
	})

	t.Run("invalid prefix fails without a usable mount", func(t *testing.T) {
		mount, err := NewMount(svc, MountOptions{APIPrefix: "auth"})
		require.Error(t, err)
		require.Nil(t, mount)
	})

	t.Run("legacy handler and catalog mount retain JSON and cookie behavior", func(t *testing.T) {
		email, password := newCookieTestUser(t, pg.Pool, svc, "mountcatalog")
		body, err := json.Marshal(map[string]string{"identifier": email, "password": password})
		require.NoError(t, err)
		opts := MountOptions{APIPrefix: "/auth", RefreshCookie: true}
		mount, err := NewMount(svc, opts)
		require.NoError(t, err)
		legacy, err := MountHandler(svc, opts)
		require.NoError(t, err)
		for _, handler := range []http.Handler{mount, legacy} {
			badJSON := mountCatalogRequest(handler, http.MethodPost, "/auth/password/login", string(body), "text/plain")
			require.Equal(t, http.StatusBadRequest, badJSON.Code, badJSON.Body.String())
			login := mountCatalogRequest(handler, http.MethodPost, "/auth/password/login", string(body), "application/json")
			require.Equal(t, http.StatusOK, login.Code, login.Body.String())
			var tokens map[string]any
			require.NoError(t, json.Unmarshal(login.Body.Bytes(), &tokens))
			require.NotEmpty(t, tokens["access_token"])
			require.NotContains(t, tokens, "refresh_token")
			cookies := login.Result().Cookies()
			require.Len(t, cookies, 1)
			require.Equal(t, RefreshCookieName, cookies[0].Name)
			require.Equal(t, "/auth/token", cookies[0].Path)
			require.True(t, cookies[0].HttpOnly)
			require.Equal(t, http.SameSiteLaxMode, cookies[0].SameSite)
		}
	})

	t.Run("custom prefix retains MFA enrollment exemptions", func(t *testing.T) {
		mfaConfig := cfg
		mfaConfig.TwoFactor.Mode = embedded.TwoFactorRequired
		mfaConfig.TwoFactor.TOTPSecretKey = []byte("0123456789abcdef0123456789abcdef")
		mfaService, err := newServer(newServerClient(t, mfaConfig, pg.Pool), WithoutRateLimiter())
		require.NoError(t, err)
		t.Cleanup(mfaService.Close)
		mount, err := NewMount(mfaService, MountOptions{APIPrefix: "/custom/auth"})
		require.NoError(t, err)
		email, password := newCookieTestUser(t, pg.Pool, mfaService, "mountmfa")
		body, err := json.Marshal(map[string]string{"identifier": email, "password": password})
		require.NoError(t, err)
		login := mountCatalogRequest(mount, http.MethodPost, "/custom/auth/password/login", string(body), "application/json")
		require.Equal(t, http.StatusForbidden, login.Code, login.Body.String())
		var response flowResponse
		require.NoError(t, json.Unmarshal(login.Body.Bytes(), &response))
		require.Equal(t, "2fa_enrollment_required", response.Error.Code)
		token := response.Error.Metadata.TokenSet.AccessToken
		require.NotEmpty(t, token)
		for _, test := range []struct {
			path   string
			status int
		}{
			{"/custom/auth/me", http.StatusForbidden},
			{"/custom/auth/user/2fa", http.StatusOK},
		} {
			req := httptest.NewRequest(http.MethodGet, test.path, nil)
			req.Header.Set("Authorization", "Bearer "+token)
			rec := httptest.NewRecorder()
			mount.ServeHTTP(rec, req)
			require.Equal(t, test.status, rec.Code, "%s: %s", test.path, rec.Body.String())
		}
	})
}

func TestMountCatalogOIDCAndDocuments(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	cfg := newServerTestConfig()
	cfg.TwoFactor.Mode = embedded.TwoFactorDisabled
	cfg.Identity.Providers = []authprovider.Provider{testOAuth2Provider("catalog", "https://idp.example", "client", "secret")}
	cfg.Documents.Readers = []embedded.DocumentReader{{Issuer: "https://reader.example"}}
	client := newServerClient(t, cfg, pg.Pool)
	doc, err := documents.NewService(t.Context(), documents.ServiceConfig{
		Type: "example.mount-catalog/v1", Payload: json.RawMessage(`{"catalog":true}`),
		Issuer: cfg.Token.Issuer, Audiences: cfg.Token.ExpectedAudiences,
		Signer: client, Store: client.DocumentStore(),
	})
	require.NoError(t, err)
	svc, err := newServer(client, WithoutRateLimiter(), WithDocuments(doc))
	require.NoError(t, err)
	t.Cleanup(svc.Close)
	mount, err := NewMount(svc, MountOptions{APIPrefix: "/auth/custom"})
	require.NoError(t, err)
	routes := mountCatalogByRoute(t, mount)
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		require.Equal(t, MountedRoute{Method: method, Path: DocumentsPath, Group: RouteDocuments, Auth: AuthRequired}, routes[RouteRef{method, DocumentsPath}])
		require.Equal(t, MountedRoute{Method: method, Path: "/oidc/{provider}/login", Group: RouteBrowserOIDC, Auth: AuthPublic}, routes[RouteRef{method, "/oidc/{provider}/login"}])
		rec := mountCatalogRequest(mount, method, "/.well-known/authkit/documents/"+doc.Reference().Digest, "", "")
		require.Equal(t, http.StatusUnauthorized, rec.Code, rec.Body.String())
	}
	for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodPost} {
		require.Contains(t, routes, RouteRef{method, "/oidc/{provider}/callback"})
	}
	login := mountCatalogRequest(mount, http.MethodGet, "/oidc/catalog/login", "", "")
	require.Equal(t, http.StatusFound, login.Code, login.Body.String())
	require.Contains(t, login.Header().Get("Location"), "https://idp.example/")

	for _, opts := range []MountOptions{
		{Groups: []RouteGroup{RouteRegistration}},
		{ExcludeRoutes: []RouteRef{{http.MethodGet, DocumentsPath}, {http.MethodGet, "/{provider}/login"}}},
	} {
		filtered, err := NewMount(svc, opts)
		require.NoError(t, err)
		filteredRoutes := mountCatalogByRoute(t, filtered)
		for _, method := range []string{http.MethodGet, http.MethodHead} {
			require.NotContains(t, filteredRoutes, RouteRef{method, DocumentsPath})
			require.NotContains(t, filteredRoutes, RouteRef{method, "/oidc/{provider}/login"})
			require.Equal(t, http.StatusNotFound, mountCatalogRequest(filtered, method, "/.well-known/authkit/documents/"+doc.Reference().Digest, "", "").Code)
			require.Equal(t, http.StatusNotFound, mountCatalogRequest(filtered, method, "/oidc/catalog/login", "", "").Code)
		}
	}
}

func mountCatalogByRoute(t *testing.T, mount *Mount) map[RouteRef]MountedRoute {
	t.Helper()
	routes := make(map[RouteRef]MountedRoute)
	for _, route := range mount.Routes() {
		key := RouteRef{route.Method, route.Path}
		require.NotContains(t, routes, key, "duplicate method/path in mounted catalog")
		routes[key] = route
	}
	return routes
}

func mountCatalogRequest(handler http.Handler, method, path, body, contentType string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}
