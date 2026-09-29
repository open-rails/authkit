package engine

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/open-rails/authkit/authprovider"
	"github.com/open-rails/authkit/documents"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/httpapi"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/stretchr/testify/require"
)

func TestNewMountRequiresService(t *testing.T) {
	for _, svc := range []*httpapi.Service{nil, {}} {
		mount, err := httpapi.NewMount(svc, httpapi.MountOptions{})
		require.Error(t, err)
		require.Nil(t, mount)
	}
}

func TestMountCatalog(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	cfg := newServerTestConfig()
	cfg.TwoFactor.Mode = iam.TwoFactorDisabled
	cfg.DeviceKeys.Enabled = false
	client := newServerClient(t, cfg, pg.Pool)
	svc, err := newServer(client, WithoutRateLimiter())
	require.NoError(t, err)
	t.Cleanup(svc.Close)

	t.Run("default surface and authentication metadata", func(t *testing.T) {
		mount, err := httpapi.NewMount(svc, httpapi.MountOptions{})
		require.NoError(t, err)
		routes := mountCatalogByRoute(t, mount)
		require.Equal(t, iam.Route{
			Method: http.MethodPost, Path: "/api/v1/register", Group: iam.RouteRegistration, Auth: iam.AuthPublic,
		}, routes[routeKey{http.MethodPost, "/api/v1/register"}])
		require.Equal(t, iam.Route{
			Method: http.MethodGet, Path: "/api/v1/me", Group: iam.RouteAccount, Auth: iam.AuthRequired,
		}, routes[routeKey{http.MethodGet, "/api/v1/me"}])
		require.Equal(t, iam.Route{
			Method: http.MethodGet, Path: "/api/v1/admin/users/{user_id}", Group: iam.RouteAdmin,
			Auth: iam.AuthPermission, Permission: iam.PermRootUsersRead,
		}, routes[routeKey{http.MethodGet, "/api/v1/admin/users/{user_id}"}])
		require.Equal(t, iam.AuthOptional, routes[routeKey{http.MethodPost, "/api/v1/verify/request"}].Auth)
		for _, route := range mount.Routes() {
			if route.Method == http.MethodGet {
				head := route
				head.Method = http.MethodHead
				require.Equal(t, head, routes[routeKey{http.MethodHead, route.Path}], "GET route must advertise its implicit HEAD")
			}
		}
		for _, path := range []string{"/api/v1/me", "/api/v1/admin/users/some-user"} {
			rec := mountCatalogRequest(mount, http.MethodGet, path, "", "")
			require.Equal(t, http.StatusUnauthorized, rec.Code, rec.Body.String())
		}
	})

	t.Run("catalog callers cannot mutate the mount", func(t *testing.T) {
		mount, err := httpapi.NewMount(svc, httpapi.MountOptions{})
		require.NoError(t, err)
		expected := mount.Routes()
		require.NotEmpty(t, expected)
		changed := mount.Routes()
		changed[0] = iam.Route{Method: http.MethodDelete, Path: "/changed"}
		require.Equal(t, expected, mount.Routes())
		rec := mountCatalogRequest(mount, http.MethodGet, iam.JWKSPath, "", "")
		require.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("JWKS is root anchored and supports HEAD", func(t *testing.T) {
		mount, err := httpapi.NewMount(svc, httpapi.MountOptions{APIPrefix: "/auth/custom"})
		require.NoError(t, err)
		routes := mountCatalogByRoute(t, mount)
		for _, method := range []string{http.MethodGet, http.MethodHead} {
			require.Equal(t, iam.Route{Method: method, Path: iam.JWKSPath, Group: iam.RouteAuth, Auth: iam.AuthPublic}, routes[routeKey{method, iam.JWKSPath}])
			rec := mountCatalogRequest(mount, method, iam.JWKSPath, "", "")
			require.Equal(t, http.StatusOK, rec.Code)
		}
		require.Equal(t, http.StatusNotFound, mountCatalogRequest(mount, http.MethodGet, "/auth/custom"+iam.JWKSPath, "", "").Code)
	})

	t.Run("custom prefix group selection and normalized exclusions", func(t *testing.T) {
		mount, err := httpapi.NewMount(svc, httpapi.MountOptions{
			APIPrefix: " /auth/custom/ ",
			Groups:    []iam.RouteGroup{iam.RouteRegistration},
			Exclude:   []string{" get /auth/custom/register/availability ", "GET " + iam.JWKSPath},
		})
		require.NoError(t, err)
		require.ElementsMatch(t, []iam.Route{
			{Method: http.MethodPost, Path: "/auth/custom/register", Group: iam.RouteRegistration, Auth: iam.AuthPublic},
			{Method: http.MethodPost, Path: "/auth/custom/register/abandon", Group: iam.RouteRegistration, Auth: iam.AuthPublic},
		}, mount.Routes())
		for _, ref := range []routeKey{
			{http.MethodGet, "/auth/custom/register/availability"},
			{http.MethodHead, "/auth/custom/register/availability"},
			{http.MethodGet, iam.JWKSPath},
			{http.MethodHead, iam.JWKSPath},
			{http.MethodPost, "/auth/custom/password/login"},
			{http.MethodPost, "/api/v1/register"},
		} {
			rec := mountCatalogRequest(mount, ref.method, ref.path, "", "")
			require.Equal(t, http.StatusNotFound, rec.Code, "%s %s", ref.method, ref.path)
		}
	})

	t.Run("root API prefix", func(t *testing.T) {
		mount, err := httpapi.NewMount(svc, httpapi.MountOptions{APIPrefix: "/", Groups: []iam.RouteGroup{iam.RouteAuth}})
		require.NoError(t, err)
		routes := mountCatalogByRoute(t, mount)
		require.Contains(t, routes, routeKey{http.MethodPost, "/password/login"})
		require.NotContains(t, routes, routeKey{http.MethodPost, "/api/v1/password/login"})
		require.Equal(t, http.StatusOK, mountCatalogRequest(mount, http.MethodGet, "/capabilities", "", "").Code)
	})

	t.Run("disabled capabilities are absent from catalog and handler", func(t *testing.T) {
		mount, err := httpapi.NewMount(svc, httpapi.MountOptions{})
		require.NoError(t, err)
		routes := mountCatalogByRoute(t, mount)
		for _, ref := range []routeKey{
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
			rec := mountCatalogRequest(mount, ref.method, ref.path, "", "")
			require.Equal(t, http.StatusNotFound, rec.Code, "%s %s: %s", ref.method, ref.path, rec.Body.String())
		}
	})

	t.Run("invalid prefix or exclusion fails without a usable mount", func(t *testing.T) {
		for _, opts := range []httpapi.MountOptions{
			{APIPrefix: "auth"},
			{Exclude: []string{"/api/v1/me"}},
			{Exclude: []string{"GET /api/v1/nowhere"}},
		} {
			mount, err := httpapi.NewMount(svc, opts)
			require.Error(t, err)
			require.Nil(t, mount)
		}
	})

	t.Run("mount retains JSON and cookie behavior", func(t *testing.T) {
		email, password := newCookieTestUser(t, pg.Pool, svc, "mountcatalog")
		body, err := json.Marshal(map[string]string{"identifier": email, "password": password})
		require.NoError(t, err)
		opts := httpapi.MountOptions{APIPrefix: "/auth", RefreshCookie: true}
		mount, err := httpapi.NewMount(svc, opts)
		require.NoError(t, err)
		for _, handler := range []http.Handler{mount} {
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
			require.Equal(t, iam.RefreshCookieName, cookies[0].Name)
			require.Equal(t, "/", cookies[0].Path)
			require.True(t, cookies[0].HttpOnly)
			require.Equal(t, http.SameSiteLaxMode, cookies[0].SameSite)
		}
	})

	t.Run("custom prefix retains MFA enrollment exemptions", func(t *testing.T) {
		mfaConfig := cfg
		mfaConfig.TwoFactor.Mode = iam.TwoFactorRequired
		mfaConfig.TwoFactor.TOTPSecretKey = []byte("0123456789abcdef0123456789abcdef")
		mfaService, err := newServer(newServerClient(t, mfaConfig, pg.Pool), WithoutRateLimiter())
		require.NoError(t, err)
		t.Cleanup(mfaService.Close)
		mount, err := httpapi.NewMount(mfaService, httpapi.MountOptions{APIPrefix: "/custom/auth"})
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
	cfg.TwoFactor.Mode = iam.TwoFactorDisabled
	cfg.Identity.Providers = []authprovider.Provider{testOAuth2Provider("catalog", "https://idp.example", "client", "secret")}
	cfg.Documents.Readers = []DocumentReader{{Issuer: "https://reader.example"}}
	client := newServerClient(t, cfg, pg.Pool)
	doc, err := client.PublishDocument(t.Context(), documents.Publication{
		Type: "example.mount-catalog/v1", Payload: json.RawMessage(`{"catalog":true}`),
		Audiences: cfg.Token.ExpectedAudiences,
	})
	require.NoError(t, err)
	svc, err := newServer(client, WithoutRateLimiter())
	require.NoError(t, err)
	t.Cleanup(svc.Close)
	mount, err := httpapi.NewMount(svc, httpapi.MountOptions{APIPrefix: "/auth/custom"})
	require.NoError(t, err)
	routes := mountCatalogByRoute(t, mount)
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		require.Equal(t, iam.Route{Method: method, Path: iam.DocumentsPath, Group: iam.RouteDocuments, Auth: iam.AuthRequired}, routes[routeKey{method, iam.DocumentsPath}])
		require.Equal(t, iam.Route{Method: method, Path: "/oidc/{provider}/login", Group: iam.RouteBrowserOIDC, Auth: iam.AuthPublic}, routes[routeKey{method, "/oidc/{provider}/login"}])
		rec := mountCatalogRequest(mount, method, "/.well-known/authkit/documents/"+doc.Digest, "", "")
		require.Equal(t, http.StatusUnauthorized, rec.Code, rec.Body.String())
	}
	for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodPost} {
		require.Contains(t, routes, routeKey{method, "/oidc/{provider}/callback"})
	}
	login := mountCatalogRequest(mount, http.MethodGet, "/oidc/catalog/login", "", "")
	require.Equal(t, http.StatusFound, login.Code, login.Body.String())
	require.Contains(t, login.Header().Get("Location"), "https://idp.example/")

	for _, opts := range []httpapi.MountOptions{
		{Groups: []iam.RouteGroup{iam.RouteRegistration}},
		{Exclude: []string{"GET " + iam.DocumentsPath, "GET /oidc/{provider}/login", "POST /oidc/{provider}/login"}},
	} {
		filtered, err := httpapi.NewMount(svc, opts)
		require.NoError(t, err)
		filteredRoutes := mountCatalogByRoute(t, filtered)
		for _, method := range []string{http.MethodGet, http.MethodHead} {
			require.NotContains(t, filteredRoutes, routeKey{method, iam.DocumentsPath})
			require.NotContains(t, filteredRoutes, routeKey{method, "/oidc/{provider}/login"})
			require.Equal(t, http.StatusNotFound, mountCatalogRequest(filtered, method, "/.well-known/authkit/documents/"+doc.Digest, "", "").Code)
			require.Equal(t, http.StatusNotFound, mountCatalogRequest(filtered, method, "/oidc/catalog/login", "", "").Code)
		}
	}
}

type routeKey struct{ method, path string }

func mountCatalogByRoute(t *testing.T, mount *httpapi.Mount) map[routeKey]iam.Route {
	t.Helper()
	routes := make(map[routeKey]iam.Route)
	for _, route := range mount.Routes() {
		key := routeKey{route.Method, route.Path}
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
