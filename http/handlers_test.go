package authhttp

import (
	"context"
	"crypto"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/open-rails/authkit/authprovider"
	core "github.com/open-rails/authkit/core"
	jwtkit "github.com/open-rails/authkit/jwt"
	oidckit "github.com/open-rails/authkit/oidc"
	"github.com/stretchr/testify/require"
)

func newTestCoreService(t *testing.T) *core.Service {
	t.Helper()
	signer, err := jwtkit.NewRSASigner(2048, "test-kid")
	require.NoError(t, err)
	ks := core.Keyset{Active: signer, PublicKeys: map[string]crypto.PublicKey{"test-kid": signer.PublicKey()}}
	opts := core.Options{
		Issuer:              "https://example.com",
		IssuedAudiences:     []string{"test-app"},
		ExpectedAudiences:   []string{"test-app"},
		AccessTokenDuration: time.Hour,
		// Tests that use newTestCoreService are not testing registration/verification flows,
		// so we explicitly opt out to avoid needing a real email sender.
		RegistrationVerification: core.RegistrationVerificationNone,
	}
	return core.NewService(opts, ks)
}

func newTestService(t *testing.T) *Service {
	t.Helper()
	coreSvc := newTestCoreService(t)
	opts := coreSvc.Options()
	ver := NewVerifier(WithSkew(5 * time.Second))
	_ = ver.AddIssuer(opts.Issuer, opts.ExpectedAudiences, IssuerOptions{
		RawKeys: coreSvc.PublicKeysByKID(),
	})
	ver.WithService(coreSvc)
	return &Service{svc: coreSvc, verifier: ver}
}

// newNoDBPool returns a *pgxpool.Pool that satisfies NewServer's mandatory
// non-nil pool requirement (#106/#108) WITHOUT touching a database. pgxpool.New
// with the default MinConns=0 never dials eagerly (idle resources are created in
// a background goroutine up to MinConns), so a pool built from a parseable DSN
// is inert. Use it for pure no-DB handler tests (request validation, rate
// limiting, provider prebuild) where the assertion fires before any query.
func newNoDBPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	pool, err := pgxpool.New(context.Background(), "postgres://authkit:authkit@127.0.0.1:5432/authkit_test")
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	return pool
}

func TestJWKSHandler(t *testing.T) {
	svc := newTestCoreService(t)
	h := JWKSHandler(svc.JWKS())

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	h.ServeHTTP(w, r)
	require.Equal(t, http.StatusOK, w.Code)

	var body struct {
		Keys []struct {
			Kty string `json:"kty"`
			Kid string `json:"kid"`
			Alg string `json:"alg"`
		} `json:"keys"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	require.NotEmpty(t, body.Keys)
	require.Equal(t, "RSA", body.Keys[0].Kty)
	require.NotEmpty(t, body.Keys[0].Kid)
	require.Equal(t, "RS256", body.Keys[0].Alg)
}

func TestAPIHandler_Token_InvalidRequest(t *testing.T) {
	s := newTestService(t)
	h := s.APIHandler()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(`{}`))
	h.ServeHTTP(w, r)
	require.Equal(t, http.StatusBadRequest, w.Code)
	require.Contains(t, w.Body.String(), `"code":"invalid_request"`)
}

func TestAPIHandler_Logout_MissingSidClaim(t *testing.T) {
	s := newTestService(t)
	h := s.APIHandler()

	tok, _, err := s.svc.IssueAccessToken(context.Background(), "user", "e@example.com", map[string]any{})
	require.NoError(t, err)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/logout", nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	h.ServeHTTP(w, r)
	require.Equal(t, http.StatusBadRequest, w.Code)
	require.Contains(t, w.Body.String(), `"code":"missing_sid_claim"`)
}

func TestOIDCHandler_Callback_MissingStateOrCode(t *testing.T) {
	s := newTestService(t)
	h := s.OIDCHandler()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/oidc/google/callback", nil)
	h.ServeHTTP(w, r)
	require.Equal(t, http.StatusBadRequest, w.Code)
	require.Contains(t, w.Body.String(), `"code":"invalid_request"`)
}

func TestOIDCHandler_ReauthCallback_MissingStateOrCode(t *testing.T) {
	s := newTestService(t)
	h := s.OIDCHandler()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/oidc/google/reauth/callback", nil)
	h.ServeHTTP(w, r)
	require.Equal(t, http.StatusBadRequest, w.Code)
	require.Contains(t, w.Body.String(), `"code":"invalid_request"`)
}

func TestOIDCHandler_LegacyAuthPathNotMounted(t *testing.T) {
	s := newTestService(t)
	h := s.OIDCHandler()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/auth/oidc/google/callback", nil)
	h.ServeHTTP(w, r)
	require.Equal(t, http.StatusNotFound, w.Code)
}

func TestServiceStateCachePersistsWithoutRedis(t *testing.T) {
	s := newTestService(t)
	err := s.stateCache().Put(context.Background(), "state-1", oidckit.StateData{Provider: "github"})
	require.NoError(t, err)

	got, ok, err := s.stateCache().Get(context.Background(), "state-1")
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, "github", got.Provider)
}

func TestOIDCHandler_OAuth2ProvidersUseGenericProviderRoute(t *testing.T) {
	s := newTestService(t)
	s.oidcProviders = map[string]oidckit.RPConfig{
		"discord": {ClientID: "discord-client", ClientSecret: "discord-secret"},
		"github":  {ClientID: "github-client", ClientSecret: "github-secret"},
	}
	s.providers = map[string]authprovider.Provider{
		"custom-oauth": {
			Name:         "custom-oauth",
			Kind:         authprovider.KindOAuth2,
			Issuer:       "https://custom.example",
			ClientID:     "custom-client",
			ClientSecret: authprovider.ClientSecret{Value: "custom-secret"},
			AuthorizeURL: "https://custom.example/oauth/authorize",
			TokenURL:     "https://custom.example/oauth/token",
			UserInfoURL:  "https://custom.example/me",
			Scopes:       []string{"profile"},
			PKCE:         true,
			UserMapping: authprovider.UserMapping{
				Subject: authprovider.FieldMapping{Path: "id"},
			},
		},
	}
	var err error
	s.authProvidersByName, err = buildAuthProvidersMap(s.oidcProviders, s.providers)
	require.NoError(t, err)
	s.resetOIDCManagerForTest()
	h := s.OIDCHandler()

	tests := []struct {
		provider string
		wantURL  string
		wantPKCE bool
	}{
		{provider: "discord", wantURL: "https://discord.com/api/oauth2/authorize"},
		{provider: "github", wantURL: "https://github.com/login/oauth/authorize", wantPKCE: true},
		{provider: "custom-oauth", wantURL: "https://custom.example/oauth/authorize", wantPKCE: true},
	}
	for _, tt := range tests {
		t.Run(tt.provider, func(t *testing.T) {
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, "/oidc/"+tt.provider+"/login", nil)
			h.ServeHTTP(w, r)
			require.Equal(t, http.StatusFound, w.Code)
			location := w.Header().Get("Location")
			require.Contains(t, location, tt.wantURL)
			require.NotContains(t, location, "openid")
			u, err := url.Parse(location)
			require.NoError(t, err)
			q := u.Query()
			if tt.wantPKCE {
				require.NotEmpty(t, q.Get("code_challenge"))
				require.Equal(t, "S256", q.Get("code_challenge_method"))
			} else {
				require.Empty(t, q.Get("code_challenge"))
				require.Empty(t, q.Get("code_challenge_method"))
			}
		})
	}
}

func TestBuildFrontendCallbackURL(t *testing.T) {
	tests := []struct {
		name         string
		baseURL      string
		callbackPath string
		fragment     string
		want         string
	}{
		{name: "default", baseURL: "https://app.example", callbackPath: "", fragment: "#access_token=a", want: "https://app.example/login/callback#access_token=a"},
		{name: "trims base slash", baseURL: "https://app.example/", callbackPath: "/login/complete", fragment: "#access_token=a", want: "https://app.example/login/complete#access_token=a"},
		{name: "preserves query", baseURL: "https://app.example", callbackPath: "/login/complete?mode=oidc", fragment: "#access_token=a", want: "https://app.example/login/complete?mode=oidc#access_token=a"},
		{name: "relative fallback", baseURL: "", callbackPath: "/login/complete", fragment: "#access_token=a", want: "/login/complete#access_token=a"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildFrontendCallbackURL(tt.baseURL, tt.callbackPath, tt.fragment)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestBuildRedirectURI_ReauthStartUsesReauthCallback(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "https://auth.example/api/v1/oidc/google/reauth/start", nil)
	got := buildRedirectURI(r, "google")
	require.Equal(t, "https://auth.example/api/v1/oidc/google/reauth/callback", got)
}

func TestFreshReauthRouteContract(t *testing.T) {
	reauthSrc := readHTTPSource(t, "reauth.go")
	oidcBrowserSrc := readHTTPSource(t, "oidc_browser.go")
	userRoutesSrc := readHTTPSource(t, "user_routes.go")
	passwordSrc := readHTTPSource(t, "user_password_post.go")
	userMeSrc := readHTTPSource(t, "user_me_get.go")

	for _, marker := range []string{
		"handlePasswordReauthPOST",
		"handleTwoFactorReauthPOST",
		"handleOIDCReauthStartPOST",
		"Require2FAForReauth",
		"Verify2FAReauthCode",
		"ReauthUserID",
		"ReauthSessionID",
		"GetProviderLinkByIssuer(r.Context(), issuer, subject)",
		"MarkSessionAuthenticated",
		"reauth_methods",
	} {
		require.Contains(t, reauthSrc, marker)
	}
	require.Contains(t, oidcBrowserSrc, "completeOIDCReauth")
	require.Contains(t, oidcBrowserSrc, "GetProviderLinkByIssuer(r.Context(), issuer, claims.Subject)")
	require.Contains(t, userRoutesSrc, "requireFreshAuthOrPassword")
	require.Contains(t, passwordSrc, "RequireFreshSession")
	require.Contains(t, userMeSrc, "time_until_reauth_required")
}

func readHTTPSource(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	require.NoError(t, err)
	return string(b)
}

func TestAPIHandler_PrefixNeutralRouteContract(t *testing.T) {
	s := newTestService(t)
	h := s.APIHandler()

	tests := []struct {
		name   string
		method string
		path   string
		body   string
		want   int
	}{
		{name: "token", method: http.MethodPost, path: "/token", body: `{}`, want: http.StatusBadRequest},
		{name: "current session lookup", method: http.MethodPost, path: "/sessions/current", body: `{}`, want: http.StatusBadRequest},
		{name: "password login", method: http.MethodPost, path: "/password/login", body: `{}`, want: http.StatusBadRequest},
		{name: "email password reset request", method: http.MethodPost, path: "/email/password/reset/request", body: `{}`, want: http.StatusAccepted},
		{name: "email password reset confirm", method: http.MethodPost, path: "/email/password/reset/confirm", body: `{}`, want: http.StatusBadRequest},
		{name: "phone password reset request", method: http.MethodPost, path: "/phone/password/reset/request", body: `{}`, want: http.StatusInternalServerError},
		{name: "phone password reset confirm", method: http.MethodPost, path: "/phone/password/reset/confirm", body: `{}`, want: http.StatusBadRequest},
		{name: "user me", method: http.MethodGet, path: "/user/me", want: http.StatusUnauthorized},
		{name: "user sessions list", method: http.MethodGet, path: "/user/sessions", want: http.StatusUnauthorized},
		{name: "user session delete", method: http.MethodDelete, path: "/user/sessions/session-id", want: http.StatusUnauthorized},
		{name: "user sessions revoke all", method: http.MethodDelete, path: "/user/sessions", want: http.StatusUnauthorized},
		{name: "logout", method: http.MethodDelete, path: "/logout", want: http.StatusUnauthorized},
		{name: "password reauth", method: http.MethodPost, path: "/reauth/password", body: `{}`, want: http.StatusUnauthorized},
		{name: "2fa reauth", method: http.MethodPost, path: "/reauth/2fa", body: `{}`, want: http.StatusUnauthorized},
		{name: "email change", method: http.MethodPost, path: "/user/email/change", body: `{}`, want: http.StatusUnauthorized},
		{name: "phone change", method: http.MethodPost, path: "/user/phone/change", body: `{}`, want: http.StatusUnauthorized},
		{name: "provider link start", method: http.MethodPost, path: "/oidc/google/link/start", want: http.StatusUnauthorized},
		{name: "provider reauth start", method: http.MethodPost, path: "/oidc/google/reauth/start", want: http.StatusUnauthorized},
		{name: "2fa status", method: http.MethodGet, path: "/user/2fa", want: http.StatusUnauthorized},
		{name: "2fa configure", method: http.MethodPost, path: "/user/2fa", body: `{}`, want: http.StatusUnauthorized},
		{name: "2fa disable", method: http.MethodDelete, path: "/user/2fa", want: http.StatusUnauthorized},
		{name: "2fa backup codes", method: http.MethodPost, path: "/user/2fa/backup-codes", body: `{}`, want: http.StatusUnauthorized},
		{name: "2fa verify", method: http.MethodPost, path: "/2fa/verify", body: `{}`, want: http.StatusBadRequest},
		{name: "solana challenge", method: http.MethodPost, path: "/solana/challenge", body: `{}`, want: http.StatusBadRequest},
		{name: "solana link", method: http.MethodPost, path: "/solana/link", body: `{}`, want: http.StatusUnauthorized},
		{name: "admin users list", method: http.MethodGet, path: "/admin/users", want: http.StatusUnauthorized},
		{name: "admin user get", method: http.MethodGet, path: "/admin/users/user-id", want: http.StatusUnauthorized},
		{name: "admin user delete", method: http.MethodDelete, path: "/admin/users/user-id", want: http.StatusUnauthorized},
		{name: "admin user restore", method: http.MethodPost, path: "/admin/users/user-id/restore", want: http.StatusUnauthorized},
		{name: "admin user signins", method: http.MethodGet, path: "/admin/users/user-id/signins", want: http.StatusUnauthorized},
		{name: "admin user session revoke", method: http.MethodPost, path: "/admin/users/user-id/sessions/revoke", want: http.StatusUnauthorized},
		{name: "admin ban", method: http.MethodPost, path: "/admin/users/ban", body: `{}`, want: http.StatusUnauthorized},
		{name: "admin unban", method: http.MethodPost, path: "/admin/users/unban", body: `{}`, want: http.StatusUnauthorized},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var body *strings.Reader
			if tt.body != "" {
				body = strings.NewReader(tt.body)
			} else {
				body = strings.NewReader("")
			}
			w := httptest.NewRecorder()
			r := httptest.NewRequest(tt.method, tt.path, body)
			r.Header.Set("Content-Type", "application/json")
			h.ServeHTTP(w, r)
			require.Equal(t, tt.want, w.Code, w.Body.String())
		})
	}
}

func TestAPIHandler_GenericPasswordResetRoutesRemoved(t *testing.T) {
	s := newTestService(t)
	h := s.APIHandler()

	for _, path := range []string{
		"/password/reset/request",
		"/password/reset/confirm-link",
		"/password/reset/confirm",
		"/email/password/reset/confirm-link",
		"/phone/password/reset/confirm-link",
		"/email/verify/confirm-link",
		"/phone/verify/confirm-link",
	} {
		t.Run(path, func(t *testing.T) {
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{}`))
			h.ServeHTTP(w, r)
			require.Equal(t, http.StatusNotFound, w.Code)
		})
	}
}

func TestAPIHandler_LegacyAuthPrefixNotMounted(t *testing.T) {
	s := newTestService(t)
	h := s.APIHandler()

	tests := []struct {
		method string
		path   string
	}{
		{method: http.MethodPost, path: "/auth/token"},
		{method: http.MethodGet, path: "/auth/user/me"},
		{method: http.MethodGet, path: "/auth/admin/users"},
		{method: http.MethodPost, path: "/auth/admin/users/user-id/sessions/revoke"},
	}

	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			w := httptest.NewRecorder()
			r := httptest.NewRequest(tt.method, tt.path, strings.NewReader(`{}`))
			r.Header.Set("Content-Type", "application/json")
			h.ServeHTTP(w, r)
			require.Equal(t, http.StatusNotFound, w.Code)
		})
	}
}

func TestAPIHandler_SolanaChallenge_InvalidRequest(t *testing.T) {
	s := newTestService(t)
	h := s.APIHandler()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/solana/challenge", strings.NewReader(`{}`))
	r.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(w, r)
	require.Equal(t, http.StatusBadRequest, w.Code)
	require.Contains(t, w.Body.String(), `"code":"address_required"`)
}

func TestAPIHandler_UserBootstrap_RequiresAuth(t *testing.T) {
	s := newTestService(t)
	h := s.APIHandler()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/me/bootstrap", nil)
	h.ServeHTTP(w, r)
	require.Equal(t, http.StatusUnauthorized, w.Code)
	require.Contains(t, w.Body.String(), `"code":"missing_token"`)

	w = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodGet, "/user/bootstrap", nil)
	h.ServeHTTP(w, r)
	require.Equal(t, http.StatusNotFound, w.Code)
}

func TestAPIHandler_AdminAccountsStateRoute_Removed(t *testing.T) {
	s := newTestService(t)
	h := s.APIHandler()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/admin/accounts/state?slug=google", nil)
	h.ServeHTTP(w, r)
	require.Equal(t, http.StatusNotFound, w.Code)
}

func TestAPIHandler_AdminAccountsReserveRoute_Removed(t *testing.T) {
	s := newTestService(t)
	h := s.APIHandler()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/admin/accounts/reserve", strings.NewReader(`{"slug":"google"}`))
	r.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(w, r)
	require.Equal(t, http.StatusNotFound, w.Code)
}

func TestAPIHandler_AdminUsersToggleActiveRoute_Removed(t *testing.T) {
	s := newTestService(t)
	h := s.APIHandler()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/admin/users/toggle-active", strings.NewReader(`{"user_id":"u","banned":true}`))
	r.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(w, r)
	require.Equal(t, http.StatusNotFound, w.Code)
}
