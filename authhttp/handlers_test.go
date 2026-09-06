package authhttp

import (
	"context"
	"crypto"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/open-rails/authkit/verify"

	"github.com/open-rails/authkit/authprovider"
	"github.com/open-rails/authkit/embedded"
	"github.com/open-rails/authkit/jwtkit"
	"github.com/open-rails/authkit/oidckit"
	"github.com/stretchr/testify/require"
)

func newTestCoreService(t *testing.T) *embedded.Client {
	t.Helper()
	signer, err := jwtkit.NewRSASigner(2048, "test-kid")
	require.NoError(t, err)
	ks := embedded.Keyset{Active: signer, PublicKeys: map[string]crypto.PublicKey{"test-kid": signer.PublicKey()}}
	cfg := embedded.Config{
		Token: embedded.TokenConfig{
			Issuer:              "https://example.com",
			IssuedAudiences:     []string{"test-app"},
			ExpectedAudiences:   []string{"test-app"},
			AccessTokenDuration: time.Hour,
		},
		// Tests that use newTestCoreService are not testing registration/verification flows,
		// so we explicitly opt out to avoid needing a real email sender.
		Registration: embedded.RegistrationConfig{Verification: embedded.RegistrationVerificationNone},
	}
	return newCore(t, cfg, ks)
}

func newTestService(t *testing.T) *Service {
	t.Helper()
	return serviceFromCore(t, newTestCoreService(t))
}

// newTestServiceNoBaseOrigin builds a Service whose core has NO frontend base
// origin (non-URL issuer, empty BaseURL), so origin-derived features (passkey
// RP identity) stay unconfigured.
func newTestServiceNoBaseOrigin(t *testing.T) *Service {
	t.Helper()
	signer, err := jwtkit.NewRSASigner(2048, "test-kid")
	require.NoError(t, err)
	ks := embedded.Keyset{Active: signer, PublicKeys: map[string]crypto.PublicKey{"test-kid": signer.PublicKey()}}
	cfg := embedded.Config{
		Token: embedded.TokenConfig{
			Issuer:              "test-app",
			IssuedAudiences:     []string{"test-app"},
			ExpectedAudiences:   []string{"test-app"},
			AccessTokenDuration: time.Hour,
		},
		Registration: embedded.RegistrationConfig{Verification: embedded.RegistrationVerificationNone},
	}
	return serviceFromCore(t, newCore(t, cfg, ks))
}

// newTestServiceWithPasskeys builds a test Service whose core has a passkey
// Relying Party ID configured, so PasskeysEnabled() is true and the /passkeys/*
// routes are mounted.
func newTestServiceWithPasskeys(t *testing.T) *Service {
	t.Helper()
	signer, err := jwtkit.NewRSASigner(2048, "test-kid")
	require.NoError(t, err)
	ks := embedded.Keyset{Active: signer, PublicKeys: map[string]crypto.PublicKey{"test-kid": signer.PublicKey()}}
	opts := embedded.Config{Token: embedded.TokenConfig{Issuer: "https://example.com", IssuedAudiences: []string{"test-app"}, ExpectedAudiences: []string{"test-app"}, AccessTokenDuration: time.Hour}, Registration: embedded.RegistrationConfig{Verification: embedded.RegistrationVerificationNone}, Passkeys: embedded.PasskeyConfig{RPID: "example.com", RPDisplayName: "Example"}}
	return serviceFromCore(t, newCore(t, opts, ks))
}

// newCore is embedded.NewService for tests: a rejected config fails the test.
func newCore(t *testing.T, cfg embedded.Config, ks embedded.Keyset, opts ...coreOpt) *embedded.Client {
	t.Helper()
	svc, err := embedded.NewWithKeys(cfg, ks, depsOf(opts...))
	require.NoError(t, err)
	return svc
}

func serviceFromCore(t *testing.T, coreSvc *embedded.Client) *Service {
	t.Helper()
	cfg := coreSvc.Config()
	ver := verify.NewVerifier(verify.WithSkew(5 * time.Second))
	_ = ver.AddIssuer(cfg.Token.Issuer, cfg.Token.ExpectedAudiences, verify.IssuerOptions{
		RawKeys: coreSvc.PublicKeysByKID(),
	})
	ver.WithService(coreSvc)
	return &Service{svc: coreSvc, verifier: ver}
}

func enableTestOIDCProvider(s *Service) {
	setTestProviders(s, authprovider.Google("google-client", "google-secret"))
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
	h := s.apiHandler()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(`{}`))
	h.ServeHTTP(w, r)
	require.Equal(t, http.StatusBadRequest, w.Code)
	require.Contains(t, w.Body.String(), `"code":"invalid_request"`)
}

func TestAPIHandler_Logout_MissingSidClaim(t *testing.T) {
	s := newTestService(t)
	h := s.apiHandler()

	tok, _, err := s.svc.MintAccessToken(context.Background(), "user", map[string]any{})
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
	enableTestOIDCProvider(s)
	h := s.oidcHandler()

	// Browser navigation: walked back to the frontend with the error fragment.
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/oidc/google/callback", nil)
	h.ServeHTTP(w, r)
	require.Equal(t, http.StatusFound, w.Code)
	require.Contains(t, w.Header().Get("Location"), "error=invalid_request")

	// JSON negotiation keeps the legacy envelope.
	w = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodGet, "/oidc/google/callback", nil)
	r.Header.Set("Accept", "application/json")
	h.ServeHTTP(w, r)
	require.Equal(t, http.StatusBadRequest, w.Code)
	require.Contains(t, w.Body.String(), `"code":"invalid_request"`)
}

func TestOIDCHandler_StepUpCallback_MissingStateOrCode(t *testing.T) {
	s := newTestService(t)
	enableTestOIDCProvider(s)
	h := s.oidcHandler()

	// Pre-state failure: no StepUpReturnTo is recoverable, so the generic
	// frontend error fragment is used.
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/oidc/google/step-up/callback", nil)
	h.ServeHTTP(w, r)
	require.Equal(t, http.StatusFound, w.Code)
	require.Contains(t, w.Header().Get("Location"), "error=invalid_request")

	w = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodGet, "/oidc/google/step-up/callback", nil)
	r.Header.Set("Accept", "application/json")
	h.ServeHTTP(w, r)
	require.Equal(t, http.StatusBadRequest, w.Code)
	require.Contains(t, w.Body.String(), `"code":"invalid_request"`)
}

func TestOIDCHandler_LegacyAuthPathNotMounted(t *testing.T) {
	s := newTestService(t)
	h := s.oidcHandler()

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
	var err error
	s.providers, err = providerRegistry([]authprovider.Provider{
		authprovider.Discord("discord-client", "discord-secret"),
		authprovider.GitHub("github-client", "github-secret"),
		authprovider.OAuth2("custom-oauth", "https://custom.example",
			authprovider.Endpoint{AuthorizeURL: "https://custom.example/oauth/authorize", TokenURL: "https://custom.example/oauth/token"},
			"custom-client", "custom-secret", testUserInfo("https://custom.example/me"),
			authprovider.WithScopes("profile"), authprovider.WithPKCE(true)),
	})
	require.NoError(t, err)
	h := s.oidcHandler()

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

func configureGitHubOAuthForTest(t *testing.T, s *Service) {
	t.Helper()
	var err error
	s.providers, err = providerRegistry([]authprovider.Provider{
		authprovider.GitHub("github-client", "github-secret"),
	})
	require.NoError(t, err)
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

func TestSanitizeReturnTo(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "empty", in: "", want: "/"},
		{name: "normal path", in: "/subscribe", want: "/subscribe"},
		{name: "path query", in: "/subscribe?plan=pro&coupon=AK", want: "/subscribe?plan=pro&coupon=AK"},
		{name: "absolute", in: "https://evil.example/subscribe", want: "/"},
		{name: "scheme relative", in: "//evil.example/subscribe", want: "/"},
		{name: "scheme text", in: "javascript:alert(1)", want: "/"},
		{name: "backslash", in: `/\evil`, want: "/"},
		{name: "crlf", in: "/ok\r\nLocation:https://evil.example", want: "/"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, sanitizeReturnTo(tt.in))
		})
	}
}

func TestBuildAuthResultFragment_ReturnTo(t *testing.T) {
	frag := buildAuthResultFragment("access", "refresh", 60, "google", "state", "/subscribe?plan=pro")
	v, err := url.ParseQuery(strings.TrimPrefix(frag, "#"))
	require.NoError(t, err)
	require.Equal(t, "access", v.Get("access_token"))
	require.Equal(t, "refresh", v.Get("refresh_token"))
	require.Equal(t, "60", v.Get("expires_in"))
	require.Equal(t, "google", v.Get("provider"))
	require.Equal(t, "state", v.Get("state"))
	require.Equal(t, "/subscribe?plan=pro", v.Get("return_to"))

	frag = buildAuthResultFragment("access", "refresh", 60, "google", "state", "https://evil.example/")
	v, err = url.ParseQuery(strings.TrimPrefix(frag, "#"))
	require.NoError(t, err)
	require.Empty(t, v.Get("return_to"))

	frag = buildAuthResultFragment("access", "refresh", 60, "google", "state", "")
	v, err = url.ParseQuery(strings.TrimPrefix(frag, "#"))
	require.NoError(t, err)
	require.Empty(t, v.Get("return_to"))
}

func TestOIDCLoginStoresReturnTo(t *testing.T) {
	s := newTestService(t)
	configureGitHubOAuthForTest(t, s)
	h := s.oidcHandler()
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/oidc/github/login?return_to=%2Fsubscribe%3Fplan%3Dpro", nil)
	h.ServeHTTP(w, r)
	require.Equal(t, http.StatusFound, w.Code)
	loc, err := url.Parse(w.Header().Get("Location"))
	require.NoError(t, err)
	state := loc.Query().Get("state")
	require.NotEmpty(t, state)
	sd, ok, err := s.stateCache().Get(context.Background(), state)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, "/subscribe?plan=pro", sd.ReturnTo)
}

// An off-origin return_to on a real login request is stored as "/": absolute
// URLs, and the "//" and "/\" prefixes browsers read as scheme-relative.
func TestOIDCLoginDropsMaliciousReturnTo(t *testing.T) {
	s := newTestService(t)
	configureGitHubOAuthForTest(t, s)
	h := s.oidcHandler()
	for _, returnTo := range []string{"https://evil.example/", "//evil.example/", `/\evil.example/`} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/oidc/github/login?return_to="+url.QueryEscape(returnTo), nil)
		h.ServeHTTP(w, r)
		require.Equal(t, http.StatusFound, w.Code)
		loc, err := url.Parse(w.Header().Get("Location"))
		require.NoError(t, err)
		state := loc.Query().Get("state")
		require.NotEmpty(t, state)
		sd, ok, err := s.stateCache().Get(context.Background(), state)
		require.NoError(t, err)
		require.True(t, ok)
		require.Equal(t, "/", sd.ReturnTo, returnTo)
	}
}

func TestOIDCCallbackPath_StepUpStartUsesStepUpCallback(t *testing.T) {
	require.Equal(t, "/api/v1/oidc/google/step-up/callback", oidcCallbackPath("/api/v1/oidc/google/step-up/start", "google"))
	require.Equal(t, "/api/v1/oidc/google/callback", oidcCallbackPath("/api/v1/oidc/google/login", "google"))
	require.Equal(t, "/api/v1/oidc/google/callback", oidcCallbackPath("/api/v1/oidc/google/link/start", "google"))
}

func TestOIDCStepUpAuthTimeFreshness(t *testing.T) {
	started := time.Date(2026, 6, 23, 12, 0, 0, 0, time.UTC)
	require.True(t, validOIDCStepUpTime(started, started.Add(time.Second), started.Add(30*time.Second)))
	require.False(t, validOIDCStepUpTime(started, time.Time{}, started.Add(30*time.Second)))
	require.False(t, validOIDCStepUpTime(started, started.Add(-10*time.Minute), started.Add(30*time.Second)))
	require.False(t, validOIDCStepUpTime(started, started.Add(10*time.Minute), started.Add(30*time.Second)))
}

func TestAPIHandler_LegacyAuthPrefixNotMounted(t *testing.T) {
	s := newTestService(t)
	h := s.apiHandler()

	tests := []struct {
		method string
		path   string
	}{
		{method: http.MethodPost, path: "/auth/token"},
		{method: http.MethodGet, path: "/auth/me"},
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
	s := newRouteFeatureTestService(t, func(cfg *embedded.Config) {
		cfg.SolanaNetwork = "devnet"
	})
	h := s.apiHandler()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/solana/challenge", strings.NewReader(`{}`))
	r.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(w, r)
	require.Equal(t, http.StatusBadRequest, w.Code)
	require.Contains(t, w.Body.String(), `"code":"address_required"`)
}

func TestAPIHandler_UserBootstrapRoute_Removed(t *testing.T) {
	s := newTestService(t)
	h := s.apiHandler()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/me/bootstrap", nil)
	h.ServeHTTP(w, r)
	require.Equal(t, http.StatusNotFound, w.Code)

	w = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodGet, "/user/bootstrap", nil)
	h.ServeHTTP(w, r)
	require.Equal(t, http.StatusNotFound, w.Code)
}

func TestAPIHandler_AdminAccountsStateRoute_Removed(t *testing.T) {
	s := newTestService(t)
	h := s.apiHandler()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/admin/accounts/state?slug=google", nil)
	h.ServeHTTP(w, r)
	require.Equal(t, http.StatusNotFound, w.Code)
}

func TestAPIHandler_AdminAccountsReserveRoute_Removed(t *testing.T) {
	s := newTestService(t)
	h := s.apiHandler()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/admin/accounts/reserve", strings.NewReader(`{"slug":"google"}`))
	r.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(w, r)
	require.Equal(t, http.StatusNotFound, w.Code)
}

func TestAPIHandler_AdminUsersToggleActiveRoute_Removed(t *testing.T) {
	s := newTestService(t)

	requireNoRoute(t, s.APIRoutes(RouteAdmin), http.MethodPost, "/admin/users/toggle-active")
}
