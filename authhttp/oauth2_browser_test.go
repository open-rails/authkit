package authhttp

import (
	"crypto"
	"encoding/json"
	"fmt"
	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/verify"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/open-rails/authkit/authprovider"
	"github.com/open-rails/authkit/embedded"
	authcore "github.com/open-rails/authkit/internal/authcore"
	"github.com/open-rails/authkit/jwtkit"
	"github.com/open-rails/authkit/oidckit"
	"github.com/stretchr/testify/require"
)

// newRegistrationModeService builds an http.Service whose core Options carry the
// native-user registration mode under test. No DB; the registration-disabled
// gate fires before any storage call (a nil pool returns empty, not an error).
func newRegistrationModeService(t *testing.T, nativeMode embedded.RegistrationMode) *Service {
	t.Helper()
	signer, err := jwtkit.NewRSASigner(2048, "test-kid")
	require.NoError(t, err)
	ks := authcore.Keyset{Active: signer, PublicKeys: map[string]crypto.PublicKey{"test-kid": signer.PublicKey()}}
	opts := embedded.Config{Token: embedded.TokenConfig{Issuer: "https://example.com", IssuedAudiences: []string{"test-app"}, ExpectedAudiences: []string{"test-app"}, AccessTokenDuration: time.Hour}, Registration: embedded.RegistrationConfig{Verification: embedded.RegistrationVerificationNone, NativeUserMode: nativeMode}}
	coreSvc := authcore.NewService(opts, ks)
	ver := verify.NewVerifier(verify.WithSkew(5 * time.Second))
	_ = ver.AddIssuer(opts.Token.Issuer, opts.Token.ExpectedAudiences, verify.IssuerOptions{
		RawKeys: coreSvc.PublicKeysByKID(),
	})
	ver.WithService(coreSvc)
	return &Service{svc: coreSvc, verifier: ver}
}

func TestExchangeOAuthCodeSendsGitHubPKCEVerifier(t *testing.T) {
	s := newTestService(t)
	var gotVerifier string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "application/json", r.Header.Get("Accept"))
		require.NoError(t, r.ParseForm())
		require.Equal(t, "client-id", r.Form.Get("client_id"))
		require.Equal(t, "client-secret", r.Form.Get("client_secret"))
		require.Equal(t, "authorization_code", r.Form.Get("grant_type"))
		require.Equal(t, "oauth-code", r.Form.Get("code"))
		require.Equal(t, "https://auth.example/oidc/github/callback", r.Form.Get("redirect_uri"))
		gotVerifier = r.Form.Get("code_verifier")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "github-access-token",
			"token_type":   "bearer",
			"scope":        "read:user,user:email",
		})
	}))
	defer ts.Close()

	token, err := s.exchangeOAuthCode(
		httptest.NewRequest(http.MethodGet, "/", nil),
		authprovider.Provider{Name: "github", TokenURL: ts.URL, PKCE: true},
		"client-id",
		"client-secret",
		"oauth-code",
		"https://auth.example/oidc/github/callback",
		"pkce-verifier",
	)
	require.NoError(t, err)
	require.Equal(t, "github-access-token", token.AccessToken)
	require.Equal(t, "bearer", token.TokenType)
	require.Equal(t, "pkce-verifier", gotVerifier)
}

func TestFetchGitHubUserInfoUsesNumericIDAndVerifiedPrimaryEmail(t *testing.T) {
	s := newTestService(t)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "bearer github-access-token", r.Header.Get("Authorization"))
		require.Equal(t, "application/vnd.github+json", r.Header.Get("Accept"))
		switch r.URL.Path {
		case "/user":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":    12345,
				"login": "octocat",
				"name":  "Mona Lisa",
				"email": "",
			})
		case "/user/emails":
			_ = json.NewEncoder(w).Encode([]map[string]any{
				{"email": "secondary@example.com", "primary": false, "verified": true},
				{"email": "octocat@example.com", "primary": true, "verified": true},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	provider, ok := authprovider.BuiltIn("github")
	require.True(t, ok)
	provider.UserInfoURL = ts.URL + "/user"
	provider.EmailFallbackURL = ts.URL + "/user/emails"

	info, err := s.fetchOAuthUserInfo(
		httptest.NewRequest(http.MethodGet, "/", nil),
		provider,
		oauth2TokenResp{AccessToken: "github-access-token", TokenType: "bearer"},
	)
	require.NoError(t, err)
	require.Equal(t, "12345", info.Subject)
	require.Equal(t, "octocat@example.com", info.Email)
	require.True(t, info.EmailVerified)
	require.Equal(t, "octocat", info.Preferred)
	require.Equal(t, "Mona Lisa", info.Display)
}

func TestFetchOAuthUserInfoUsesCustomDescriptorMapping(t *testing.T) {
	s := newTestService(t)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "Bearer descriptor-token", r.Header.Get("Authorization"))
		_ = json.NewEncoder(w).Encode(map[string]any{
			"user": map[string]any{
				"id":       9876,
				"email":    "mapped@example.com",
				"verified": true,
				"handle":   "mapped-user",
				"name":     "Mapped User",
			},
		})
	}))
	defer ts.Close()

	info, err := s.fetchOAuthUserInfo(
		httptest.NewRequest(http.MethodGet, "/", nil),
		authprovider.Provider{
			Name:        "mapped",
			Kind:        authprovider.KindOAuth2,
			Issuer:      "https://mapped.example",
			UserInfoURL: ts.URL,
			IdentityMapper: func(root any) (authprovider.Identity, error) {
				m, _ := root.(map[string]any)
				u, _ := m["user"].(map[string]any)
				email, _ := u["email"].(string)
				verified, _ := u["verified"].(bool)
				handle, _ := u["handle"].(string)
				name, _ := u["name"].(string)
				return authprovider.Identity{
					Subject:           strings.TrimSpace(fmt.Sprint(u["id"])),
					Email:             email,
					EmailVerified:     verified,
					PreferredUsername: handle,
					DisplayName:       name,
				}, nil
			},
		},
		oauth2TokenResp{AccessToken: "descriptor-token", TokenType: "Bearer"},
	)
	require.NoError(t, err)
	require.Equal(t, "9876", info.Subject)
	require.Equal(t, "mapped@example.com", info.Email)
	require.True(t, info.EmailVerified)
	require.Equal(t, "mapped-user", info.Preferred)
	require.Equal(t, "Mapped User", info.Display)
}

// Auto-create (a public-registration path) is blocked when native-user
// registration is disabled. No DB: the disabled gate fires after the (empty)
// provider-link + email lookups.
func TestResolveOAuthUser_RegistrationDisabled_BlocksAutoCreate(t *testing.T) {
	s := newRegistrationModeService(t, embedded.RegistrationModeClosed)
	cfg := authprovider.Provider{
		Name:   "github",
		Kind:   authprovider.KindOAuth2,
		Issuer: "https://github.com/login/oauth",
	}
	info := oauth2UserInfo{
		Subject:       "brand-new-subject",
		Email:         "newuser@example.com",
		EmailVerified: true,
	}
	_, created, err := s.resolveOAuthUser(
		httptest.NewRequest(http.MethodGet, "/", nil),
		cfg,
		oidckit.StateData{},
		info,
	)
	require.ErrorIs(t, err, authkit.ErrRegistrationDisabled)
	require.False(t, created)
}

// The explicit link flow (StateData.LinkUserID set) is NOT a registration path,
// so it is unaffected by the registration-disabled gate.
func TestResolveOAuthUser_LinkFlow_IgnoresRegistrationDisabled(t *testing.T) {
	s := newRegistrationModeService(t, embedded.RegistrationModeClosed)
	cfg := authprovider.Provider{
		Name:   "github",
		Kind:   authprovider.KindOAuth2,
		Issuer: "https://github.com/login/oauth",
	}
	info := oauth2UserInfo{Subject: "linked-subject", Email: "linked@example.com"}
	uid, created, err := s.resolveOAuthUser(
		httptest.NewRequest(http.MethodGet, "/", nil),
		cfg,
		oidckit.StateData{LinkUserID: "user-123"},
		info,
	)
	require.NoError(t, err)
	require.Equal(t, "user-123", uid)
	require.False(t, created)
}

// TestOAuthCallback_MissingStateOrCode exercises the browser callback
// entrypoint's request-validation gate through the real router (no DB): a
// browser navigation is walked back to the frontend with the error in the
// fragment, while a JSON caller keeps the legacy envelope.
func TestOAuthCallback_MissingStateOrCode(t *testing.T) {
	s := newTestService(t)
	// Register a github OAuth2 provider so the callback resolves past the
	// unknown-provider check and reaches the state/code validation.
	var err error
	s.authProvidersByName, err = buildAuthProvidersMap([]authprovider.Provider{
		authprovider.GitHub("github-client", "github-secret"),
	})
	require.NoError(t, err)
	s.resetOIDCManagerForTest()
	h := s.OIDCHandler()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/oidc/github/callback", nil)
	h.ServeHTTP(w, r)
	require.Equal(t, http.StatusFound, w.Code)
	target, err := url.Parse(w.Header().Get("Location"))
	require.NoError(t, err)
	require.Equal(t, "/login/callback", target.Path)
	fragment, err := url.ParseQuery(target.Fragment)
	require.NoError(t, err)
	require.Equal(t, "invalid_request", fragment.Get("error"))
	require.Equal(t, "login", fragment.Get("flow"))

	w = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodGet, "/oidc/github/callback", nil)
	r.Header.Set("Accept", "application/json")
	h.ServeHTTP(w, r)
	require.Equal(t, http.StatusBadRequest, w.Code)
	require.Contains(t, w.Body.String(), `"code":"invalid_request"`)
}
