package authhttp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/open-rails/authkit/authprovider"
	core "github.com/open-rails/authkit/core"
	oidckit "github.com/open-rails/authkit/oidc"
	"github.com/stretchr/testify/require"
)

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
	var userURL string
	var emailURL string
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
	userURL = ts.URL + "/user"
	emailURL = ts.URL + "/user/emails"

	provider, ok := authprovider.BuiltIn("github")
	require.True(t, ok)
	provider.UserInfoURL = userURL
	provider.EmailFallback.URL = emailURL

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
			UserMapping: authprovider.UserMapping{
				Subject:           authprovider.FieldMapping{Path: "user.id", Transforms: []string{"string"}},
				Email:             authprovider.FieldMapping{Path: "user.email"},
				EmailVerified:     authprovider.FieldMapping{Path: "user.verified"},
				PreferredUsername: authprovider.FieldMapping{Path: "user.handle"},
				DisplayName:       authprovider.FieldMapping{Path: "user.name"},
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

func TestResolveOAuthUser_RegistrationDisabled_BlocksAutoCreate(t *testing.T) {
	s := newTestServiceWithPolicy(t, true, false)
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
	require.ErrorIs(t, err, core.ErrRegistrationDisabled)
	require.False(t, created)
}

func TestResolveOAuthUser_LinkFlow_IgnoresRegistrationDisabled(t *testing.T) {
	s := newTestServiceWithPolicy(t, true, false)
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
