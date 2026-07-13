package authhttp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/open-rails/authkit/authprovider"
	"github.com/stretchr/testify/require"
)

func TestOAuthBrowserLoginCallbackPreservesReturnToIntegration(t *testing.T) {
	ctx := context.Background()
	pool := newServerTestPool(t)
	srv, err := NewServer(newServerClient(t, newServerTestConfig(), pool), WithoutRateLimiter())
	require.NoError(t, err)

	email := uniqueEmail("oauth-return-to")
	subject := "oauth-return-to-" + uniqueSuffix()
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE email=$1`, email)
	})

	var sawTokenExchange bool
	var sawUserInfo bool
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			require.Equal(t, http.MethodPost, r.Method)
			require.NoError(t, r.ParseForm())
			require.Equal(t, "authorization_code", r.Form.Get("grant_type"))
			require.Equal(t, "oauth-code", r.Form.Get("code"))
			require.Equal(t, "oauth-client", r.Form.Get("client_id"))
			require.Equal(t, "oauth-secret", r.Form.Get("client_secret"))
			sawTokenExchange = true
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": "provider-access-token",
				"token_type":   "Bearer",
			})
		case "/me":
			require.Equal(t, "Bearer provider-access-token", r.Header.Get("Authorization"))
			sawUserInfo = true
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":             subject,
				"email":          email,
				"email_verified": true,
				"login":          "oauthreturnto",
				"name":           "OAuth Return To",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(provider.Close)

	srv.authProvidersByName = map[string]authprovider.Provider{
		"example-oauth": {
			Name:         "example-oauth",
			Kind:         authprovider.KindOAuth2,
			Issuer:       provider.URL,
			ClientID:     "oauth-client",
			ClientSecret: authprovider.ClientSecret{Value: "oauth-secret"},
			Scopes:       []string{"profile", "email"},
			AuthorizeURL: provider.URL + "/authorize",
			TokenURL:     provider.URL + "/token",
			UserInfoURL:  provider.URL + "/me",
			IdentityMapper: func(root any) (authprovider.Identity, error) {
				m, _ := root.(map[string]any)
				id, _ := m["id"].(string)
				email, _ := m["email"].(string)
				verified, _ := m["email_verified"].(bool)
				login, _ := m["login"].(string)
				name, _ := m["name"].(string)
				return authprovider.Identity{
					Subject:           id,
					Email:             email,
					EmailVerified:     verified,
					PreferredUsername: login,
					DisplayName:       name,
				}, nil
			},
		},
	}
	srv.resetOIDCManagerForTest()
	h := srv.OIDCHandler()

	start := httptest.NewRecorder()
	startReq := httptest.NewRequest(http.MethodGet, "/oidc/example-oauth/login?return_to=%2Fsubscribe%3Fplan%3Dpro", nil)
	h.ServeHTTP(start, startReq)
	require.Equal(t, http.StatusFound, start.Code, start.Body.String())

	authURL, err := url.Parse(start.Header().Get("Location"))
	require.NoError(t, err)
	require.Equal(t, provider.URL+"/authorize", authURL.Scheme+"://"+authURL.Host+authURL.Path)
	state := authURL.Query().Get("state")
	require.NotEmpty(t, state)
	require.Equal(t, "oauth-client", authURL.Query().Get("client_id"))

	var stateCookie *http.Cookie
	for _, cookie := range start.Result().Cookies() {
		if cookie.Name == oauthStateCookie {
			stateCookie = cookie
			break
		}
	}
	require.NotNil(t, stateCookie)

	callback := httptest.NewRecorder()
	callbackReq := httptest.NewRequest(http.MethodGet, "/oidc/example-oauth/callback?state="+url.QueryEscape(state)+"&code=oauth-code", nil)
	callbackReq.AddCookie(stateCookie)
	h.ServeHTTP(callback, callbackReq)
	require.Equal(t, http.StatusFound, callback.Code, callback.Body.String())
	require.Equal(t, "no-store", callback.Header().Get("Cache-Control"), "token-bearing redirect must never be cached (RFC 6749 §5.1)")
	require.True(t, sawTokenExchange)
	require.True(t, sawUserInfo)

	target, err := url.Parse(callback.Header().Get("Location"))
	require.NoError(t, err)
	require.Equal(t, "/login/callback", target.Path)
	fragment, err := url.ParseQuery(target.Fragment)
	require.NoError(t, err)
	require.NotEmpty(t, fragment.Get("access_token"))
	require.NotEmpty(t, fragment.Get("refresh_token"))
	require.Equal(t, "example-oauth", fragment.Get("provider"))
	require.Equal(t, "/subscribe?plan=pro", fragment.Get("return_to"))
}
