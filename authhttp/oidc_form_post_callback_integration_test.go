package authhttp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/open-rails/authkit/authprovider"
	"github.com/open-rails/authkit/embedded"
)

// #295: a response_mode=form_post provider (Apple) returns code/state as a
// cross-site POST. The real OIDC routes must complete that POST with a
// SameSite=None; Secure state cookie, reject it without the cookie, and leave
// every other provider on the Lax cookie.
func TestOIDCFormPostCallbackIntegration(t *testing.T) {
	ctx := context.Background()
	pool := newServerTestPool(t)
	cfg := newServerTestConfig()
	cfg.Frontend.BaseURL = "https://auth.example"
	srv, err := NewServer(newServerClient(t, cfg, pool), WithoutRateLimiter())
	require.NoError(t, err)

	idp := newFakeOIDCIdP(t, "idp-client")
	subject := "apple-" + uniqueSuffix()
	idp.SetIdentity(subject, uniqueEmail("apple"), true, nil)
	apple := idp.Provider("apple")
	apple.ExtraAuthParams = map[string]string{"response_mode": "form_post"}
	srv.authProvidersByName = map[string]authprovider.Provider{
		"apple":  apple,
		"google": idp.Provider("google"),
	}
	srv.resetOIDCManagerForTest()
	h := srv.OIDCHandler()
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE id IN (SELECT user_id FROM profiles.user_providers WHERE issuer=$1 AND subject=$2)`, idp.Server.URL, subject)
	})

	startFlow := func(provider string) (state string, cookie *http.Cookie) {
		t.Helper()
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/oidc/"+provider+"/login", nil))
		require.Equal(t, http.StatusFound, w.Code, w.Body.String())
		authURL, err := url.Parse(w.Header().Get("Location"))
		require.NoError(t, err)
		idp.SetNonce(authURL.Query().Get("nonce"))
		state = authURL.Query().Get("state")
		for _, c := range w.Result().Cookies() {
			if c.Name == stateCookieName(state) {
				cookie = c
			}
		}
		require.NotNil(t, cookie)
		if provider == "apple" {
			require.Equal(t, "form_post", authURL.Query().Get("response_mode"))
		}
		return state, cookie
	}
	postCallback := func(state string, cookie *http.Cookie) *httptest.ResponseRecorder {
		t.Helper()
		form := url.Values{"code": {"idp-code"}, "state": {state}}
		req := httptest.NewRequest(http.MethodPost, "/oidc/apple/callback", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if cookie != nil {
			req.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w
	}

	// form_post provider: SameSite=None; Secure cookie, POST callback succeeds.
	state, cookie := startFlow("apple")
	require.Equal(t, http.SameSiteNoneMode, cookie.SameSite)
	require.True(t, cookie.Secure)
	require.True(t, cookie.HttpOnly)

	w := postCallback(state, cookie)
	require.Equal(t, http.StatusFound, w.Code, w.Body.String())
	require.Equal(t, "no-store", w.Header().Get("Cache-Control"))
	target, err := url.Parse(w.Header().Get("Location"))
	require.NoError(t, err)
	require.Equal(t, "auth.example", target.Host)
	frag, err := url.ParseQuery(target.Fragment)
	require.NoError(t, err)
	require.Empty(t, frag.Get("error"), target.String())
	require.NotEmpty(t, frag.Get("access_token"))
	require.Equal(t, "apple", frag.Get("provider"))
	require.Equal(t, state, frag.Get("state"))

	// Same POST without the browser's state cookie is login CSRF: refused, state untouched.
	state, _ = startFlow("apple")
	w = postCallback(state, nil)
	require.Equal(t, http.StatusFound, w.Code, w.Body.String())
	require.Equal(t, "no-store", w.Header().Get("Cache-Control"))
	target, err = url.Parse(w.Header().Get("Location"))
	require.NoError(t, err)
	frag, err = url.ParseQuery(target.Fragment)
	require.NoError(t, err)
	require.Equal(t, string(ErrInvalidState), frag.Get("error"))
	require.Empty(t, frag.Get("access_token"))

	// Non-form_post providers keep the Lax cookie: the GET path is not weakened.
	_, cookie = startFlow("google")
	require.Equal(t, http.SameSiteLaxMode, cookie.SameSite)
	require.True(t, cookie.Secure)
}

// A form_post provider needs a SameSite=None; Secure cookie, which browsers only
// send over HTTPS: NewServer refuses the configuration on a non-HTTPS deployment
// instead of shipping a login that can never complete.
func TestNewServerRefusesFormPostWithoutHTTPS(t *testing.T) {
	base := func() embedded.Config {
		cfg := newServerTestConfig()
		cfg.Identity = embedded.IdentityConfig{Providers: []authprovider.Provider{authprovider.Apple("apple-client", "apple-secret")}}
		return cfg
	}

	// Explicit http BaseURL.
	cfg := base()
	cfg.Frontend.BaseURL = "http://auth.example"
	_, err := NewServer(newServerClient(t, cfg, newNoDBPool(t)))
	require.Error(t, err)
	require.Contains(t, err.Error(), "form_post")

	// BaseURL defaulted from an http issuer.
	cfg = base()
	cfg.Token.Issuer = "http://auth.example"
	_, err = NewServer(newServerClient(t, cfg, newNoDBPool(t)))
	require.Error(t, err)
	require.Contains(t, err.Error(), "form_post")

	cfg = base()
	cfg.Frontend.BaseURL = "https://auth.example"
	_, err = NewServer(newServerClient(t, cfg, newNoDBPool(t)))
	require.NoError(t, err)
}
