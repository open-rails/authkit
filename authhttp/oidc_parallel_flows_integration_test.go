package authhttp

import (
	"context"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// #323: two OIDC flows started in one browser must both complete. The state
// cookie is keyed per flow, so the second start no longer clobbers the first
// flow's cookie. A real cookie jar plays the browser.
func TestParallelOIDCFlowsBothCompleteIntegration(t *testing.T) {
	ctx := context.Background()
	pool := newServerTestPool(t)
	srv, err := NewServer(newServerClient(t, newServerTestConfig(), pool), WithoutRateLimiter())
	require.NoError(t, err)

	idp := newFakeOIDCIdP(t, "parallel-client")
	subject := "parallel-" + uniqueSuffix()
	idp.SetIdentity(subject, uniqueEmail("parallel"), true, nil)
	setTestProviders(srv, idp.Provider("custom"))
	h := srv.oidcHandler()
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE id IN (SELECT user_id FROM profiles.user_providers WHERE issuer=$1 AND subject=$2)`, idp.Server.URL, subject)
	})

	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	site, _ := url.Parse("https://example.com/")

	start := func() (state, nonce string) {
		t.Helper()
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/oidc/custom/login", nil))
		require.Equal(t, http.StatusFound, w.Code, w.Body.String())
		jar.SetCookies(site, w.Result().Cookies())
		authURL, err := url.Parse(w.Header().Get("Location"))
		require.NoError(t, err)
		return authURL.Query().Get("state"), authURL.Query().Get("nonce")
	}
	callback := func(state, nonce string) url.Values {
		t.Helper()
		idp.SetNonce(nonce)
		req := httptest.NewRequest(http.MethodGet, "/oidc/custom/callback?state="+url.QueryEscape(state)+"&code=idp-code", nil)
		for _, c := range jar.Cookies(site) {
			req.AddCookie(c)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		require.Equal(t, http.StatusFound, w.Code, w.Body.String())
		jar.SetCookies(site, w.Result().Cookies())
		target, err := url.Parse(w.Header().Get("Location"))
		require.NoError(t, err)
		frag, err := url.ParseQuery(target.Fragment)
		require.NoError(t, err)
		return frag
	}

	stateA, nonceA := start()
	stateB, nonceB := start()
	require.NotEqual(t, stateA, stateB)
	names := map[string]bool{}
	for _, c := range jar.Cookies(site) {
		if strings.HasPrefix(c.Name, oauthStateCookie) {
			names[c.Name] = true
		}
	}
	require.Len(t, names, 2, "each flow keeps its own state cookie")

	fragA := callback(stateA, nonceA)
	require.Empty(t, fragA.Get("error"))
	require.NotEmpty(t, fragA.Get("access_token"), "first flow must survive the second start")
	fragB := callback(stateB, nonceB)
	require.Empty(t, fragB.Get("error"))
	require.NotEmpty(t, fragB.Get("access_token"))

	// Each callback cleared only its own cookie.
	for _, c := range jar.Cookies(site) {
		require.False(t, strings.HasPrefix(c.Name, oauthStateCookie), "state cookies are single-use: %s", c.Name)
	}
}
