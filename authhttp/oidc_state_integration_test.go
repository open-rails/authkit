package authhttp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/open-rails/authkit/authprovider"
	"github.com/stretchr/testify/require"
)

// oidcFlow drives the browser side of one OIDC login against a fake IdP.
type oidcFlow struct {
	state, nonce, codeChallenge string
	cookies                     []*http.Cookie
}

func startOIDCFlow(t *testing.T, h http.Handler, provider string) oidcFlow {
	t.Helper()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/oidc/"+provider+"/login", nil))
	require.Equal(t, http.StatusFound, w.Code, w.Body.String())
	authURL, err := url.Parse(w.Header().Get("Location"))
	require.NoError(t, err)
	q := authURL.Query()
	return oidcFlow{state: q.Get("state"), nonce: q.Get("nonce"), codeChallenge: q.Get("code_challenge"), cookies: w.Result().Cookies()}
}

// callback replays the IdP redirect with the flow's original cookies and returns
// the redirect Location the browser would follow.
func (f oidcFlow) callback(t *testing.T, h http.Handler, provider, state string) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/oidc/"+provider+"/callback?state="+url.QueryEscape(state)+"&code=idp-code", nil)
	for _, c := range f.cookies {
		req.AddCookie(c)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	require.Equal(t, http.StatusFound, w.Code, w.Body.String())
	return w.Header().Get("Location")
}

// #288/7: on a real pool and both ephemeral stores, the callback must reject a
// forged state, a state started for another provider, a tampered nonce, a
// tampered PKCE verifier, and a replay of an already-consumed state — and only
// the genuine flow completes.
func TestOIDCCallbackStateIsBoundAndSingleUse(t *testing.T) {
	forEachStore(t, testOIDCCallbackStateIsBoundAndSingleUse)
}

func testOIDCCallbackStateIsBoundAndSingleUse(t *testing.T, store ephemeralStore) {
	ctx := context.Background()
	pool := newServerTestPool(t)
	srv, err := NewServer(newServerClient(t, newServerTestConfig(), pool, store.engineOpts()...), WithoutRateLimiter())
	require.NoError(t, err)

	idp := newFakeOIDCIdP(t, "state-client")
	subject := "state-" + uniqueSuffix()
	idp.SetIdentity(subject, uniqueEmail("oidc-state"), true, nil)
	other := newFakeOIDCIdP(t, "other-client")
	setTestProviders(srv, idp.Provider("custom", authprovider.WithPKCE(true)), other.Provider("other"))
	h := srv.oidcHandler()
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE id IN (SELECT user_id FROM profiles.user_providers WHERE issuer=$1 AND subject=$2)`, idp.Server.URL, subject)
	})
	rejected := func(loc string, code ErrorCode) {
		t.Helper()
		require.Contains(t, loc, "error="+string(code), loc)
		require.NotContains(t, loc, "access_token", loc)
	}

	t.Run("forged state with a matching forged cookie", func(t *testing.T) {
		forged := "forged-" + uniqueSuffix()
		f := oidcFlow{cookies: []*http.Cookie{{Name: stateCookieName(forged), Value: forged}}}
		rejected(f.callback(t, h, "custom", forged), ErrInvalidState)
	})

	t.Run("state started for another provider", func(t *testing.T) {
		f := startOIDCFlow(t, h, "custom")
		idp.SetNonce(f.nonce)
		rejected(f.callback(t, h, "other", f.state), ErrInvalidState)
		// The state was consumed by the failed attempt: the real provider cannot use it either.
		rejected(f.callback(t, h, "custom", f.state), ErrInvalidState)
	})

	t.Run("nonce mismatch", func(t *testing.T) {
		f := startOIDCFlow(t, h, "custom")
		idp.SetNonce("not-" + f.nonce)
		rejected(f.callback(t, h, "custom", f.state), ErrOIDCExchangeFailed)
	})

	t.Run("PKCE verifier tampered", func(t *testing.T) {
		f := startOIDCFlow(t, h, "custom")
		require.NotEmpty(t, f.codeChallenge, "login must start a PKCE flow")
		idp.SetNonce(f.nonce)
		idp.ExpectCodeChallenge(f.codeChallenge)
		t.Cleanup(func() { idp.ExpectCodeChallenge("") })
		sd, ok, err := srv.stateCache().Get(ctx, f.state)
		require.NoError(t, err)
		require.True(t, ok)
		sd.Verifier = "tampered-" + sd.Verifier
		require.NoError(t, srv.stateCache().Put(ctx, f.state, sd))
		rejected(f.callback(t, h, "custom", f.state), ErrOIDCExchangeFailed)
	})

	t.Run("genuine flow completes once; replay is rejected", func(t *testing.T) {
		f := startOIDCFlow(t, h, "custom")
		idp.SetNonce(f.nonce)
		idp.ExpectCodeChallenge(f.codeChallenge)
		t.Cleanup(func() { idp.ExpectCodeChallenge("") })
		loc := f.callback(t, h, "custom", f.state)
		target, err := url.Parse(loc)
		require.NoError(t, err)
		frag, err := url.ParseQuery(target.Fragment)
		require.NoError(t, err)
		require.Empty(t, frag.Get("error"), loc)
		require.NotEmpty(t, frag.Get("access_token"), loc)
		require.False(t, strings.Contains(loc, "error="), loc)

		rejected(f.callback(t, h, "custom", f.state), ErrInvalidState)
		_, ok, err := srv.stateCache().Get(ctx, f.state)
		require.NoError(t, err)
		require.False(t, ok, "consumed state must be gone from the store")
	})
}
