package apitest_test

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authprovider"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/internal/testidp"
)

// withProviders configures the Client's identity providers.
func withProviders(providers ...authprovider.Provider) authtest.Option {
	return authtest.WithConfig(func(c *authkit.Config) { c.Identity.Providers = providers })
}

// providerFlow is a provider flow a browser started: the IdP authorization
// request and the state cookie bound to that browser.
type providerFlow struct {
	authURL string
	cookies []*http.Cookie
}

// startProviderFlow reads a flow start's answer: a browser redirect, or a
// page's JSON {"auth_url"}.
func startProviderFlow(t *testing.T, res response) providerFlow {
	t.Helper()
	f := providerFlow{authURL: res.header.Get("Location"), cookies: res.cookies}
	if res.status == http.StatusOK {
		var begun struct {
			AuthURL string `json:"auth_url"`
		}
		res.decode(t, &begun)
		f.authURL = begun.AuthURL
	} else {
		require.Equal(t, http.StatusFound, res.status, res.String())
	}
	require.NotEmpty(t, f.authURL)
	return f
}

// callback replays the IdP's redirect to provider's callback, carrying q, in
// the browser that started f. No callback response may be cached.
func (f providerFlow) callback(a *api, provider string, q url.Values) response {
	a.t.Helper()
	jar := &http.Request{Header: http.Header{}}
	for _, c := range f.cookies {
		jar.AddCookie(c)
	}
	res := a.do(request{method: http.MethodGet, path: "//oidc/" + provider + "/callback?" + q.Encode(), header: jar.Header})
	require.Equal(a.t, "no-store", res.header.Get("Cache-Control"))
	return res
}

// callbackFragment is what a browser callback hands the page: the fragment of
// its redirect, which never carries a query.
func callbackFragment(t *testing.T, res response) url.Values {
	t.Helper()
	require.Equal(t, http.StatusFound, res.status, res.String())
	target, err := url.Parse(res.header.Get("Location"))
	require.NoError(t, err)
	require.Empty(t, target.RawQuery)
	fragment, err := url.ParseQuery(target.Fragment)
	require.NoError(t, err)
	return fragment
}

// stateCookieName is the name of the __Host- state cookie an HTTPS
// deployment binds state to: httpapi's OIDCStatePrefix plus
// hex(sha256(state)[:4]).
func stateCookieName(state string) string {
	sum := sha256.Sum256([]byte(state))
	return "__Host-authkit_oauth_state_" + hex.EncodeToString(sum[:4])
}

// The callback refuses a forged state, a state started for another provider,
// a tampered nonce, a code bound to another flow's PKCE challenge and a
// replayed state; only the genuine flow completes, on any replica.
func TestOIDCCallbackStateIsBoundAndSingleUse(t *testing.T) {
	idp, other := testidp.New(t), testidp.New(t)
	auth, _ := authtest.New(t, withProviders(idp.OIDC("custom"), other.OIDC("other")))
	id := testidp.Identity{Subject: "state-subject", Email: "oidc-state@example.com", EmailVerified: true}
	start := func(t *testing.T, a *api) providerFlow { return startProviderFlow(t, a.get("//oidc/custom/login", "")) }
	rejected := func(t *testing.T, res response, code string) {
		t.Helper()
		require.Equal(t, http.StatusFound, res.status, res.String())
		location := res.header.Get("Location")
		require.Contains(t, location, "error="+code, location)
		require.NotContains(t, location, "access_token", location)
	}

	t.Run("forged state with a matching forged cookie", func(t *testing.T) {
		a := newAPI(t, auth)
		genuine := start(t, a)
		require.Len(t, genuine.cookies, 1)
		require.Equal(t, stateCookieName(idp.Authorize(t, genuine.authURL).State), genuine.cookies[0].Name,
			"the forged cookie is named as AuthKit names one")
		forged := "forged-state"
		f := providerFlow{cookies: []*http.Cookie{{Name: stateCookieName(forged), Value: forged}}}
		code := idp.Code(id, testidp.Authorization{State: forged})
		rejected(t, f.callback(a, "custom", url.Values{"state": {forged}, "code": {code}}), "invalid_state")
	})

	t.Run("state started for another provider", func(t *testing.T) {
		a := newAPI(t, auth)
		f := start(t, a)
		q := idp.Redirect(t, f.authURL, id)
		rejected(t, f.callback(a, "other", q), "invalid_state")
		// The failed attempt consumed the state: the real provider cannot use it either.
		rejected(t, f.callback(a, "custom", q), "invalid_state")
	})

	t.Run("nonce mismatch", func(t *testing.T) {
		a := newAPI(t, auth)
		f := start(t, a)
		authz := idp.Authorize(t, f.authURL)
		authz.Nonce = "not-" + authz.Nonce
		rejected(t, f.callback(a, "custom", url.Values{"state": {authz.State}, "code": {idp.Code(id, authz)}}), "oidc_exchange_failed")
	})

	t.Run("code bound to another flow's PKCE challenge", func(t *testing.T) {
		a := newAPI(t, auth)
		victim, attacker := start(t, a), start(t, a)
		authz, stolen := idp.Authorize(t, victim.authURL), idp.Authorize(t, attacker.authURL)
		require.NotEmpty(t, authz.CodeChallenge, "login must start a PKCE flow")
		require.NotEqual(t, authz.CodeChallenge, stolen.CodeChallenge)
		// Everything but the challenge matches the victim's flow, so only the
		// victim's verifier can fail the exchange.
		authz.CodeChallenge = stolen.CodeChallenge
		rejected(t, victim.callback(a, "custom", url.Values{"state": {authz.State}, "code": {idp.Code(id, authz)}}), "oidc_exchange_failed")
	})

	t.Run("genuine flow completes once; replay is rejected", func(t *testing.T) {
		a := newAPI(t, auth)
		f := start(t, a)
		q := idp.Redirect(t, f.authURL, id)
		res := f.callback(a, "custom", q)
		fragment := callbackFragment(t, res)
		require.Empty(t, fragment.Get("error"), res.header.Get("Location"))
		require.NotEmpty(t, fragment.Get("access_token"))
		require.NotContains(t, res.header.Get("Location"), "error=")
		// The replay presents the flow's own state cookie, so only the state
		// store can refuse it: the state is gone.
		rejected(t, f.callback(a, "custom", q), "invalid_state")
	})

	t.Run("state issued by one replica completes on another", func(t *testing.T) {
		replica := authtest.Replica(t, auth, withProviders(idp.OIDC("custom"), other.OIDC("other")))
		a := newAPI(t, auth)
		f := start(t, a)
		q := idp.Redirect(t, f.authURL, id)
		res := f.callback(newAPI(t, replica), "custom", q)
		require.Contains(t, res.header.Get("Location"), "access_token", res.header.Get("Location"))
		rejected(t, f.callback(a, "custom", q), "invalid_state")
	})
}

// An unreachable identity provider fails only its own login with 503
// provider_unavailable; genuine client errors keep their statuses, and logins
// recover without a restart once the provider returns.
func TestOIDCProviderOutageIsServiceUnavailable(t *testing.T) {
	idp := testidp.New(t)
	provider := idp.OIDC("custom")
	auth, _ := authtest.New(t, withProviders(provider))
	a := newAPI(t, auth)
	ctx := t.Context()
	id := testidp.Identity{Subject: "outage-subject", Email: "oidc-outage@example.com", EmailVerified: true}
	start := func() response { return a.get("//oidc/custom/login?format=json", "") }
	callback := func(f providerFlow, authz testidp.Authorization) response {
		return f.callback(a, "custom", url.Values{"state": {authz.State}, "code": {idp.Code(id, authz)}, "format": {"json"}})
	}
	unavailable := func(res response) {
		t.Helper()
		require.Equal(t, http.StatusServiceUnavailable, res.status, res.String())
		require.Equal(t, "provider_unavailable", res.code())
	}
	health := provider.(authprovider.HealthChecker)

	// Discovery unavailable on first use: 503, not 400.
	idp.SetOutage(testidp.Unavailable)
	unavailable(start())
	require.ErrorIs(t, health.CheckHealth(ctx), authprovider.ErrProviderUnavailable)

	// Recovery is background; the next login after it simply works.
	idp.SetOutage(testidp.Up)
	require.Eventually(t, func() bool { return health.CheckHealth(ctx) == nil }, 10*time.Second, 20*time.Millisecond)
	require.Equal(t, http.StatusFound, start().status)

	// Cached discovery keeps logins starting; a token endpoint outage during
	// the exchange is 503, not 401.
	f := startProviderFlow(t, a.get("//oidc/custom/login", ""))
	idp.SetOutage(testidp.Reset)
	require.Equal(t, http.StatusFound, start().status)
	unavailable(callback(f, idp.Authorize(t, f.authURL)))
	idp.SetOutage(testidp.Unavailable)
	f = startProviderFlow(t, a.get("//oidc/custom/login", ""))
	unavailable(callback(f, idp.Authorize(t, f.authURL)))

	// A genuine rejection from a reachable provider keeps its 401.
	idp.SetOutage(testidp.Up)
	f = startProviderFlow(t, a.get("//oidc/custom/login", ""))
	authz := idp.Authorize(t, f.authURL)
	authz.Nonce = "not-" + authz.Nonce
	res := callback(f, authz)
	require.Equal(t, http.StatusUnauthorized, res.status, res.String())
	require.Equal(t, "oidc_exchange_failed", res.code())

	f = startProviderFlow(t, a.get("//oidc/custom/login", ""))
	require.NotEmpty(t, idp.Authorize(t, f.authURL).CodeChallenge)
	require.NotEmpty(t, callbackFragment(t, f.callback(a, "custom", idp.Redirect(t, f.authURL, id))).Get("access_token"))
}

// A browser sign-in returns to the page it started from only when return_to
// is a path on this site; the redirect's fragment omits anything else.
func TestProviderLoginReturnTo(t *testing.T) {
	idp := testidp.New(t)
	auth, _ := authtest.New(t, withProviders(idp.OAuth2("returns")))
	id := testidp.Identity{Subject: "return-to-subject", Email: "return-to@example.com", EmailVerified: true}
	for _, tt := range []struct {
		name string
		in   string
		want string // "" when the fragment carries no return_to
	}{
		{name: "empty", in: "", want: ""},
		{name: "normal path", in: "/subscribe", want: "/subscribe"},
		{name: "path query", in: "/subscribe?plan=pro&coupon=AK", want: "/subscribe?plan=pro&coupon=AK"},
		{name: "absolute", in: "https://evil.example/subscribe", want: ""},
		{name: "scheme relative", in: "//evil.example/subscribe", want: ""},
		{name: "scheme text", in: "javascript:alert(1)", want: ""},
		{name: "backslash", in: `/\evil`, want: ""},
		{name: "crlf", in: "/ok\r\nLocation:https://evil.example", want: ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			a := newAPI(t, auth)
			f := startProviderFlow(t, a.get("//oidc/returns/login?"+url.Values{"return_to": {tt.in}}.Encode(), ""))
			fragment := callbackFragment(t, f.callback(a, "returns", idp.Redirect(t, f.authURL, id)))
			require.NotEmpty(t, fragment.Get("access_token"))
			require.Equal(t, tt.want != "", fragment.Has("return_to"))
			require.Equal(t, tt.want, fragment.Get("return_to"))
		})
	}
}
