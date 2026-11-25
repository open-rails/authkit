package critical_test

import (
	"errors"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/testidp"
	"github.com/open-rails/authkit/provider"
)

// TestCriticalProviderSignIn signs in through an OpenID Provider on a local
// TLS server (discovery, JWKS, a token endpoint issuing signed ID tokens),
// as a browser does: start, the IdP's redirect back, the callback, and the
// one-time code the SPA trades for its session.
func TestCriticalProviderSignIn(t *testing.T) {
	idp := testidp.New(t)
	f := newFixture(t, authtest.WithDeps(func(d *authkit.Deps) { d.Providers = []provider.Provider{idp.OIDC("idp")} }))
	client := &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	// start begins a sign-in in a browser: the IdP URL it is sent to and the
	// state cookie it now holds.
	start := func(t *testing.T) (string, []*http.Cookie) {
		t.Helper()
		r := f.call(t, "POST", "/oidc/idp/login/start", "", map[string]string{"return_to": "/"})
		r.want(t, http.StatusOK, "")
		var out struct {
			AuthURL string `json:"auth_url"`
		}
		decode(t, r.body, &out)
		cookies := (&http.Response{Header: r.header}).Cookies()
		if out.AuthURL == "" || len(cookies) == 0 {
			t.Fatalf("start answered %s with cookies %v", r.body, cookies)
		}
		return out.AuthURL, cookies
	}
	// callback is the browser following the IdP's redirect back, holding
	// cookies; asJSON asks for the result instead of a redirect.
	callback := func(t *testing.T, query url.Values, cookies []*http.Cookie, asJSON bool) response {
		t.Helper()
		r, err := http.NewRequestWithContext(t.Context(), http.MethodGet, f.server.URL+"/oidc/idp/callback?"+query.Encode(), nil)
		noError(t, err)
		for _, c := range cookies {
			r.AddCookie(&http.Cookie{Name: c.Name, Value: c.Value})
		}
		if asJSON {
			r.Header.Set("Accept", "application/json")
		}
		return wire(t, client, r.Method, r.URL.String(), "", "", "", r.Header)
	}
	signedIn := func(t *testing.T, r response, email string) iam.TokenSet {
		t.Helper()
		r.want(t, http.StatusOK, "")
		var result signInResult
		decode(t, r.body, &result)
		if result.Status != "complete" || result.Tokens == nil || result.User == nil || result.User.Email == nil || *result.User.Email != email {
			t.Fatalf("provider sign-in answered %s", r.body)
		}
		f.call(t, "PATCH", "/me", result.Tokens.AccessToken, map[string]string{"preferred_language": "en"}).want(t, http.StatusOK, "")
		return *result.Tokens
	}
	person := testidp.Identity{Subject: "idp-person", Email: "idp-person@example.com", EmailVerified: true, Username: "idpperson"}

	t.Run("AK-J45-C01_a_provider_sign_in_completes_through_the_callback_and_a_one_time_code", func(t *testing.T) {
		authURL, cookies := start(t)
		query := idp.Redirect(t, authURL, person)
		r := callback(t, query, cookies, false)
		r.want(t, http.StatusFound, "")
		location, err := url.Parse(r.header.Get("Location"))
		noError(t, err)
		fragment, err := url.ParseQuery(location.Fragment)
		noError(t, err)
		if fragment.Get("code") == "" || fragment.Get("state") != query.Get("state") {
			t.Fatalf("callback redirected to %s", location)
		}
		first := signedIn(t, f.call(t, "POST", "/oidc/exchange", "", map[string]string{"code": fragment.Get("code")}), person.Email)
		f.call(t, "POST", "/oidc/exchange", "", map[string]string{"code": fragment.Get("code")}).expect(t, http.StatusBadRequest, "invalid_state")
		// The same identity signs in to the same account.
		authURL, cookies = start(t)
		again := signedIn(t, callback(t, idp.Redirect(t, authURL, person), cookies, true), person.Email)
		a, err := verifyToken(t, f.auth, first.AccessToken)
		noError(t, err)
		b, err := verifyToken(t, f.auth, again.AccessToken)
		noError(t, err)
		if a.UserID == "" || a.UserID != b.UserID {
			t.Fatalf("one identity signed in as %q and %q", a.UserID, b.UserID)
		}
	})

	t.Run("AK-J45-C02_a_callback_completes_only_in_the_browser_that_started_it_and_once", func(t *testing.T) {
		// Each refusal is its own flow: none spends another's state.
		authURL, _ := start(t)
		_, otherCookies := start(t)
		callback(t, idp.Redirect(t, authURL, person), otherCookies, true).expect(t, http.StatusBadRequest, "invalid_state")
		authURL, _ = start(t)
		callback(t, idp.Redirect(t, authURL, person), nil, true).expect(t, http.StatusBadRequest, "invalid_state")
		authURL, cookies := start(t)
		query := idp.Redirect(t, authURL, person)
		forged := url.Values{"state": {"forged-" + query.Get("state")}, "code": query["code"]}
		callback(t, forged, cookies, true).expect(t, http.StatusBadRequest, "invalid_state")
		// The browser that started it completes it, once.
		signedIn(t, callback(t, query, cookies, true), person.Email)
		callback(t, query, cookies, true).expect(t, http.StatusBadRequest, "invalid_state")
	})

	t.Run("AK-J45-C03_an_ID_token_for_another_sign_in's_nonce_is_refused", func(t *testing.T) {
		stranger := testidp.Identity{Subject: "idp-nonce-stranger", Email: "idp-nonce-stranger@example.com", EmailVerified: true}
		authURL, cookies := start(t)
		request := idp.Authorize(t, authURL)
		replayed := request
		replayed.Nonce = "another sign-in's nonce"
		r := callback(t, url.Values{"state": {request.State}, "code": {idp.Code(stranger, replayed)}}, cookies, true)
		r.expect(t, http.StatusUnauthorized, "oidc_exchange_failed")
		if _, err := f.auth.User(t.Context(), iam.UserByEmail(stranger.Email)); !errors.Is(err, iam.ErrUserNotFound) {
			t.Errorf("a refused ID token made an account: %v", err)
		}
		// The same flow with its own nonce signs in.
		authURL, cookies = start(t)
		signedIn(t, callback(t, idp.Redirect(t, authURL, stranger), cookies, true), stranger.Email)
	})
}
