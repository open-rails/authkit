package httpapi_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/httpapi"
	"github.com/stretchr/testify/require"
)

func TestRefreshCookiesIsolateIssuersInOneBrowser(t *testing.T) {
	const issuerA, issuerB = "http://issuer-a.test", "http://issuer-b.test"
	a, _ := authtest.New(t, authtest.WithConfig(func(c *authkit.Config) {
		c.Token.Issuer = issuerA
		c.TwoFactor.Mode = iam.TwoFactorDisabled
		c.Frontend.BaseURL = "http://127.0.0.1"
		c.HTTP.RefreshCookie = true
	}))
	b := authtest.Replica(t, a, authtest.WithConfig(func(c *authkit.Config) { c.Token.Issuer = issuerB }))
	user := authtest.NewUser(t, a)
	sa, sb := httptest.NewServer(a.Handler()), httptest.NewServer(b.Handler())
	t.Cleanup(sa.Close)
	t.Cleanup(sb.Close)
	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	client := &http.Client{Jar: jar}
	call := func(base, method, path string, body any, bearer string, status int) (httpapi.AuthResult, []*http.Cookie) {
		t.Helper()
		raw, err := json.Marshal(body)
		require.NoError(t, err)
		req, err := http.NewRequest(method, base+"/api/v1"+path, bytes.NewReader(raw))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		res, err := client.Do(req)
		require.NoError(t, err)
		defer res.Body.Close()
		data, err := io.ReadAll(res.Body)
		require.NoError(t, err)
		require.Equal(t, status, res.StatusCode, string(data))
		var out httpapi.AuthResult
		if status == http.StatusOK {
			require.NoError(t, json.Unmarshal(data, &out))
		}
		return out, res.Cookies()
	}
	credentials := map[string]string{"identifier": user.Email, "password": user.Password}
	call(sa.URL, "POST", "/password/login", credentials, "", 200)
	call(sb.URL, "POST", "/password/login", credentials, "", 200)
	ua, _ := url.Parse(sa.URL)
	ub, _ := url.Parse(sb.URL)
	for _, name := range []string{httpapi.IssuerRefreshCookieName(issuerA, false), httpapi.IssuerRefreshCookieName(issuerB, false)} {
		found := false
		for _, c := range jar.Cookies(ua) {
			found = found || c.Name == name
		}
		require.True(t, found, "same-host jar lost %s", name)
	}
	refresh := map[string]string{"grant_type": "refresh_token"}
	first, _ := call(sa.URL, "POST", "/token", refresh, "", 200)
	second, _ := call(sb.URL, "POST", "/token", refresh, "", 200)
	require.Equal(t, user.ID, first.User.ID)
	require.Equal(t, user.ID, second.User.ID)
	call(sa.URL, "DELETE", "/logout", nil, first.TokenSet.AccessToken, 204)
	call(sb.URL, "POST", "/token", refresh, "", 200)
	call(sa.URL, "POST", "/token", refresh, "", 401)

	// A legacy cookie belonging to B survives A's rejection, login and logout.
	var bCookie *http.Cookie
	for _, c := range jar.Cookies(ub) {
		if c.Name == httpapi.IssuerRefreshCookieName(issuerB, false) {
			bCookie = c
		}
	}
	require.NotNil(t, bCookie)
	jar.SetCookies(ua, []*http.Cookie{{Name: iam.InsecureRefreshCookieName, Value: bCookie.Value, Path: "/"}})
	call(sa.URL, "POST", "/token", refresh, "", 401)
	login, _ := call(sa.URL, "POST", "/password/login", credentials, "", 200)
	call(sa.URL, "DELETE", "/logout", nil, login.TokenSet.AccessToken, 204)
	var legacy *http.Cookie
	for _, c := range jar.Cookies(ua) {
		if c.Name == iam.InsecureRefreshCookieName {
			legacy = c
		}
	}
	require.NotNil(t, legacy, "A deleted B's legacy refresh cookie")
	require.Equal(t, bCookie.Value, legacy.Value)
	// B can consume its legacy cookie, issue the new name and retire only it.
	jar.SetCookies(ub, []*http.Cookie{{Name: bCookie.Name, Path: "/", MaxAge: -1}})
	call(sb.URL, "POST", "/token", refresh, "", 200)
	for _, c := range jar.Cookies(ub) {
		require.NotEqual(t, iam.InsecureRefreshCookieName, c.Name)
	}
}

func TestRefreshCookieExplicitName(t *testing.T) {
	a, _ := authtest.New(t, authtest.WithConfig(func(c *authkit.Config) {
		c.TwoFactor.Mode = iam.TwoFactorDisabled
		c.Frontend.BaseURL = "http://127.0.0.1"
		c.HTTP.RefreshCookie, c.HTTP.RefreshCookieName = true, "intentional-shared-session"
	}))
	u := authtest.NewUser(t, a)
	req := httptest.NewRequest("POST", "/api/v1/password/login", strings.NewReader(`{"identifier":"`+u.Email+`","password":"`+u.Password+`"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var found bool
	for _, c := range w.Result().Cookies() {
		if c.Name == "intentional-shared-session" {
			found = true
		}
	}
	require.True(t, found)
}
