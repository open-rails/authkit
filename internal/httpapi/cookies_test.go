package httpapi_test

import (
	"bufio"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/config"
	"github.com/open-rails/authkit/internal/httpapi"
	"github.com/open-rails/authkit/provider"
)

// TestCookieRegistry is the cookie compatibility guard.
// The cookies AuthKit sets must be the registry's current variants, and the
// registry must match the append-only golden list, so a cookie's name, path,
// domain or prefix cannot change without its old variant staying registered
// (and therefore migrated) for browsers that still hold it.
func TestCookieRegistry(t *testing.T) {
	f, err := os.Open("testdata/cookie-registry.golden")
	require.NoError(t, err)
	defer f.Close()
	var golden, registered []string
	lines := bufio.NewScanner(f)
	for lines.Scan() {
		if line := strings.TrimSpace(lines.Text()); line != "" && !strings.HasPrefix(line, "#") {
			golden = append(golden, line)
		}
	}
	require.NoError(t, lines.Err())
	for _, v := range httpapi.CookieRegistry {
		registered = append(registered, v.Identity())
	}
	require.ElementsMatch(t, golden, registered,
		"cookie variants are append-only: register a changed shape as a new variant and add it to testdata/cookie-registry.golden; never edit or remove one")

	for _, secure := range []bool{false, true} {
		t.Run(fmt.Sprintf("secure=%v", secure), func(t *testing.T) {
			auth, _ := authtest.New(t, authtest.WithConfig(func(c *authkit.Config) {
				c.TwoFactor.Mode = iam.TwoFactorDisabled
				c.Frontend.BaseURL = "http://app.example.test"
				if secure {
					c.Frontend.BaseURL = "https://app.example.test"
				}
				c.HTTP.RefreshCookie = true
			}), authtest.WithDeps(func(d *authkit.Deps) {
				d.Providers = []provider.Provider{provider.GitHub("registry-client", "registry-secret")}
			}))
			u := authtest.NewUser(t, auth)
			serve := func(method, path, body string) *http.Response {
				r := httptest.NewRequest(method, path, strings.NewReader(body))
				r.Header.Set("Content-Type", "application/json")
				w := httptest.NewRecorder()
				auth.Handler().ServeHTTP(w, r)
				return w.Result()
			}

			login := serve(http.MethodPost, config.DefaultAPIPath+config.APIVersion+"/password/login", `{"identifier":"`+u.Email+`","password":"`+u.Password+`"}`)
			require.Equal(t, http.StatusOK, login.StatusCode)
			requireIssued(t, login.Cookies(), httpapi.CurrentCookie(httpapi.CookieRefresh, secure), secure, func(name string) bool {
				return strings.HasSuffix(name, "authkit_rt")
			})

			start := serve(http.MethodGet, httpapi.OIDCPath+"/github/login", "")
			require.Equal(t, http.StatusFound, start.StatusCode)
			requireIssued(t, start.Cookies(), httpapi.CurrentCookie(httpapi.CookieOIDCState, secure), secure, func(name string) bool {
				return strings.Contains(name, httpapi.OIDCStatePrefix)
			})
		})
	}
}

// requireIssued: the response sets exactly one cookie of the kind, shaped as
// the registry's current variant.
func requireIssued(t *testing.T, cookies []*http.Cookie, want httpapi.CookieVariant, secure bool, ofKind func(string) bool) {
	t.Helper()
	var got []*http.Cookie
	for _, c := range cookies {
		if ofKind(c.Name) {
			got = append(got, c)
		}
	}
	require.Len(t, got, 1)
	c := got[0]
	if want.Kind == httpapi.CookieOIDCState {
		require.True(t, strings.HasPrefix(c.Name, want.Name), "state cookie %q is not the registry's current %q", c.Name, want.Name)
	} else {
		require.Equal(t, want.Name, c.Name, "refresh cookie name is not the registry's current variant")
	}
	require.Equal(t, want.Path, c.Path, "cookie path is not the registry's current variant")
	require.Equal(t, want.Domain, c.Domain, "cookie domain is not the registry's current variant")
	require.Equal(t, secure, c.Secure)
	require.True(t, c.HttpOnly)
}
