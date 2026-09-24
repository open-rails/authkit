package authhttp

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/open-rails/authkit/authprovider"
	"github.com/open-rails/authkit/embedded"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/stretchr/testify/require"
)

// TestCookieRegistry is the cookie compatibility guard (docs/security/cookies.md).
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
	for _, v := range cookieRegistry {
		registered = append(registered, v.identity())
	}
	require.ElementsMatch(t, golden, registered,
		"cookie variants are append-only: register a changed shape as a new variant and add it to testdata/cookie-registry.golden; never edit or remove one")

	pg := testdb.ScratchPostgres(t)
	for _, secure := range []bool{false, true} {
		t.Run(fmt.Sprintf("secure=%v", secure), func(t *testing.T) {
			cfg := newServerTestConfig()
			cfg.TwoFactor.Mode = embedded.TwoFactorDisabled
			cfg.Frontend.BaseURL = "http://app.example.test"
			if secure {
				cfg.Frontend.BaseURL = "https://app.example.test"
			}
			svc, err := newServer(newServerClient(t, cfg, pg.Pool), WithoutRateLimiter())
			require.NoError(t, err)
			t.Cleanup(svc.Close)
			setTestProviders(svc, authprovider.GitHub("registry-client", "registry-secret"))
			mount, err := MountHandler(svc, MountOptions{RefreshCookie: true})
			require.NoError(t, err)

			email, pass := newCookieTestUser(t, pg.Pool, svc, "registry")
			body, err := json.Marshal(map[string]string{"identifier": email, "password": pass})
			require.NoError(t, err)
			login := mountCatalogRequest(mount, http.MethodPost, DefaultAPIPrefix+"/password/login", string(body), "application/json")
			require.Equal(t, http.StatusOK, login.Code, login.Body.String())
			requireIssued(t, login.Result().Cookies(), currentCookie(cookieRefresh, secure), secure, func(name string) bool {
				return strings.HasSuffix(name, "authkit_rt")
			})

			start := mountCatalogRequest(mount, http.MethodGet, DefaultOIDCPath+"/github/login", "", "")
			require.Equal(t, http.StatusFound, start.Code, start.Body.String())
			requireIssued(t, start.Result().Cookies(), currentCookie(cookieOIDCState, secure), secure, func(name string) bool {
				return strings.Contains(name, oidcStatePrefix)
			})
		})
	}
}

// requireIssued: the response sets exactly one cookie of the kind, shaped as
// the registry's current variant.
func requireIssued(t *testing.T, cookies []*http.Cookie, want cookieVariant, secure bool, ofKind func(string) bool) {
	t.Helper()
	var got []*http.Cookie
	for _, c := range cookies {
		if ofKind(c.Name) {
			got = append(got, c)
		}
	}
	require.Len(t, got, 1)
	c := got[0]
	if want.Kind == cookieOIDCState {
		require.True(t, strings.HasPrefix(c.Name, want.Name), "state cookie %q is not the registry's current %q", c.Name, want.Name)
	} else {
		require.Equal(t, want.Name, c.Name, "refresh cookie name is not the registry's current variant")
	}
	require.Equal(t, want.Path, c.Path, "cookie path is not the registry's current variant")
	require.Equal(t, want.Domain, c.Domain, "cookie domain is not the registry's current variant")
	require.Equal(t, secure, c.Secure)
	require.True(t, c.HttpOnly)
}
