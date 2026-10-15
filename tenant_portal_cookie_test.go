package authkit_test

import (
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/httpapi"
	"github.com/stretchr/testify/require"
)

func TestTenantPortalRefreshUsesHintOnlyWithLiveCookieProof(t *testing.T) {
	shared, _ := authtest.New(t, authtest.WithConfig(func(c *authkit.Config) {
		c.DefaultTenantID = iam.TenantID{}
		c.TwoFactor.Mode = iam.TwoFactorDisabled
		c.HTTP.RefreshCookie = true
		c.Frontend.BaseURL = "http://127.0.0.1"
	}))
	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	portal := httptest.NewServer(shared.Handler())
	t.Cleanup(portal.Close)
	portal.Client().Jar = jar
	views := make([]*authkit.Client, 2)
	servers := make([]*httptest.Server, 2)
	users := make([]authtest.User, 2)
	for i := range views {
		id := iam.NewTenantID()
		require.NoError(t, shared.CreateTenant(t.Context(), iam.Tenant{ID: id}))
		views[i], err = shared.ForTenant(t.Context(), id)
		require.NoError(t, err)
		users[i] = authtest.NewUser(t, views[i])
		servers[i] = httptest.NewServer(views[i].Handler())
		t.Cleanup(servers[i].Close)
		servers[i].Client().Jar = jar
		status, _ := tenantNetwork(t, servers[i], views[i], http.MethodPost, "/password/login", "", map[string]string{"identifier": users[i].Email, "password": users[i].Password})
		require.Equal(t, http.StatusOK, status)
	}
	refresh := func(server *httptest.Server, client *authkit.Client, access string) string {
		status, raw := tenantNetwork(t, server, client, http.MethodPost, "/token", access, map[string]string{"grant_type": "refresh_token"})
		require.Equal(t, http.StatusOK, status)
		var result httpapi.AuthResult
		require.NoError(t, json.Unmarshal(raw, &result))
		return result.User.ID
	}
	require.Equal(t, users[1].ID, refresh(portal, shared, ""), "unbound reload has no access token but must restore the most recent directory from actual cookie proof")
	require.Equal(t, users[0].ID, refresh(servers[0], views[0], ""), "fixed A ignores the current portal hint")
	require.Equal(t, users[1].ID, refresh(servers[1], views[1], ""), "fixed B keeps its independent session")
	require.Equal(t, users[1].ID, refresh(portal, shared, "expired.invalid.access"), "an expired access token is not used to select the directory")
	origin, err := url.Parse(portal.URL)
	require.NoError(t, err)
	hint := httpapi.ActiveTenantCookieName(authtest.Issuer, false)
	bName := httpapi.TenantRefreshCookieName(authtest.Issuer, users[1].TenantID, "", false)
	value := func(name string) string {
		for _, c := range jar.Cookies(origin) {
			if c.Name == name {
				return c.Value
			}
		}
		return ""
	}
	for _, bad := range []string{"malformed", iam.NewTenantID().String()} {
		before := value(bName)
		require.NotEmpty(t, before)
		jar.SetCookies(origin, []*http.Cookie{{Name: hint, Value: bad, Path: "/"}})
		status, _ := tenantNetwork(t, portal, shared, http.MethodPost, "/token", "", map[string]string{"grant_type": "refresh_token"})
		require.GreaterOrEqual(t, status, 400)
		require.Less(t, status, 500)
		require.Equal(t, before, value(bName), "invalid hint must not clear or rotate B's real credential")
		require.Equal(t, users[1].ID, refresh(servers[1], views[1], ""), "fixed mount ignores malformed and foreign hints")
	}
}
