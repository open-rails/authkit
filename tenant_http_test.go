package authkit_test

import (
	"bytes"
	"encoding/json"
	"io"
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

func TestTenantHTTPMountsKeepAccountsAndAdministrationSeparate(t *testing.T) {
	r := authkit.NewRoles()
	tenantReader := r.Tenant.Role("reader", r.Tenant.Users.Read)
	rootReader := r.Root.Role("reader", r.Root.Users.Read)
	shared, outbox := authtest.New(t, authtest.WithConfig(func(c *authkit.Config) {
		c.Roles, c.DefaultTenantID = r, iam.TenantID{}
	}))
	views := make([]*authkit.Client, 2)
	servers := make([]*httptest.Server, 2)
	users := make([]iam.User, 2)
	tokens := make([]iam.TokenSet, 2)
	for i := range views {
		tenant := iam.NewTenantID()
		require.NoError(t, shared.CreateTenant(t.Context(), iam.Tenant{ID: tenant}))
		var err error
		views[i], err = shared.ForTenant(t.Context(), tenant)
		require.NoError(t, err)
		users[i], err = views[i].CreateUser(t.Context(), iam.NewUser{Username: "sameuser", Email: "same@example.test", Password: authtest.Password, EmailVerified: true})
		require.NoError(t, err)
		mux := http.NewServeMux()
		require.NoError(t, views[i].Mount(mux))
		servers[i] = httptest.NewServer(mux)
		t.Cleanup(servers[i].Close)
		code, raw := tenantNetwork(t, servers[i], views[i], http.MethodPost, "/password/login", "", map[string]string{"identifier": "same@example.test", "password": authtest.Password})
		require.Equal(t, http.StatusOK, code)
		var result httpapi.AuthResult
		require.NoError(t, json.Unmarshal(raw, &result))
		require.Equal(t, users[i].ID, result.User.ID)
		require.NotNil(t, result.TokenSet)
		tokens[i] = *result.TokenSet
	}
	require.NoError(t, func() error {
		_, err := views[0].SetGroupRole(t.Context(), iam.SystemIdentity(), iam.GroupByID(users[0].TenantID.String()), iam.UserSubject(users[0].ID), tenantReader)
		return err
	}())
	for i := range views {
		status, _ := tenantNetwork(t, servers[i], views[i], http.MethodGet, "/me", tokens[i].AccessToken, nil)
		require.Equal(t, http.StatusOK, status)
		status, _ = tenantNetwork(t, servers[1-i], views[1-i], http.MethodGet, "/me", tokens[i].AccessToken, nil)
		require.GreaterOrEqual(t, status, 400)
		require.Less(t, status, 500)
	}
	status, raw := tenantNetwork(t, servers[0], views[0], http.MethodGet, "/admin/users?status=any", tokens[0].AccessToken, nil)
	require.Equal(t, http.StatusOK, status)
	require.Contains(t, string(raw), users[0].ID)
	require.NotContains(t, string(raw), users[1].ID)
	status, _ = tenantNetwork(t, servers[1], views[1], http.MethodGet, "/admin/users?status=any", tokens[0].AccessToken, nil)
	require.Equal(t, http.StatusForbidden, status)
	operator := authtest.NewUser(t, views[0])
	authtest.GrantRole(t, views[0], iam.RootGroup(), iam.UserSubject(operator.ID), rootReader)
	operatorTokens := authtest.SignIn(t, views[0], operator)
	status, raw = tenantNetwork(t, servers[1], views[1], http.MethodGet, "/admin/users?status=any", operatorTokens.AccessToken, nil)
	require.Equal(t, http.StatusOK, status)
	require.Contains(t, string(raw), users[1].ID)
	require.NotContains(t, string(raw), operator.ID)
	status, _ = tenantNetwork(t, servers[1], views[1], http.MethodGet, "/me/permissions", operatorTokens.AccessToken, nil)
	require.Equal(t, http.StatusOK, status, "authority introspection is available to a foreign global operator")
	status, _ = tenantNetwork(t, servers[1], views[1], http.MethodGet, "/me", operatorTokens.AccessToken, nil)
	require.GreaterOrEqual(t, status, 400, "global authority does not create an account in the target tenant")
	require.Less(t, status, 500)
	refresh := map[string]any{"grant_type": "refresh_token", "refresh_token": tokens[0].RefreshToken}
	status, _ = tenantNetwork(t, servers[1], views[1], http.MethodPost, "/token", "", refresh)
	require.Equal(t, http.StatusUnauthorized, status)
	status, _ = tenantNetwork(t, servers[0], views[0], http.MethodPost, "/token", "", refresh)
	require.Equal(t, http.StatusOK, status)
	status, _ = tenantNetwork(t, servers[0], views[0], http.MethodPost, "/password/reset/request", "", map[string]string{"identifier": "same@example.test"})
	require.Equal(t, http.StatusAccepted, status)
	proof := outbox.Last(t, iam.MessagePasswordReset, "same@example.test").Token
	reset := map[string]string{"token": proof, "new_password": "Network-reset-password-9"}
	status, _ = tenantNetwork(t, servers[1], views[1], http.MethodPost, "/password/reset/confirm", "", reset)
	require.GreaterOrEqual(t, status, 400)
	require.Less(t, status, 500)
	status, _ = tenantNetwork(t, servers[0], views[0], http.MethodPost, "/password/reset/confirm", "", reset)
	require.Equal(t, http.StatusNoContent, status)
}

func TestTenantRefreshCookiesCoexistWithDefaultAndConfiguredNames(t *testing.T) {
	for _, base := range []string{"", "configured-session"} {
		t.Run("base="+base, func(t *testing.T) {
			shared, _ := authtest.New(t, authtest.WithConfig(func(c *authkit.Config) {
				c.DefaultTenantID = iam.TenantID{}
				c.HTTP.RefreshCookie, c.HTTP.RefreshCookieName = true, base
				c.Frontend.BaseURL = "http://127.0.0.1"
				c.TwoFactor.Mode = iam.TwoFactorDisabled
			}))
			jar, err := cookiejar.New(nil)
			require.NoError(t, err)
			views := make([]*authkit.Client, 2)
			servers := make([]*httptest.Server, 2)
			users := make([]iam.User, 2)
			access := make([]string, 2)
			for i := range views {
				id := iam.NewTenantID()
				require.NoError(t, shared.CreateTenant(t.Context(), iam.Tenant{ID: id}))
				views[i], err = shared.ForTenant(t.Context(), id)
				require.NoError(t, err)
				users[i], err = views[i].CreateUser(t.Context(), iam.NewUser{Username: "cookieuser", Email: "same@example.test", Password: authtest.Password, EmailVerified: true})
				require.NoError(t, err)
				servers[i] = httptest.NewServer(views[i].Handler())
				t.Cleanup(servers[i].Close)
				servers[i].Client().Jar = jar
				status, raw := tenantNetwork(t, servers[i], views[i], http.MethodPost, "/password/login", "", map[string]string{"identifier": "same@example.test", "password": authtest.Password})
				require.Equal(t, http.StatusOK, status)
				var result httpapi.AuthResult
				require.NoError(t, json.Unmarshal(raw, &result))
				access[i] = result.TokenSet.AccessToken
			}
			origin, err := url.Parse(servers[0].URL)
			require.NoError(t, err)
			for _, u := range users {
				name := httpapi.TenantRefreshCookieName(authtest.Issuer, u.TenantID, base, false)
				var found bool
				for _, c := range jar.Cookies(origin) {
					if c.Name == name {
						found = true
					}
				}
				require.True(t, found, "tenant cookie missing")
			}
			for i := range views {
				status, raw := tenantNetwork(t, servers[i], views[i], http.MethodPost, "/token", "", map[string]string{"grant_type": "refresh_token"})
				require.Equal(t, http.StatusOK, status)
				var result httpapi.AuthResult
				require.NoError(t, json.Unmarshal(raw, &result))
				require.Equal(t, users[i].ID, result.User.ID)
			}
			status, _ := tenantNetwork(t, servers[0], views[0], http.MethodDelete, "/logout", access[0], nil)
			require.Equal(t, http.StatusNoContent, status)
			bName := httpapi.TenantRefreshCookieName(authtest.Issuer, users[1].TenantID, base, false)
			var bCookie *http.Cookie
			for _, c := range jar.Cookies(origin) {
				if c.Name == bName {
					bCookie = c
				}
			}
			require.NotNil(t, bCookie)
			legacyName := base
			if legacyName == "" {
				legacyName = httpapi.IssuerRefreshCookieName(authtest.Issuer, false)
			}
			jar.SetCookies(origin, []*http.Cookie{{Name: legacyName, Value: bCookie.Value, Path: "/"}})
			status, _ = tenantNetwork(t, servers[0], views[0], http.MethodPost, "/token", "", map[string]string{"grant_type": "refresh_token"})
			require.Equal(t, http.StatusUnauthorized, status)
			var legacySurvives bool
			for _, c := range jar.Cookies(origin) {
				if c.Name == legacyName && c.Value == bCookie.Value {
					legacySurvives = true
				}
			}
			require.True(t, legacySurvives, "foreign legacy cookie must not be cleared")
			status, _ = tenantNetwork(t, servers[1], views[1], http.MethodPost, "/token", "", map[string]string{"grant_type": "refresh_token"})
			require.Equal(t, http.StatusOK, status, "ending A must preserve B")
		})
	}
}

func tenantNetwork(t *testing.T, server *httptest.Server, client *authkit.Client, method, path, token string, body any) (int, []byte) {
	t.Helper()
	data, err := json.Marshal(body)
	require.NoError(t, err)
	req, err := http.NewRequest(method, server.URL+client.APIBase()+path, bytes.NewReader(data))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res, err := server.Client().Do(req)
	require.NoError(t, err)
	defer res.Body.Close()
	raw, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	return res.StatusCode, raw
}
