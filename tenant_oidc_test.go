package authkit_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/httpapi"
	"github.com/open-rails/authkit/provider"
	"github.com/stretchr/testify/require"
)

func TestTenantOIDCCallbackRecoversStoredOwnerWithoutCrossTenantConsumption(t *testing.T) {
	idp := authtest.NewIdP(t)
	shared, _ := authtest.New(t, authtest.WithConfig(func(c *authkit.Config) { c.DefaultTenantID = iam.TenantID{} }), authtest.WithDeps(func(d *authkit.Deps) { d.Providers = []provider.Provider{idp.Provider("tenantidp")} }))
	views := make([]*authkit.Client, 2)
	ids := []iam.TenantID{iam.NewTenantID(), iam.NewTenantID()}
	for i, id := range ids {
		require.NoError(t, shared.CreateTenant(t.Context(), iam.Tenant{ID: id}))
		var err error
		views[i], err = shared.ForTenant(t.Context(), id)
		require.NoError(t, err)
	}
	start := func(client *authkit.Client) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		client.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/oidc/tenantidp/login", nil))
		require.Equal(t, http.StatusFound, rec.Code)
		return rec
	}
	callback := func(client *authkit.Client, begin *httptest.ResponseRecorder, path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("Accept", "application/json")
		for _, c := range begin.Result().Cookies() {
			req.AddCookie(c)
		}
		rec := httptest.NewRecorder()
		client.Handler().ServeHTTP(rec, req)
		return rec
	}
	beginB := start(views[1])
	identity := provider.Identity{Subject: "same-provider-subject", Email: "oidc-same@example.test", EmailVerified: true}
	query := idp.SignIn(t, beginB.Header().Get("Location"), identity)
	path := "/oidc/tenantidp/callback?" + query.Encode()
	wrong := callback(views[0], beginB, path)
	require.GreaterOrEqual(t, wrong.Code, 400)
	for _, c := range wrong.Result().Cookies() {
		require.GreaterOrEqual(t, c.MaxAge, 0, "wrong tenant must preserve the initiating browser cookie")
	}
	correct := callback(views[1], beginB, path)
	require.Equal(t, http.StatusOK, correct.Code)
	var b httpapi.AuthResult
	require.NoError(t, json.Unmarshal(correct.Body.Bytes(), &b))
	require.Equal(t, ids[1], b.User.TenantID)
	replay := callback(views[1], beginB, path)
	require.GreaterOrEqual(t, replay.Code, 400)

	// The unbound shared callback resolves only the stored random state after
	// the browser cookie has matched. It must not select the default tenant.
	beginA := start(views[0])
	query = idp.SignIn(t, beginA.Header().Get("Location"), identity)
	sharedResult := callback(shared, beginA, "/oidc/tenantidp/callback?"+query.Encode())
	require.Equal(t, http.StatusOK, sharedResult.Code)
	var a httpapi.AuthResult
	require.NoError(t, json.Unmarshal(sharedResult.Body.Bytes(), &a))
	require.Equal(t, ids[0], a.User.TenantID)
	require.NotEqual(t, a.User.ID, b.User.ID)
}
