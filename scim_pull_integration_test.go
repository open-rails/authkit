package authkit_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/scim"
)

const (
	directorySync       = "directory-sync"
	directorySyncSecret = "directory-sync-secret-0123456789-abcdefghij"
	otherResource       = "https://other.example.com"
)

// scimCall sends method to the SCIM service provider's path with token
// ("Bearer", or "DPoP" with key's proof) and decodes the answer into out.
func scimCall(t *testing.T, as *authtest.AuthorizationServer, method, path, token string, key *authtest.DPoPKey, out any) (int, http.Header) {
	t.Helper()
	req, err := http.NewRequest(method, as.URL+"/scim/v2"+path, nil)
	require.NoError(t, err)
	switch {
	case key != nil:
		target := strings.SplitN(req.URL.String(), "?", 2)[0]
		req.Header.Set("Authorization", "DPoP "+token)
		req.Header.Set("DPoP", key.Proof(t, method, target, token, ""))
	case token != "":
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res, err := as.HTTPClient().Do(req)
	require.NoError(t, err)
	defer res.Body.Close()
	require.Equal(t, scim.MediaType, res.Header.Get("Content-Type"), "%s %s", method, path)
	if out != nil {
		require.NoError(t, json.NewDecoder(res.Body).Decode(out))
	}
	return res.StatusCode, res.Header
}

// TestSCIMServiceProvider: AuthKit's directory reads as SCIM 2.0 for a
// client-credentials token with scope scim:read, and nothing else; writes
// answer 501.
func TestSCIMServiceProvider(t *testing.T) {
	as, _, _ := newOAuthServer(t, authtest.WithConfig(func(c *authkit.Config) {
		c.AuthorizationServer.Clients = append(c.AuthorizationServer.Clients, authkit.OAuthClientConfig{
			ID: directorySync, SecretSHA256: authtest.ClientSecretSHA256(directorySyncSecret),
			GrantTypes: []authkit.OAuthGrantType{authkit.GrantClientCredentials}, Resources: []string{c.Token.Issuer + "/scim/v2", oauthResource},
		})
	}))
	scimResource := as.URL + "/scim/v2"
	ctx := context.Background()
	alice, bob := authtest.NewUser(t, as.Client), authtest.NewUser(t, as.Client)
	require.NoError(t, as.Client.Ban(ctx, iam.SystemIdentity(), bob.ID, iam.Ban{Reason: "spam"}))
	read := as.ClientCredentials(t, directorySync, directorySyncSecret, scimResource, []string{"scim:read"}, nil).AccessToken

	t.Run("only a scim:read token for the service provider reads", func(t *testing.T) {
		var e scim.Error
		status, header := scimCall(t, as, http.MethodGet, "/Users/"+alice.ID, "", nil, &e)
		require.Equal(t, http.StatusUnauthorized, status)
		require.Equal(t, []string{scim.SchemaError}, e.Schemas)
		require.Equal(t, "401", e.Status)
		require.Contains(t, header.Get("WWW-Authenticate"), `error="invalid_token"`)

		noScope := as.ClientCredentials(t, directorySync, directorySyncSecret, scimResource, nil, nil).AccessToken
		status, header = scimCall(t, as, http.MethodGet, "/Users/"+alice.ID, noScope, nil, &e)
		require.Equal(t, http.StatusForbidden, status)
		require.Contains(t, header.Get("WWW-Authenticate"), `error="insufficient_scope"`)

		otherAudience := as.ClientCredentials(t, directorySync, directorySyncSecret, oauthResource, nil, nil).AccessToken
		status, _ = scimCall(t, as, http.MethodGet, "/Users/"+alice.ID, otherAudience, nil, &e)
		require.Equal(t, http.StatusUnauthorized, status, "a token for another resource")

		userToken := authtest.SignIn(t, as.Client, alice).AccessToken
		status, _ = scimCall(t, as, http.MethodGet, "/Users/"+alice.ID, userToken, nil, &e)
		require.Equal(t, http.StatusUnauthorized, status, "a user's session token")

		key := authtest.NewDPoPKey(t)
		bound := as.ClientCredentials(t, directorySync, directorySyncSecret, scimResource, []string{"scim:read"}, key).AccessToken
		var u scim.User
		status, _ = scimCall(t, as, http.MethodGet, "/Users/"+alice.ID, bound, key, &u)
		require.Equal(t, http.StatusOK, status, "a DPoP-bound token with its proof")
		status, _ = scimCall(t, as, http.MethodGet, "/Users/"+alice.ID, bound, nil, &e)
		require.Equal(t, http.StatusUnauthorized, status, "a DPoP-bound token without its proof")
	})

	t.Run("a user", func(t *testing.T) {
		var u scim.User
		status, _ := scimCall(t, as, http.MethodGet, "/Users/"+alice.ID, read, nil, &u)
		require.Equal(t, http.StatusOK, status)
		require.Equal(t, alice.ID, u.ID)
		require.Equal(t, alice.Username, u.UserName)
		require.Equal(t, alice.Username, u.DisplayName)
		require.Equal(t, alice.Email, u.PrimaryEmail())
		require.True(t, *u.Active)
		require.Equal(t, "User", u.Meta.ResourceType)
		require.Equal(t, scimResource+"/Users/"+alice.ID, u.Meta.Location)
		require.NotNil(t, u.Meta.LastModified)

		status, _ = scimCall(t, as, http.MethodGet, "/Users/"+bob.ID, read, nil, &u)
		require.Equal(t, http.StatusOK, status)
		require.False(t, *u.Active, "a banned account is inactive")

		var e scim.Error
		for _, missing := range []string{"0192f6a0-0000-7000-8000-000000000001", "not-a-uuid"} {
			status, _ = scimCall(t, as, http.MethodGet, "/Users/"+missing, read, nil, &e)
			require.Equal(t, http.StatusNotFound, status)
			require.Equal(t, "404", e.Status)
		}
	})

	t.Run("filters", func(t *testing.T) {
		query := func(q url.Values) scim.ListResponse[scim.User] {
			t.Helper()
			var page scim.ListResponse[scim.User]
			status, _ := scimCall(t, as, http.MethodGet, "/Users?"+q.Encode(), read, nil, &page)
			require.Equal(t, http.StatusOK, status)
			require.Equal(t, []string{scim.SchemaListResponse}, page.Schemas)
			require.Equal(t, len(page.Resources), page.ItemsPerPage)
			return page
		}
		ids := func(page scim.ListResponse[scim.User]) []string {
			var out []string
			for _, u := range page.Resources {
				out = append(out, u.ID)
			}
			return out
		}
		require.Equal(t, []string{alice.ID}, ids(query(url.Values{"filter": {`userName eq "` + strings.ToUpper(alice.Username) + `"`}})))
		require.Equal(t, []string{alice.ID}, ids(query(url.Values{"filter": {`emails.value eq "` + alice.Email + `"`}})))
		require.Equal(t, []string{alice.ID}, ids(query(url.Values{"filter": {`id eq "` + alice.ID + `"`}})))
		require.ElementsMatch(t, []string{alice.ID, bob.ID}, ids(query(url.Values{"filter": {`id eq "` + alice.ID + `" OR userName eq "` + bob.Username + `"`}})))
		require.Empty(t, ids(query(url.Values{"filter": {`userName eq "nobody-at-all"`}})))

		unproven := "unproven-" + alice.Email
		_, err := as.Client.UpdateUser(ctx, iam.SystemIdentity(), bob.ID, iam.UserUpdate{Email: &unproven})
		require.NoError(t, err)
		require.Empty(t, ids(query(url.Values{"filter": {`emails.value eq "` + unproven + `"`}})), "an unverified address matches nothing")

		page := query(url.Values{"startIndex": {"1"}, "count": {"1"}})
		require.Equal(t, 2, page.TotalResults)
		require.Len(t, page.Resources, 1)
		next := query(url.Values{"startIndex": {"2"}, "count": {"1"}})
		require.Len(t, next.Resources, 1)
		require.NotEqual(t, page.Resources[0].ID, next.Resources[0].ID)
		require.Empty(t, query(url.Values{"count": {"0"}}).Resources)

		for _, bad := range []string{`name.givenName eq "x"`, `userName co "a"`, `userName eq "a" and id eq "b"`, `userName eq a`} {
			var e scim.Error
			status, _ := scimCall(t, as, http.MethodGet, "/Users?"+url.Values{"filter": {bad}}.Encode(), read, nil, &e)
			require.Equal(t, http.StatusBadRequest, status, bad)
			require.Equal(t, "invalidFilter", e.ScimType, bad)
		}
	})

	t.Run("discovery", func(t *testing.T) {
		var spc scim.ServiceProviderConfig
		status, _ := scimCall(t, as, http.MethodGet, "/ServiceProviderConfig", read, nil, &spc)
		require.Equal(t, http.StatusOK, status)
		require.False(t, spc.Bulk.Supported)
		require.True(t, spc.Filter.Supported)
		require.False(t, spc.Patch.Supported)
		require.Equal(t, "oauthbearertoken", spc.AuthenticationSchemes[0].Type)

		var types scim.ListResponse[scim.ResourceType]
		status, _ = scimCall(t, as, http.MethodGet, "/ResourceTypes", read, nil, &types)
		require.Equal(t, http.StatusOK, status)
		require.Equal(t, "/Users", types.Resources[0].Endpoint)
		var userType scim.ResourceType
		status, _ = scimCall(t, as, http.MethodGet, "/ResourceTypes/User", read, nil, &userType)
		require.Equal(t, http.StatusOK, status)
		require.Equal(t, scim.SchemaUser, userType.Schema)

		var schemas scim.ListResponse[scim.SchemaDoc]
		status, _ = scimCall(t, as, http.MethodGet, "/Schemas", read, nil, &schemas)
		require.Equal(t, http.StatusOK, status)
		require.Equal(t, scim.SchemaUser, schemas.Resources[0].ID)
		var schema scim.SchemaDoc
		status, _ = scimCall(t, as, http.MethodGet, "/Schemas/"+scim.SchemaUser, read, nil, &schema)
		require.Equal(t, http.StatusOK, status)
		require.Equal(t, "User", schema.Name)
	})

	t.Run("writes are not implemented", func(t *testing.T) {
		for _, w := range []struct{ method, path string }{
			{http.MethodPost, "/Users"}, {http.MethodPut, "/Users/" + alice.ID}, {http.MethodPatch, "/Users/" + alice.ID},
			{http.MethodDelete, "/Users/" + alice.ID}, {http.MethodPost, "/Bulk"},
		} {
			var e scim.Error
			status, _ := scimCall(t, as, w.method, w.path, read, nil, &e)
			require.Equal(t, http.StatusNotImplemented, status, "%s %s", w.method, w.path)
			require.Equal(t, "501", e.Status)
		}
	})
}

// TestContactClaims: a user's access token for a resource with
// ContactClaims carries the OIDC contact claims, and updated_at moves when
// the contact changes; tokens for other resources carry none.
func TestContactClaims(t *testing.T) {
	as, _, _ := newOAuthServer(t, authtest.WithConfig(func(c *authkit.Config) {
		as := &c.AuthorizationServer
		as.Resources[0].ContactClaims = true
		as.Resources = append(as.Resources, authkit.ResourceServerConfig{ID: otherResource, Scopes: []string{"other:read"}})
		for i := range as.Clients {
			if as.Clients[i].ID == oauthAdminUI {
				as.Clients[i].Resources = append(as.Clients[i].Resources, otherResource)
			}
		}
	}))
	ctx := context.Background()
	alice := authtest.NewUser(t, as.Client)
	signedIn := authtest.SignIn(t, as.Client, alice)
	token := func(resource string) map[string]any {
		t.Helper()
		tokens := as.Exchange(t, authtest.TokenExchange{ClientID: oauthAdminUI, SubjectToken: signedIn.AccessToken, Resource: resource})
		return verifyIssued(t, as, tokens.AccessToken, "at+jwt")
	}

	claims := token(oauthResource)
	require.Equal(t, alice.Email, claims["email"])
	require.Equal(t, true, claims["email_verified"])
	require.Equal(t, alice.Username, claims["preferred_username"])
	require.Equal(t, alice.Username, claims["name"])
	first, ok := claims["updated_at"].(float64)
	require.True(t, ok, "updated_at is seconds since the epoch: %v", claims["updated_at"])

	other := token(otherResource)
	for _, name := range []string{"email", "email_verified", "preferred_username", "name", "updated_at"} {
		require.NotContains(t, other, name, "a token for a resource without ContactClaims")
	}

	time.Sleep(1100 * time.Millisecond) // updated_at counts seconds
	language := "fr"
	_, err := as.Client.UpdateUser(ctx, iam.SystemIdentity(), alice.ID, iam.UserUpdate{PreferredLanguage: &language})
	require.NoError(t, err)
	require.Equal(t, first, token(oauthResource)["updated_at"], "a change the contact does not show")

	email, verified := "moved-"+alice.Email, true
	_, err = as.Client.UpdateUser(ctx, iam.SystemIdentity(), alice.ID, iam.UserUpdate{Email: &email, EmailVerified: &verified})
	require.NoError(t, err)
	signedIn = authtest.SignIn(t, as.Client, authtest.User{User: alice.User, Email: email, Password: alice.Password})
	claims = token(oauthResource)
	require.Equal(t, email, claims["email"])
	require.Greater(t, claims["updated_at"].(float64), first)
}
