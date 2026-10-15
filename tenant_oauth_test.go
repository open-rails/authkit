package authkit_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
	"github.com/stretchr/testify/require"
)

func TestTenantOAuthProofsAndSCIMAreDirectoryBound(t *testing.T) {
	ids := []iam.TenantID{iam.NewTenantID(), iam.NewTenantID()}
	shared, _ := authtest.New(t, authtest.WithConfig(func(c *authkit.Config) {
		c.DefaultTenantID = iam.TenantID{}
		c.TwoFactor.Mode = iam.TwoFactorDisabled
		c.AuthorizationServer = authkit.AuthorizationServerConfig{Clients: []authkit.OAuthClientConfig{
			{ID: "client-a", TenantID: ids[0], SecretSHA256: authtest.ClientSecretSHA256(directorySyncSecret), RedirectURIs: []string{"https://client.example.test/callback"}, Resources: []string{c.Token.Issuer + "/scim/v2"}, GrantTypes: []authkit.OAuthGrantType{authkit.GrantAuthorizationCode, authkit.GrantRefreshToken, authkit.GrantClientCredentials}},
			{ID: "client-b", TenantID: ids[1], SecretSHA256: authtest.ClientSecretSHA256(directorySyncSecret), RedirectURIs: []string{"https://client.example.test/callback"}, Resources: []string{c.Token.Issuer + "/scim/v2"}, GrantTypes: []authkit.OAuthGrantType{authkit.GrantAuthorizationCode, authkit.GrantRefreshToken, authkit.GrantClientCredentials}},
		}}
	}))
	views := make([]*authkit.Client, 2)
	users := make([]authtest.User, 2)
	for i, id := range ids {
		require.NoError(t, shared.CreateTenant(t.Context(), iam.Tenant{ID: id}))
		var err error
		views[i], err = shared.ForTenant(t.Context(), id)
		require.NoError(t, err)
		users[i] = authtest.NewUser(t, views[i])
	}
	form := func(client *authkit.Client, path, id string, body url.Values) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, authtest.Issuer+path, strings.NewReader(body.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth(id, directorySyncSecret)
		w := httptest.NewRecorder()
		client.Handler().ServeHTTP(w, req)
		return w
	}
	get := func(client *authkit.Client, path, token string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, authtest.Issuer+path, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		client.Handler().ServeHTTP(w, req)
		return w
	}
	for i, clientID := range []string{"client-a", "client-b"} {
		w := form(shared, iam.OAuthTokenPath, clientID, url.Values{"grant_type": {"client_credentials"}, "resource": {authtest.Issuer + "/scim/v2"}, "scope": {"scim:read"}})
		require.Equal(t, http.StatusOK, w.Code)
		var token authtest.OAuthTokens
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &token))
		own := get(views[i], "/scim/v2/Users/"+users[i].ID, token.AccessToken)
		require.Equal(t, http.StatusOK, own.Code)
		foreign := get(views[1-i], "/scim/v2/Users/"+users[1-i].ID, token.AccessToken)
		require.Equal(t, http.StatusUnauthorized, foreign.Code)
		foreign = get(views[i], "/scim/v2/Users/"+users[1-i].ID, token.AccessToken)
		require.Equal(t, http.StatusNotFound, foreign.Code)
	}
	// Begin on the shared issuer using a trusted registered client, approve as
	// B, and redeem on the shared endpoint. Wrong A attempts spend no proof.
	verifier := strings.Repeat("t", 43)
	query := url.Values{"response_type": {"code"}, "client_id": {"client-b"}, "redirect_uri": {"https://client.example.test/callback"}, "scope": {"openid email"}, "code_challenge": {authtest.PKCEChallenge(verifier)}, "code_challenge_method": {"S256"}}
	req := httptest.NewRequest(http.MethodGet, authtest.Issuer+iam.OAuthAuthorizePath+"?"+query.Encode(), nil)
	w := httptest.NewRecorder()
	shared.Handler().ServeHTTP(w, req)
	require.Equal(t, http.StatusSeeOther, w.Code)
	location, err := url.Parse(w.Header().Get("Location"))
	require.NoError(t, err)
	requestID := location.Query().Get("authorization")
	require.NotEmpty(t, requestID)
	token := authtest.SignIn(t, views[1], users[1]).AccessToken
	approvePath := shared.APIBase() + "/oauth2/authorizations/" + url.PathEscape(requestID) + "/approve"
	approve := func(client *authkit.Client) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, approvePath, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		client.Handler().ServeHTTP(w, req)
		return w
	}
	w = approve(views[0])
	require.GreaterOrEqual(t, w.Code, 400)
	require.Less(t, w.Code, 500)
	w = approve(shared)
	require.Equal(t, http.StatusOK, w.Code)
	var result struct {
		RedirectTo string `json:"redirect_to"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &result))
	location, err = url.Parse(result.RedirectTo)
	require.NoError(t, err)
	body := url.Values{"grant_type": {"authorization_code"}, "code": {location.Query().Get("code")}, "redirect_uri": {"https://client.example.test/callback"}, "code_verifier": {verifier}}
	w = form(views[0], iam.OAuthTokenPath, "client-b", body)
	require.GreaterOrEqual(t, w.Code, 400)
	require.Less(t, w.Code, 500)
	w = form(shared, iam.OAuthTokenPath, "client-b", body)
	require.Equal(t, http.StatusOK, w.Code)
	var oauth authtest.OAuthTokens
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &oauth))
	require.NotEmpty(t, oauth.RefreshToken)
	w = get(views[0], iam.OAuthUserInfoPath, oauth.AccessToken)
	require.GreaterOrEqual(t, w.Code, 400)
	require.Less(t, w.Code, 500)
	w = get(shared, iam.OAuthUserInfoPath, oauth.AccessToken)
	require.Equal(t, http.StatusOK, w.Code)
	require.Contains(t, w.Body.String(), users[1].ID)
	body = url.Values{"grant_type": {"refresh_token"}, "refresh_token": {oauth.RefreshToken}}
	w = form(views[0], iam.OAuthTokenPath, "client-b", body)
	require.GreaterOrEqual(t, w.Code, 400)
	require.Less(t, w.Code, 500)
	w = form(shared, iam.OAuthTokenPath, "client-b", body)
	require.Equal(t, http.StatusOK, w.Code)
}
