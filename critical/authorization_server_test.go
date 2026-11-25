package critical_test

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/verify"
)

// TestCriticalAuthorizationServer drives AuthKit's OAuth 2.0 token endpoint
// as a client would, over HTTPS, with real sign-ins.
func TestCriticalAuthorizationServer(t *testing.T) {
	t.Parallel()
	const secret = "a confidential client's secret of at least 32 bytes"
	const redirect = "https://client.example/callback"
	const api = "https://api.example"
	as := authtest.NewAuthorizationServer(t, authtest.WithConfig(func(c *authkit.Config) {
		c.AuthorizationServer.Resources = []authkit.ResourceServerConfig{{ID: api, Scopes: []string{"orders:read"}}}
		c.AuthorizationServer.Clients = []authkit.OAuthClientConfig{
			{ID: "web", SecretSHA256: authtest.ClientSecretSHA256(secret), RedirectURIs: []string{redirect}, Resources: []string{api},
				GrantTypes: []authkit.OAuthGrantType{authkit.GrantAuthorizationCode, authkit.GrantRefreshToken}},
			{ID: "service", SecretSHA256: authtest.ClientSecretSHA256(secret), Resources: []string{api},
				GrantTypes: []authkit.OAuthGrantType{authkit.GrantClientCredentials}},
		}
	}))
	u := authtest.NewUser(t, as.Client)
	signedIn := authtest.SignIn(t, as.Client, u)
	key := authtest.NewDPoPKey(t)
	flow := authtest.CodeFlow{ClientID: "web", ClientSecret: secret, RedirectURI: redirect, Resource: api, Scopes: []string{"openid", "orders:read"}, DPoP: key}
	// code approves a fresh authorization request with verifier's challenge.
	code := func(t *testing.T, verifier string) string {
		t.Helper()
		state := randomText(t)
		callback, err := url.Parse(as.Approve(t, signedIn.AccessToken, as.BeginAuthorization(t, flow, verifier, state)))
		noError(t, err)
		if callback.Query().Get("state") != state || callback.Query().Get("code") == "" {
			t.Fatalf("approval answered %s", callback)
		}
		return callback.Query().Get("code")
	}
	token := func(t *testing.T, key *authtest.DPoPKey, params url.Values) (int, oauthAnswer) {
		t.Helper()
		status, body := as.Token(t, authtest.TokenRequest{ClientID: "web", ClientSecret: secret, DPoP: key, Params: params})
		var answer oauthAnswer
		if err := json.Unmarshal(body, &answer); err != nil {
			t.Fatalf("token endpoint answered %d %s", status, body)
		}
		return status, answer
	}
	redeem := func(t *testing.T, code, verifier, redirectURI string) (int, oauthAnswer) {
		t.Helper()
		return token(t, key, url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirectURI}, "code_verifier": {verifier}, "resource": {api}})
	}
	refresh := func(t *testing.T, key *authtest.DPoPKey, refreshToken string) (int, oauthAnswer) {
		t.Helper()
		return token(t, key, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refreshToken}})
	}

	t.Run("AK-J44-C01_an_authorization_code_redeems_once_with_its_PKCE_verifier_at_its_redirect_URI", func(t *testing.T) {
		verifier := randomText(t)
		refused(t, "wrong verifier", invalidGrant("code_verifier"))(redeem(t, code(t, verifier), randomText(t), redirect))
		refused(t, "wrong redirect_uri", invalidGrant("redirect_uri"))(redeem(t, code(t, verifier), verifier, "https://client.example/elsewhere"))
		issued := code(t, verifier)
		status, tokens := redeem(t, issued, verifier, redirect)
		if status != http.StatusOK || tokens.AccessToken == "" || tokens.RefreshToken == "" || tokens.IDToken == "" || tokens.TokenType != "DPoP" {
			t.Fatalf("redemption answered %d %+v", status, tokens)
		}
		// RFC 6749 §4.1.2: a code used twice is refused.
		refused(t, "reused code", invalidGrant("already used"))(redeem(t, issued, verifier, redirect))
	})

	t.Run("AK-J44-C02_a_refresh_token_refreshes_only_with_its_DPoP_key_and_its_reuse_revokes_the_family", func(t *testing.T) {
		family := func() oauthAnswer {
			verifier := randomText(t)
			status, tokens := redeem(t, code(t, verifier), verifier, redirect)
			if status != http.StatusOK {
				t.Fatalf("redemption answered %d", status)
			}
			return tokens
		}
		bound := family()
		refused(t, "another key's proof", oauthRefusal{"invalid_dpop_proof", "another DPoP key"})(refresh(t, authtest.NewDPoPKey(t), bound.RefreshToken))
		if status, _ := refresh(t, key, bound.RefreshToken); status != http.StatusOK {
			t.Errorf("after another key's refusal its own key's refresh answered %d", status)
		}
		first := family()
		status, second := refresh(t, key, first.RefreshToken)
		if status != http.StatusOK || second.RefreshToken == "" || second.RefreshToken == first.RefreshToken {
			t.Fatalf("refresh answered %d %+v", status, second)
		}
		refused(t, "rotated-out token", invalidGrant("already used"))(refresh(t, key, first.RefreshToken))
		refused(t, "the family's live token", invalidGrant(""))(refresh(t, key, second.RefreshToken))
	})

	t.Run("AK-J44-C03_client_credentials_issues_a_confidential_client_its_own_token", func(t *testing.T) {
		tokens := as.ClientCredentials(t, "service", secret, api, []string{"orders:read"}, nil)
		if tokens.RefreshToken != "" || tokens.IDToken != "" || tokens.TokenType != "Bearer" {
			t.Fatalf("client credentials answered %+v", tokens)
		}
		v := verify.NewVerifier(verify.WithHTTPClient(as.HTTPClient()))
		defer v.Close()
		noError(t, v.AddIssuer(as.URL, []string{api}, verify.IssuerOptions{JWKSURI: as.URL + iam.JWKSPath}))
		claims, err := v.Verify(t.Context(), tokens.AccessToken)
		noError(t, err)
		if claims.Kind != verify.TokenOAuthClient || claims.ClientID != "service" || claims.Subject != "service" || !claims.HasScope("orders:read") || claims.UserID != "" {
			t.Fatalf("client credentials token: %+v", claims)
		}
		cc := func(clientID, clientSecret, scope string) (int, oauthAnswer) {
			status, body := as.Token(t, authtest.TokenRequest{ClientID: clientID, ClientSecret: clientSecret, Params: url.Values{
				"grant_type": {"client_credentials"}, "resource": {api}, "scope": {scope}}})
			var answer oauthAnswer
			if err := json.Unmarshal(body, &answer); err != nil {
				t.Fatalf("token endpoint answered %d %s", status, body)
			}
			return status, answer
		}
		refused(t, "wrong secret", oauthRefusal{code: "invalid_client"})(cc("service", "not the secret", "orders:read"))
		refused(t, "undeclared scope", oauthRefusal{code: "invalid_scope"})(cc("service", secret, "orders:write"))
		refused(t, "a client without the grant", oauthRefusal{code: "unauthorized_client"})(cc("web", secret, "orders:read"))
	})
}

// oauthAnswer is a token endpoint answer: tokens or an RFC 6749 error.
type oauthAnswer struct {
	AccessToken      string `json:"access_token"`
	TokenType        string `json:"token_type"`
	RefreshToken     string `json:"refresh_token"`
	IDToken          string `json:"id_token"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// oauthRefusal is an expected error, and a phrase its description names.
type oauthRefusal struct{ code, names string }

func invalidGrant(names string) oauthRefusal { return oauthRefusal{"invalid_grant", names} }

// refused checks a token endpoint answer is want.
func refused(t *testing.T, what string, want oauthRefusal) func(int, oauthAnswer) {
	t.Helper()
	return func(status int, got oauthAnswer) {
		t.Helper()
		if status < 400 || status >= 500 || got.AccessToken != "" || got.Error != want.code || !strings.Contains(got.ErrorDescription, want.names) {
			t.Errorf("%s answered %d %+v, want %s naming %q", what, status, got, want.code, want.names)
		}
	}
}

// randomText is 32 random bytes, base64url: a PKCE verifier or a state.
func randomText(t *testing.T) string {
	t.Helper()
	b := make([]byte, 32)
	_, err := rand.Read(b)
	noError(t, err)
	return base64.RawURLEncoding.EncodeToString(b)
}
