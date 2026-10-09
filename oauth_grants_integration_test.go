package authkit_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
)

// tokenError posts req and returns the status and OAuth error code.
func tokenError(t *testing.T, as *authtest.AuthorizationServer, req authtest.TokenRequest) (int, string) {
	t.Helper()
	status, body := as.Token(t, req)
	var out struct {
		Error string `json:"error"`
	}
	require.NoError(t, json.Unmarshal(body, &out), string(body))
	return status, out.Error
}

// TestOAuthDPoPAtTheTokenEndpoint: a public client must prove a DPoP key,
// each proof works once and only for the token endpoint, and a code bound
// with dpop_jkt redeems only with that key.
func TestOAuthDPoPAtTheTokenEndpoint(t *testing.T) {
	as, _, _ := newOAuthServer(t)
	var meta map[string]any
	require.Equal(t, http.StatusOK, getJSON(t, as, as.URL+iam.OpenIDConfigurationPath, &meta))
	require.Equal(t, []any{"ES256"}, meta["dpop_signing_alg_values_supported"])
	require.Equal(t, as.URL+iam.OAuthRevocationPath, meta["revocation_endpoint"])
	require.ElementsMatch(t, []any{"authorization_code", "refresh_token", "client_credentials", "urn:ietf:params:oauth:grant-type:token-exchange"}, meta["grant_types_supported"])

	signedIn := authtest.SignIn(t, as.Client, authtest.NewUser(t, as.Client))
	key := authtest.NewDPoPKey(t)
	verifier := strings.Repeat("d", 43)
	code := func(f authtest.CodeFlow) string {
		loc, err := url.Parse(as.Approve(t, signedIn.AccessToken, as.BeginAuthorization(t, f, verifier, "st")))
		require.NoError(t, err)
		return loc.Query().Get("code")
	}
	redeem := func(code string) url.Values {
		return url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {oauthConsoleCB}, "code_verifier": {verifier}}
	}

	_, errCode := tokenError(t, as, authtest.TokenRequest{ClientID: oauthConsole, Params: redeem(code(consoleFlow()))})
	require.Equal(t, "invalid_dpop_proof", errCode, "a public client without a proof")

	bound := consoleFlow()
	bound.DPoP = key
	_, errCode = tokenError(t, as, authtest.TokenRequest{ClientID: oauthConsole, DPoP: authtest.NewDPoPKey(t), Params: redeem(code(bound))})
	require.Equal(t, "invalid_dpop_proof", errCode, "a code bound by dpop_jkt redeems only with that key")
	status, body := as.Token(t, authtest.TokenRequest{ClientID: oauthConsole, DPoP: key, Params: redeem(code(bound))})
	require.Equal(t, http.StatusOK, status, string(body))

	proof := key.Proof(t, http.MethodPost, as.URL+iam.OAuthTokenPath, "", "")
	for name, header := range map[string]string{
		"a replayed proof":           proof,
		"a proof for another URL":    key.Proof(t, http.MethodPost, as.URL+iam.OAuthUserInfoPath, "", ""),
		"a proof for another method": key.Proof(t, http.MethodGet, as.URL+iam.OAuthTokenPath, "", ""),
		"a proof with ath":           key.Proof(t, http.MethodPost, as.URL+iam.OAuthTokenPath, "some-token", ""),
		"garbage":                    "not-a-proof",
	} {
		if name == "a replayed proof" {
			status, body := postWithDPoP(t, as, redeem(code(consoleFlow())), proof)
			require.Equal(t, http.StatusOK, status, string(body))
		}
		status, body := postWithDPoP(t, as, redeem(code(consoleFlow())), header)
		require.Equal(t, http.StatusBadRequest, status, name)
		require.Contains(t, string(body), `"invalid_dpop_proof"`, name)
	}

	// A DPoP-bound token reaches userinfo only with a proof of its key.
	tokens := as.Authorize(t, authtest.NewUser(t, as.Client), consoleFlow())
	var info map[string]any
	require.Equal(t, http.StatusUnauthorized, bearerJSON(t, as, http.MethodGet, as.URL+iam.OAuthUserInfoPath, tokens.AccessToken, &info))
	require.Equal(t, "invalid_token", info["error"])
	require.Equal(t, http.StatusUnauthorized, dpopJSON(t, as, http.MethodGet, as.URL+iam.OAuthUserInfoPath, authtest.OAuthTokens{AccessToken: tokens.AccessToken, DPoP: key}, &info))

	// A confidential client may bind its tokens too.
	backend := as.Authorize(t, authtest.NewUser(t, as.Client), authtest.CodeFlow{
		ClientID: oauthBackend, ClientSecret: oauthBackendToken, RedirectURI: oauthBackendCB, Scopes: []string{"openid"}, DPoP: key,
	})
	require.Equal(t, "DPoP", backend.TokenType)
	require.Equal(t, map[string]any{"jkt": key.Thumbprint()}, verifyIssued(t, as, backend.AccessToken, "at+jwt")["cnf"])
}

func postWithDPoP(t *testing.T, as *authtest.AuthorizationServer, params url.Values, proof string) (int, []byte) {
	t.Helper()
	params.Set("client_id", oauthConsole)
	req, _ := http.NewRequest(http.MethodPost, as.URL+iam.OAuthTokenPath, strings.NewReader(params.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("DPoP", proof)
	res, err := as.HTTPClient().Do(req)
	require.NoError(t, err)
	defer res.Body.Close()
	var body json.RawMessage
	_ = json.NewDecoder(res.Body).Decode(&body)
	return res.StatusCode, body
}

// TestOAuthRefreshTokenFamilies: refresh tokens rotate, stay bound to their
// DPoP key, re-read permissions live, end with their sign-in, family
// lifetime or revocation, and a replay revokes the whole family.
func TestOAuthRefreshTokenFamilies(t *testing.T) {
	as, admin, _ := newOAuthServer(t)
	ctx := context.Background()
	owner := authtest.NewUser(t, as.Client)
	authtest.GrantRole(t, as.Client, iam.RootGroup(), iam.UserSubject(owner.ID), admin)
	first := as.Authorize(t, owner, consoleFlow())

	second := as.Refresh(t, oauthConsole, "", first)
	require.Equal(t, "DPoP", second.TokenType)
	require.NotEqual(t, first.RefreshToken, second.RefreshToken)
	require.NotEmpty(t, second.IDToken, "openid: the refresh carries an ID token")
	at := verifyIssued(t, as, second.AccessToken, "at+jwt")
	require.Equal(t, map[string]any{"jkt": first.DPoP.Thumbprint()}, at["cnf"])
	require.Equal(t, []any{"merchant:*"}, at["permissions"])
	require.Nil(t, decodeClaims(t, second.IDToken)["nonce"], "no nonce on a refreshed ID token")

	refresh := func(tokens authtest.OAuthTokens, key *authtest.DPoPKey, extra url.Values) (int, string) {
		params := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tokens.RefreshToken}}
		for k, v := range extra {
			params[k] = v
		}
		return tokenError(t, as, authtest.TokenRequest{ClientID: oauthConsole, DPoP: key, Params: params})
	}
	_, code := refresh(second, authtest.NewDPoPKey(t), nil)
	require.Equal(t, "invalid_dpop_proof", code, "bound to its key")
	_, code = refresh(second, nil, nil)
	require.Equal(t, "invalid_dpop_proof", code, "a public client always proves its key")
	_, code = refresh(second, second.DPoP, url.Values{"scope": {"openid admin:all"}})
	require.Equal(t, "invalid_scope", code, "scopes only narrow")
	_, code = refresh(second, second.DPoP, url.Values{"resource": {"https://other.example"}})
	require.Equal(t, "invalid_target", code)
	status, body := as.Token(t, authtest.TokenRequest{ClientID: oauthBackend, ClientSecret: oauthBackendToken, Params: url.Values{"grant_type": {"refresh_token"}, "refresh_token": {second.RefreshToken}}})
	require.Equal(t, http.StatusBadRequest, status)
	require.Contains(t, string(body), "unauthorized_client", "another client")

	// Narrowed scopes; and the permissions follow the user's roles live.
	authtest.RevokeRole(t, as.Client, iam.RootGroup(), iam.UserSubject(owner.ID), admin)
	status, body = as.Token(t, authtest.TokenRequest{ClientID: oauthConsole, DPoP: second.DPoP, Params: url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {second.RefreshToken}, "scope": {"api:merchant"},
	}})
	require.Equal(t, http.StatusOK, status, string(body))
	var third authtest.OAuthTokens
	require.NoError(t, json.Unmarshal(body, &third))
	third.DPoP = second.DPoP
	require.Equal(t, "api:merchant", third.Scope)
	require.Empty(t, third.IDToken)
	require.Equal(t, []any{}, verifyIssued(t, as, third.AccessToken, "at+jwt")["permissions"])

	// Replaying a rotated-out token revokes the family: the newest one dies too.
	_, code = refresh(second, second.DPoP, nil)
	require.Equal(t, "invalid_grant", code)
	_, code = refresh(third, third.DPoP, nil)
	require.Equal(t, "invalid_grant", code, "the family is revoked")

	// Two redemptions of one token race: at most one wins, and the family dies.
	racing := as.Authorize(t, owner, consoleFlow())
	var wg sync.WaitGroup
	codes := make([]string, 2)
	for i := range codes {
		wg.Add(1)
		go func() {
			defer wg.Done()
			status, body := as.Token(t, authtest.TokenRequest{ClientID: oauthConsole, DPoP: racing.DPoP, Params: url.Values{"grant_type": {"refresh_token"}, "refresh_token": {racing.RefreshToken}}})
			if status == http.StatusOK {
				var won authtest.OAuthTokens
				_ = json.Unmarshal(body, &won)
				codes[i] = won.RefreshToken
			}
		}()
	}
	wg.Wait()
	winners := 0
	for _, rt := range codes {
		if rt != "" {
			winners++
			_, code = refresh(authtest.OAuthTokens{RefreshToken: rt}, racing.DPoP, nil)
			require.Equal(t, "invalid_grant", code, "the loser's replay revoked the winner's family")
		}
	}
	require.LessOrEqual(t, winners, 1)

	// Revocation (RFC 7009) ends a family; any token answers 200.
	revoked := as.Authorize(t, owner, consoleFlow())
	require.Equal(t, http.StatusOK, as.Revoke(t, oauthBackend, oauthBackendToken, revoked.RefreshToken), "another client's revocation is ignored")
	revoked = as.Refresh(t, oauthConsole, "", revoked)
	require.Equal(t, http.StatusOK, as.Revoke(t, oauthConsole, "", revoked.RefreshToken))
	_, code = refresh(revoked, revoked.DPoP, nil)
	require.Equal(t, "invalid_grant", code)
	require.Equal(t, http.StatusOK, as.Revoke(t, oauthConsole, "", "garbage"))
	require.Equal(t, http.StatusOK, as.Revoke(t, oauthConsole, "", revoked.AccessToken))

	// Ending the sign-in ends its families.
	signedIn := authtest.SignIn(t, as.Client, owner)
	ended := as.AuthorizeAs(t, signedIn, consoleFlow())
	claims, err := as.Client.Verify(ctx, signedIn.AccessToken)
	require.NoError(t, err)
	require.NoError(t, as.Client.RevokeSession(ctx, iam.SystemIdentity(), owner.ID, claims.SessionID))
	_, code = refresh(ended, ended.DPoP, nil)
	require.Equal(t, "invalid_grant", code)

	// The family lifetime is never extended by rotation.
	short, _, _ := newOAuthServer(t, authtest.WithConfig(func(c *authkit.Config) { c.AuthorizationServer.RefreshTokenTTL = 2 * time.Second }))
	tokens := short.Authorize(t, authtest.NewUser(t, short.Client), consoleFlow())
	tokens = short.Refresh(t, oauthConsole, "", tokens)
	time.Sleep(2100 * time.Millisecond)
	_, code = tokenError(t, short, authtest.TokenRequest{ClientID: oauthConsole, DPoP: tokens.DPoP, Params: url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tokens.RefreshToken}}})
	require.Equal(t, "invalid_grant", code)
}

// TestOAuthTokenExchange: a host frontend trades the user's AuthKit access
// token for a resource's, standing on the same sign-in; every other
// subject, target and scope is refused.
func TestOAuthTokenExchange(t *testing.T) {
	as, admin, _ := newOAuthServer(t)
	ctx := context.Background()
	owner := authtest.NewUser(t, as.Client)
	authtest.GrantRole(t, as.Client, iam.RootGroup(), iam.UserSubject(owner.ID), admin)
	signedIn := authtest.SignIn(t, as.Client, owner)
	key := authtest.NewDPoPKey(t)

	tokens := as.Exchange(t, authtest.TokenExchange{ClientID: oauthAdminUI, SubjectToken: signedIn.AccessToken, Resource: oauthResource, Scopes: []string{"api:merchant", "email"}, DPoP: key})
	require.Equal(t, "DPoP", tokens.TokenType)
	require.Equal(t, "urn:ietf:params:oauth:token-type:access_token", tokens.IssuedTokenType)
	require.Empty(t, tokens.RefreshToken)
	require.Empty(t, tokens.IDToken)
	at := verifyIssued(t, as, tokens.AccessToken, "at+jwt")
	session, err := as.Client.Verify(ctx, signedIn.AccessToken)
	require.NoError(t, err)
	require.Equal(t, owner.ID, at["sub"])
	require.Equal(t, oauthResource, at["aud"])
	require.Equal(t, oauthAdminUI, at["client_id"])
	require.Equal(t, session.SessionID, at["sid"])
	require.Equal(t, []any{"merchant:*"}, at["permissions"])
	require.Equal(t, owner.Email, at["email"])
	require.Equal(t, map[string]any{"jkt": key.Thumbprint()}, at["cnf"])

	exchange := func(mutate func(url.Values), dpop *authtest.DPoPKey) (int, string) {
		params := url.Values{
			"grant_type": {"urn:ietf:params:oauth:grant-type:token-exchange"}, "subject_token": {signedIn.AccessToken},
			"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"}, "resource": {oauthResource}, "scope": {"api:merchant"},
		}
		mutate(params)
		return tokenError(t, as, authtest.TokenRequest{ClientID: oauthAdminUI, DPoP: dpop, Params: params})
	}
	for name, tc := range map[string]struct {
		mutate func(url.Values)
		code   string
	}{
		"a resource token as subject": {func(p url.Values) { p.Set("subject_token", tokens.AccessToken) }, "invalid_grant"},
		"garbage subject":             {func(p url.Values) { p.Set("subject_token", "garbage") }, "invalid_grant"},
		"no subject":                  {func(p url.Values) { p.Del("subject_token") }, "invalid_request"},
		"an ID token type":            {func(p url.Values) { p.Set("subject_token_type", "urn:ietf:params:oauth:token-type:id_token") }, "invalid_request"},
		"a refresh token requested":   {func(p url.Values) { p.Set("requested_token_type", "urn:ietf:params:oauth:token-type:refresh_token") }, "invalid_request"},
		"an unregistered resource":    {func(p url.Values) { p.Set("resource", "https://other.example") }, "invalid_target"},
		"an unknown scope":            {func(p url.Values) { p.Set("scope", "api:merchant admin:all") }, "invalid_scope"},
		"openid":                      {func(p url.Values) { p.Set("scope", "openid") }, "invalid_scope"},
	} {
		_, code := exchange(tc.mutate, key)
		require.Equal(t, tc.code, code, name)
	}
	_, code := exchange(func(url.Values) {}, nil)
	require.Equal(t, "invalid_dpop_proof", code, "a public client proves a key")
	_, code = tokenError(t, as, authtest.TokenRequest{ClientID: oauthConsole, DPoP: key, Params: url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:token-exchange"}, "subject_token": {signedIn.AccessToken},
		"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
	}})
	require.Equal(t, "unauthorized_client", code, "a client without the grant")

	require.NoError(t, as.Client.RevokeSession(ctx, iam.SystemIdentity(), owner.ID, session.SessionID))
	_, code = exchange(func(url.Values) {}, key)
	require.Equal(t, "invalid_grant", code, "an ended sign-in exchanges nothing")

	// The frontend's origin may call the token endpoint; another may not.
	for origin, allowed := range map[string]bool{oauthAdminOrigin: true, "https://evil.example": false} {
		req, _ := http.NewRequest(http.MethodOptions, as.URL+iam.OAuthTokenPath, nil)
		req.Header.Set("Origin", origin)
		req.Header.Set("Access-Control-Request-Method", http.MethodPost)
		res, err := as.HTTPClient().Do(req)
		require.NoError(t, err)
		res.Body.Close()
		if allowed {
			require.Equal(t, origin, res.Header.Get("Access-Control-Allow-Origin"))
			require.Contains(t, res.Header.Get("Access-Control-Allow-Headers"), "DPoP")
		} else {
			require.Empty(t, res.Header.Get("Access-Control-Allow-Origin"), origin)
		}
	}
}

// TestOAuthClientCredentials: a confidential client gets its own token
// (sub = client_id) carrying its grants within the resource's ceiling.
func TestOAuthClientCredentials(t *testing.T) {
	as, _, _ := newOAuthServer(t)
	tokens := as.ClientCredentials(t, oauthWorker, oauthWorkerSecret, oauthResource, []string{"api:merchant"}, nil)
	require.Equal(t, "Bearer", tokens.TokenType)
	require.Empty(t, tokens.RefreshToken)
	at := verifyIssued(t, as, tokens.AccessToken, "at+jwt")
	require.Equal(t, oauthWorker, at["sub"])
	require.Equal(t, oauthWorker, at["client_id"])
	require.Equal(t, oauthResource, at["aud"])
	require.Equal(t, "api:merchant", at["scope"])
	require.Equal(t, []any{"merchant:payouts:read"}, at["permissions"])
	require.Nil(t, at["sid"])

	key := authtest.NewDPoPKey(t)
	bound := as.ClientCredentials(t, oauthWorker, oauthWorkerSecret, "", nil, key)
	require.Equal(t, "DPoP", bound.TokenType)
	require.Equal(t, map[string]any{"jkt": key.Thumbprint()}, verifyIssued(t, as, bound.AccessToken, "at+jwt")["cnf"])

	grant := func(clientID, secret string, params url.Values) (int, string) {
		params.Set("grant_type", "client_credentials")
		return tokenError(t, as, authtest.TokenRequest{ClientID: clientID, ClientSecret: secret, Params: params})
	}
	status, code := grant(oauthWorker, "wrong-secret-0123456789", url.Values{})
	require.Equal(t, http.StatusUnauthorized, status)
	require.Equal(t, "invalid_client", code)
	_, code = grant(oauthWorker, oauthWorkerSecret, url.Values{"resource": {"https://other.example"}})
	require.Equal(t, "invalid_target", code)
	_, code = grant(oauthWorker, oauthWorkerSecret, url.Values{"scope": {"openid"}})
	require.Equal(t, "invalid_scope", code)
	_, code = grant(oauthBackend, oauthBackendToken, url.Values{})
	require.Equal(t, "unauthorized_client", code)
}
