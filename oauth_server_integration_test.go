package authkit_test

import (
	"context"
	"crypto"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/require"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/testkeys"
	"github.com/open-rails/authkit/keys"
	"github.com/open-rails/authkit/verify"
)

const (
	oauthResource     = "https://api.example.com"
	oauthConsole      = "console"
	oauthConsoleCB    = "https://console.example.com/callback"
	oauthConsoleOut   = "https://console.example.com/signed-out"
	oauthBackend      = "backend"
	oauthBackendCB    = "https://app.example.com/cb"
	oauthBackendToken = "backend-secret-0123456789-abcdefghij-0123456789"
	oauthAdminUI      = "admin-ui"
	oauthAdminOrigin  = "https://admin.example.com"
	oauthWorker       = "billing-worker"
	oauthWorkerSecret = "worker-secret-0123456789-abcdefghij-0123456789"
)

// oauthRoles gives the issuer a merchant persona in the resource server's
// vocabulary: an admin role holding all of it, a support role holding only
// subscriptions.
func oauthRoles() (*authkit.Roles, iam.Role, iam.Role) {
	roles := authkit.NewRoles()
	merchant := roles.Persona("merchant")
	merchant.Permission("subscriptions", "read")
	merchant.Permission("subscriptions", "update")
	merchant.Permission("payouts", "read")
	admin := roles.Root.Role("admin", merchant.All())
	support := roles.Root.Role("support", merchant.Resource("subscriptions").All())
	return roles, admin, support
}

func newOAuthServer(t *testing.T, opts ...authtest.Option) (*authtest.AuthorizationServer, iam.Role, iam.Role) {
	t.Helper()
	roles, admin, support := oauthRoles()
	opts = append([]authtest.Option{authtest.WithConfig(func(c *authkit.Config) {
		c.Roles = roles
		c.AuthorizationServer = authkit.AuthorizationServerConfig{
			Resources: []authkit.ResourceServerConfig{{
				ID: oauthResource, Scopes: []string{"api:merchant", "api:self"}, Permissions: []string{"merchant:*"},
			}},
			Clients: []authkit.OAuthClientConfig{
				{ID: oauthConsole, Name: "Console", RedirectURIs: []string{oauthConsoleCB}, PostLogoutRedirectURIs: []string{oauthConsoleOut}, Resources: []string{oauthResource},
					GrantTypes: []authkit.OAuthGrantType{authkit.GrantAuthorizationCode, authkit.GrantRefreshToken}},
				{ID: oauthAdminUI, Resources: []string{oauthResource}, Origins: []string{oauthAdminOrigin},
					GrantTypes: []authkit.OAuthGrantType{authkit.GrantTokenExchange}},
				{ID: oauthWorker, SecretSHA256: authtest.ClientSecretSHA256(oauthWorkerSecret), Resources: []string{oauthResource},
					GrantTypes: []authkit.OAuthGrantType{authkit.GrantClientCredentials}, Permissions: []string{"merchant:payouts:read"}},
				{ID: oauthBackend, SecretSHA256: authtest.ClientSecretSHA256(oauthBackendToken), RedirectURIs: []string{oauthBackendCB}},
			},
		}
	})}, opts...)
	return authtest.NewAuthorizationServer(t, opts...), admin, support
}

func consoleFlow() authtest.CodeFlow {
	return authtest.CodeFlow{
		ClientID: oauthConsole, RedirectURI: oauthConsoleCB, Resource: oauthResource,
		Scopes: []string{"openid", "profile", "email", "api:merchant"}, Nonce: "n-0S6_WzA2Mj",
	}
}

// TestOAuthAuthorizationCodeFlow runs the code flow end to end over HTTPS and
// verifies its tokens the way a resource server and a client would: from
// the issuer's metadata and JWKS alone.
func TestOAuthAuthorizationCodeFlow(t *testing.T) {
	as, admin, _ := newOAuthServer(t)
	ctx := context.Background()

	var meta map[string]any
	require.Equal(t, http.StatusOK, getJSON(t, as, as.URL+iam.OpenIDConfigurationPath, &meta))
	require.Equal(t, as.URL, meta["issuer"])
	require.Equal(t, as.URL+iam.OAuthAuthorizePath, meta["authorization_endpoint"])
	require.Equal(t, as.URL+iam.OAuthTokenPath, meta["token_endpoint"])
	require.Equal(t, as.URL+iam.JWKSPath, meta["jwks_uri"])
	require.Equal(t, []any{"S256"}, meta["code_challenge_methods_supported"])
	require.Equal(t, []any{"code"}, meta["response_types_supported"])
	require.Equal(t, true, meta["authorization_response_iss_parameter_supported"])
	var rfc8414 map[string]any
	require.Equal(t, http.StatusOK, getJSON(t, as, as.URL+iam.AuthorizationServerMetadataPath, &rfc8414))
	require.Equal(t, meta, rfc8414)

	owner := authtest.NewUser(t, as.Client)
	authtest.GrantRole(t, as.Client, iam.RootGroup(), iam.UserSubject(owner.ID), admin)
	tokens := as.Authorize(t, owner, consoleFlow())
	require.Equal(t, "DPoP", tokens.TokenType, "a public client's tokens are DPoP-bound")
	require.EqualValues(t, 300, tokens.ExpiresIn)
	require.Equal(t, "openid profile email api:merchant", tokens.Scope)
	require.NotEmpty(t, tokens.RefreshToken)

	at := verifyIssued(t, as, tokens.AccessToken, "at+jwt")
	require.Equal(t, as.URL, at["iss"])
	require.Equal(t, owner.ID, at["sub"])
	require.Equal(t, oauthResource, at["aud"])
	require.Equal(t, oauthConsole, at["client_id"])
	require.Equal(t, "openid profile email api:merchant", at["scope"])
	require.Equal(t, []any{"merchant:*"}, at["permissions"], "the admin role's grants, within the resource's ceiling")
	require.Equal(t, []any{"admin"}, at["roles"])
	require.Equal(t, owner.Email, at["email"])
	require.Equal(t, true, at["email_verified"])
	require.NotEmpty(t, at["jti"])
	require.NotEmpty(t, at["sid"])
	require.EqualValues(t, 300, at["exp"].(float64)-at["iat"].(float64))
	require.Equal(t, map[string]any{"jkt": tokens.DPoP.Thumbprint()}, at["cnf"])

	id := verifyIssued(t, as, tokens.IDToken, "JWT")
	require.Equal(t, []any{oauthConsole}, id["aud"])
	require.Equal(t, oauthConsole, id["azp"])
	require.Equal(t, "n-0S6_WzA2Mj", id["nonce"])
	require.Equal(t, at["sid"], id["sid"])
	require.Equal(t, owner.Username, id["preferred_username"])
	require.Equal(t, owner.Email, id["email"])

	var info map[string]any
	require.Equal(t, http.StatusOK, dpopJSON(t, as, http.MethodGet, as.URL+iam.OAuthUserInfoPath, tokens, &info))
	require.Equal(t, owner.ID, info["sub"])
	require.Equal(t, owner.Email, info["email"])

	// AuthKit's own API refuses a token minted for a resource server.
	status, _ := bearer(t, as, http.MethodGet, as.URL+as.Client.APIBase()+"/me", tokens.AccessToken)
	require.Equal(t, http.StatusUnauthorized, status)

	// A user without a role on the resource's namespace gets no permissions;
	// a narrower role, only its own.
	plain := as.Authorize(t, authtest.NewUser(t, as.Client), consoleFlow())
	require.Equal(t, []any{}, verifyIssued(t, as, plain.AccessToken, "at+jwt")["permissions"])
	require.Equal(t, []any{}, verifyIssued(t, as, plain.AccessToken, "at+jwt")["roles"])

	// Without openid there is no ID token, and userinfo refuses the token.
	flow := consoleFlow()
	flow.Scopes = []string{"api:merchant"}
	apiOnly := as.Authorize(t, authtest.NewUser(t, as.Client), flow)
	require.Empty(t, apiOnly.IDToken)
	require.Equal(t, http.StatusForbidden, dpopJSON(t, as, http.MethodGet, as.URL+iam.OAuthUserInfoPath, apiOnly, &info))
	require.Equal(t, "insufficient_scope", info["error"])

	// A confidential client authenticates with its secret, and without a
	// DPoP proof gets bearer tokens; with no resource, the access token is
	// for userinfo alone. It was not granted refresh tokens.
	backend := as.Authorize(t, authtest.NewUser(t, as.Client), authtest.CodeFlow{
		ClientID: oauthBackend, ClientSecret: oauthBackendToken, RedirectURI: oauthBackendCB, Scopes: []string{"openid"},
	})
	require.Equal(t, "Bearer", backend.TokenType)
	require.Empty(t, backend.RefreshToken)
	backendAT := verifyIssued(t, as, backend.AccessToken, "at+jwt")
	require.Equal(t, as.URL, backendAT["aud"])
	require.Nil(t, backendAT["cnf"])
	require.Equal(t, http.StatusOK, bearerJSON(t, as, http.MethodGet, as.URL+iam.OAuthUserInfoPath, backend.AccessToken, &info))
	_ = ctx
}

// TestOAuthResourceServerVerifiesAccessTokens: a resource server that trusts
// the issuer by its JWKS alone reads the token's user, client, scopes and
// permissions, and refuses a token minted for another audience.
func TestOAuthResourceServerVerifiesAccessTokens(t *testing.T) {
	as, admin, support := newOAuthServer(t)
	// The resource server's own vocabulary, as it would declare it.
	merchant := authkit.NewRoles().Persona("merchant")
	update, payouts := merchant.Permission("subscriptions", "update"), merchant.Permission("payouts", "read")
	// The handler needs the server's URL (for DPoP proofs) before it starts.
	resource := httptest.NewUnstartedServer(nil)
	t.Cleanup(resource.Close)
	v := verify.NewVerifier(verify.WithHTTPClient(as.HTTPClient()), verify.WithDPoP(memoryReplay()), verify.WithPublicURL("http://"+resource.Listener.Addr().String()))
	require.NoError(t, v.AddIssuer(as.URL, []string{oauthResource}, verify.IssuerOptions{JWKSURI: as.URL + iam.JWKSPath}))
	resource.Config.Handler = verify.Required(v)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cl, _ := verify.ClaimsFromContext(r.Context())
		id, _ := verify.VerifiedIdentity(r.Context(), v)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"subject": id.Subject, "subject_kind": id.SubjectKind, "invoker": id.Invoker.ID, "invoker_issuer": id.Invoker.Issuer,
			"credential": id.Credential.Kind, "self_invoked": id.SelfInvoked(),
			"kind": cl.Kind, "sub": cl.Subject, "user_id": cl.UserID, "client_id": cl.ClientID, "scopes": cl.Scopes,
			"roles": cl.Roles, "sid": cl.SessionID, "can_update": cl.HasPermission(update), "can_pay_out": cl.HasPermission(payouts),
			"jkt": cl.JWKThumbprint, "kind_client": cl.Kind == verify.TokenOAuthClient,
		})
	}))
	resource.Start()
	call := func(tokens authtest.OAuthTokens) (int, map[string]any) {
		req, _ := http.NewRequest(http.MethodGet, resource.URL+"/v1/merchant/subscriptions", nil)
		if tokens.DPoP != nil {
			tokens.DPoP.Authorize(t, req, tokens.AccessToken, "")
		} else {
			req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
		}
		res, err := resource.Client().Do(req)
		require.NoError(t, err)
		defer res.Body.Close()
		var out map[string]any
		require.NoError(t, json.NewDecoder(res.Body).Decode(&out))
		return res.StatusCode, out
	}

	owner := authtest.NewUser(t, as.Client)
	authtest.GrantRole(t, as.Client, iam.RootGroup(), iam.UserSubject(owner.ID), admin)
	ownerTokens := as.Authorize(t, owner, consoleFlow())
	status, got := call(ownerTokens)
	require.Equal(t, http.StatusOK, status, got)
	require.Equal(t, ownerTokens.DPoP.Thumbprint(), got["jkt"])
	require.Equal(t, string(verify.TokenUser), got["kind"])
	require.Equal(t, owner.ID, got["sub"])
	require.Empty(t, got["user_id"], "another deployment's user")
	require.Equal(t, oauthConsole, got["client_id"])
	require.Equal(t, []any{"openid", "profile", "email", "api:merchant"}, got["scopes"])
	require.Equal(t, []any{"admin"}, got["roles"])
	require.NotEmpty(t, got["sid"])
	require.Equal(t, true, got["can_update"])
	require.Equal(t, true, got["can_pay_out"])
	// The user is the subject; the client acting for them is the invoker.
	require.Equal(t, owner.ID, got["subject"])
	require.Equal(t, "user", got["subject_kind"])
	require.Equal(t, oauthConsole, got["invoker"])
	require.Equal(t, as.URL, got["invoker_issuer"])
	require.Equal(t, "access_token", got["credential"])
	require.Equal(t, false, got["self_invoked"])

	agent := authtest.NewUser(t, as.Client)
	authtest.GrantRole(t, as.Client, iam.RootGroup(), iam.UserSubject(agent.ID), support)
	_, got = call(as.Authorize(t, agent, consoleFlow()))
	require.Equal(t, true, got["can_update"])
	require.Equal(t, false, got["can_pay_out"], "the support role holds subscriptions only")

	backend := as.Authorize(t, authtest.NewUser(t, as.Client), authtest.CodeFlow{
		ClientID: oauthBackend, ClientSecret: oauthBackendToken, RedirectURI: oauthBackendCB, Scopes: []string{"openid"},
	})
	status, got = call(backend)
	require.Equal(t, http.StatusUnauthorized, status, "a token for userinfo is not for this resource")
	require.Equal(t, "bad_audience", got["error"].(map[string]any)["code"])
	status, _ = call(authtest.OAuthTokens{AccessToken: authtest.SignIn(t, as.Client, owner).AccessToken})
	require.Equal(t, http.StatusUnauthorized, status, "nor is the issuer's own sign-in")
	status, _ = call(authtest.OAuthTokens{AccessToken: ownerTokens.AccessToken})
	require.Equal(t, http.StatusUnauthorized, status, "a DPoP-bound token without its proof")
	status, _ = call(authtest.OAuthTokens{AccessToken: ownerTokens.AccessToken, DPoP: authtest.NewDPoPKey(t)})
	require.Equal(t, http.StatusUnauthorized, status, "nor with another key's")

	// A host frontend's token exchange and a machine's client credentials
	// reach the same resource server.
	exchanged := as.Exchange(t, authtest.TokenExchange{ClientID: oauthAdminUI, SubjectToken: authtest.SignIn(t, as.Client, owner).AccessToken, Scopes: []string{"api:merchant"}})
	status, got = call(exchanged)
	require.Equal(t, http.StatusOK, status, got)
	require.Equal(t, owner.ID, got["sub"])
	require.Equal(t, oauthAdminUI, got["client_id"])
	require.Equal(t, true, got["can_update"])
	machine := as.ClientCredentials(t, oauthWorker, oauthWorkerSecret, "", nil, nil)
	status, got = call(machine)
	require.Equal(t, http.StatusOK, status, got)
	require.Equal(t, oauthWorker, got["sub"])
	require.Equal(t, true, got["kind_client"])
	require.Equal(t, oauthWorker, got["subject"], "a client acting for itself is the subject")
	require.Equal(t, "application", got["subject_kind"])
	require.Equal(t, true, got["self_invoked"])
	require.Equal(t, true, got["can_pay_out"])
	require.Equal(t, false, got["can_update"], "the worker holds payouts only")
}

// TestOAuthCodeFlowRefusals pins every refusal of the authorize and token
// endpoints and of the SPA's approval.
func TestOAuthCodeFlowRefusals(t *testing.T) {
	as, _, support := newOAuthServer(t)
	user := authtest.NewUser(t, as.Client)
	authtest.GrantRole(t, as.Client, iam.RootGroup(), iam.UserSubject(user.ID), support)
	signedIn := authtest.SignIn(t, as.Client, user)
	flow := consoleFlow()

	authorize := func(q url.Values) (int, *url.URL, map[string]any) {
		t.Helper()
		res, err := as.HTTPClient().Get(as.URL + iam.OAuthAuthorizePath + "?" + q.Encode())
		require.NoError(t, err)
		defer res.Body.Close()
		body, _ := io.ReadAll(res.Body)
		var out map[string]any
		_ = json.Unmarshal(body, &out)
		loc, _ := url.Parse(res.Header.Get("Location"))
		return res.StatusCode, loc, out
	}
	good := func() url.Values {
		return url.Values{
			"response_type": {"code"}, "client_id": {oauthConsole}, "redirect_uri": {oauthConsoleCB},
			"scope": {"openid api:merchant"}, "state": {"xyz"}, "resource": {oauthResource},
			"code_challenge": {authtest.PKCEChallenge(strings.Repeat("v", 43))}, "code_challenge_method": {"S256"},
		}
	}
	t.Run("authorize answers here until the redirect URI is known good", func(t *testing.T) {
		q := good()
		q.Set("redirect_uri", "https://evil.example/cb")
		status, loc, body := authorize(q)
		require.Equal(t, http.StatusBadRequest, status)
		require.Empty(t, loc.String())
		require.Equal(t, "invalid_request", body["error"])
		q = good()
		q.Set("client_id", "nobody")
		status, loc, _ = authorize(q)
		require.Equal(t, http.StatusBadRequest, status)
		require.Empty(t, loc.String())
		q = good()
		q.Add("state", "again")
		status, _, body = authorize(q)
		require.Equal(t, http.StatusBadRequest, status)
		require.Equal(t, "invalid_request", body["error"])
	})
	t.Run("authorize returns other errors to the client", func(t *testing.T) {
		for name, tc := range map[string]struct {
			edit func(url.Values)
			code string
		}{
			"no PKCE":               {func(q url.Values) { q.Del("code_challenge"); q.Del("code_challenge_method") }, "invalid_request"},
			"plain PKCE":            {func(q url.Values) { q.Set("code_challenge_method", "plain") }, "invalid_request"},
			"implicit":              {func(q url.Values) { q.Set("response_type", "token") }, "unsupported_response_type"},
			"unknown scope":         {func(q url.Values) { q.Set("scope", "openid admin:everything") }, "invalid_scope"},
			"offline_access":        {func(q url.Values) { q.Set("scope", "openid offline_access") }, "invalid_scope"},
			"authorization_details": {func(q url.Values) { q.Set("authorization_details", `[{"type":"machine"}]`) }, "invalid_request"},
			"unregistered target":   {func(q url.Values) { q.Set("resource", "https://other.example") }, "invalid_target"},
			"two targets":           {func(q url.Values) { q.Add("resource", "https://other.example") }, "invalid_target"},
			"request object":        {func(q url.Values) { q.Set("request", "eyJ") }, "request_not_supported"},
			"form_post":             {func(q url.Values) { q.Set("response_mode", "form_post") }, "invalid_request"},
			"prompt none+login":     {func(q url.Values) { q.Set("prompt", "none login") }, "invalid_request"},
		} {
			t.Run(name, func(t *testing.T) {
				q := good()
				tc.edit(q)
				status, loc, _ := authorize(q)
				require.Equal(t, http.StatusSeeOther, status)
				require.Equal(t, "https://console.example.com", loc.Scheme+"://"+loc.Host)
				require.Equal(t, tc.code, loc.Query().Get("error"))
				require.Equal(t, "xyz", loc.Query().Get("state"))
				require.Equal(t, as.URL, loc.Query().Get("iss"))
			})
		}
	})

	consoleKey := authtest.NewDPoPKey(t)
	exchange := func(code, verifier string, mutate func(url.Values)) (int, map[string]any) {
		t.Helper()
		params := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {oauthConsoleCB}, "code_verifier": {verifier}}
		if mutate != nil {
			mutate(params)
		}
		status, body := as.Token(t, authtest.TokenRequest{ClientID: oauthConsole, Params: params, DPoP: consoleKey})
		var out map[string]any
		require.NoError(t, json.Unmarshal(body, &out), string(body))
		return status, out
	}
	codeFor := func(verifier string) string {
		t.Helper()
		id := as.BeginAuthorization(t, flow, verifier, "st")
		loc, err := url.Parse(as.Approve(t, signedIn.AccessToken, id))
		require.NoError(t, err)
		return loc.Query().Get("code")
	}
	verifier := strings.Repeat("a", 43)
	t.Run("a code is redeemed once", func(t *testing.T) {
		code := codeFor(verifier)
		status, out := exchange(code, verifier, nil)
		require.Equal(t, http.StatusOK, status, out)
		require.Equal(t, []any{"merchant:subscriptions:*"}, decodeClaims(t, out["access_token"].(string))["permissions"])
		status, out = exchange(code, verifier, nil)
		require.Equal(t, http.StatusBadRequest, status)
		require.Equal(t, "invalid_grant", out["error"])
	})
	for name, tc := range map[string]struct {
		verifier string
		mutate   func(url.Values)
		code     string
	}{
		"wrong verifier":     {strings.Repeat("b", 43), nil, "invalid_grant"},
		"short verifier":     {"abc", nil, "invalid_grant"},
		"wrong redirect_uri": {verifier, func(p url.Values) { p.Set("redirect_uri", oauthBackendCB) }, "invalid_grant"},
		"wrong resource":     {verifier, func(p url.Values) { p.Set("resource", "https://other.example") }, "invalid_target"},
		"unknown grant":      {verifier, func(p url.Values) { p.Set("grant_type", "password") }, "unsupported_grant_type"},
	} {
		t.Run(name, func(t *testing.T) {
			status, out := exchange(codeFor(verifier), tc.verifier, tc.mutate)
			require.Equal(t, tc.code, out["error"], out)
			require.GreaterOrEqual(t, status, 400)
		})
	}
	t.Run("a code redeems only for its client", func(t *testing.T) {
		status, body := as.Token(t, authtest.TokenRequest{ClientID: oauthBackend, ClientSecret: oauthBackendToken, Params: url.Values{
			"grant_type": {"authorization_code"}, "code": {codeFor(verifier)}, "redirect_uri": {oauthConsoleCB}, "code_verifier": {verifier},
		}})
		require.Equal(t, http.StatusBadRequest, status)
		require.Contains(t, string(body), `"invalid_grant"`)
	})
	t.Run("client authentication", func(t *testing.T) {
		status, body := as.Token(t, authtest.TokenRequest{ClientID: oauthBackend, ClientSecret: "wrong-secret", Params: url.Values{"grant_type": {"authorization_code"}, "code": {"x"}}})
		require.Equal(t, http.StatusUnauthorized, status, string(body))
		require.Contains(t, string(body), `"invalid_client"`)
		status, body = as.Token(t, authtest.TokenRequest{ClientID: oauthBackend, Params: url.Values{"grant_type": {"authorization_code"}, "code": {"x"}}})
		require.Equal(t, http.StatusUnauthorized, status, "a confidential client must authenticate: %s", body)
		status, body = as.Token(t, authtest.TokenRequest{ClientID: oauthConsole, Params: url.Values{"grant_type": {"authorization_code"}, "code": {"x"}, "client_secret": {"anything"}}})
		require.Equal(t, http.StatusUnauthorized, status, "a public client has no secret: %s", body)
		req, _ := http.NewRequest(http.MethodPost, as.URL+iam.OAuthTokenPath, strings.NewReader("grant_type=authorization_code&code=x"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth(oauthBackend, "wrong-secret")
		res, err := as.HTTPClient().Do(req)
		require.NoError(t, err)
		res.Body.Close()
		require.Equal(t, http.StatusUnauthorized, res.StatusCode)
		require.Equal(t, `Basic realm="authkit"`, res.Header.Get("WWW-Authenticate"), "a failed Basic authentication is challenged (RFC 6749 §5.2)")
	})
	t.Run("the token endpoint takes only a form body", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodPost, as.URL+iam.OAuthTokenPath, strings.NewReader(`{"grant_type":"authorization_code"}`))
		req.Header.Set("Content-Type", "application/json")
		res, err := as.HTTPClient().Do(req)
		require.NoError(t, err)
		res.Body.Close()
		require.Equal(t, http.StatusBadRequest, res.StatusCode)
		req, _ = http.NewRequest(http.MethodPost, as.URL+iam.OAuthTokenPath+"?code=x", strings.NewReader("grant_type=authorization_code&client_id=console"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		res, err = as.HTTPClient().Do(req)
		require.NoError(t, err)
		res.Body.Close()
		require.Equal(t, http.StatusBadRequest, res.StatusCode)
	})
	t.Run("an ended sign-in redeems nothing", func(t *testing.T) {
		other := authtest.SignIn(t, as.Client, user)
		id := as.BeginAuthorization(t, flow, verifier, "st")
		loc, err := url.Parse(as.Approve(t, other.AccessToken, id))
		require.NoError(t, err)
		claims, err := as.Client.Verify(context.Background(), other.AccessToken)
		require.NoError(t, err)
		require.NoError(t, as.Client.RevokeSession(context.Background(), iam.SystemIdentity(), user.ID, claims.SessionID))
		_, out := exchange(loc.Query().Get("code"), verifier, nil)
		require.Equal(t, "invalid_grant", out["error"])
	})
	t.Run("the SPA's answers", func(t *testing.T) {
		status, _ := postJSON(t, as, as.URL+as.Client.APIBase()+"/oauth2/authorizations/nope/approve", signedIn.AccessToken, nil)
		require.Equal(t, http.StatusNotFound, status)
		id := as.BeginAuthorization(t, flow, verifier, "st")
		status, _ = postJSON(t, as, as.URL+as.Client.APIBase()+"/oauth2/authorizations/"+id+"/approve", "", nil)
		require.Equal(t, http.StatusUnauthorized, status, "approving needs a sign-in")
		var view map[string]any
		require.Equal(t, http.StatusOK, getJSON(t, as, as.URL+as.Client.APIBase()+"/oauth2/authorizations/"+id, &view))
		require.Equal(t, "Console", view["client_name"])
		require.Equal(t, oauthResource, view["resource"])
		status, body := postJSON(t, as, as.URL+as.Client.APIBase()+"/oauth2/authorizations/"+id+"/decline", "", map[string]string{"error": "server_error"})
		require.Equal(t, http.StatusBadRequest, status, string(body))
		status, body = postJSON(t, as, as.URL+as.Client.APIBase()+"/oauth2/authorizations/"+id+"/decline", "", map[string]string{"error": "login_required"})
		require.Equal(t, http.StatusOK, status, string(body))
		var out struct {
			RedirectTo string `json:"redirect_to"`
		}
		require.NoError(t, json.Unmarshal(body, &out))
		loc, _ := url.Parse(out.RedirectTo)
		require.Equal(t, "login_required", loc.Query().Get("error"))
		require.Equal(t, "st", loc.Query().Get("state"))
		status, _ = postJSON(t, as, as.URL+as.Client.APIBase()+"/oauth2/authorizations/"+id+"/approve", signedIn.AccessToken, nil)
		require.Equal(t, http.StatusNotFound, status, "a declined request is gone")
	})
	t.Run("max_age and prompt=login ask for a fresh sign-in", func(t *testing.T) {
		stale := authtest.StaleSession(t, as.Client, signedIn.AccessToken)
		for _, extra := range []url.Values{{"max_age": {"3600"}}, {"prompt": {"login"}}} {
			q := good()
			for k, v := range extra {
				q[k] = v
			}
			status, loc, _ := authorize(q)
			require.Equal(t, http.StatusSeeOther, status)
			id := loc.Query().Get("authorization")
			status, body := postJSON(t, as, as.URL+as.Client.APIBase()+"/oauth2/authorizations/"+id+"/approve", stale, nil)
			require.Equal(t, http.StatusUnauthorized, status, string(body))
			require.Contains(t, string(body), "step_up_required")
		}
	})
}

// TestOAuthDeviceKeyTokensGrantNothing: a device-key sign-in stands on no
// session, so it neither approves an authorization request nor exchanges for
// a resource token; a workload reaches a resource through jwt-bearer.
func TestOAuthDeviceKeyTokensGrantNothing(t *testing.T) {
	as, _, _ := newOAuthServer(t, authtest.WithConfig(func(c *authkit.Config) { c.DeviceKeys.Enabled = true }))
	owner := authtest.NewUser(t, as.Client)
	dk := authtest.EnrollDeviceKey(t, as.Client, as.Outbox, owner)

	id := as.BeginAuthorization(t, consoleFlow(), strings.Repeat("v", 43), "state-dk")
	status, body := postJSON(t, as, as.URL+as.Client.APIBase()+"/oauth2/authorizations/"+url.PathEscape(id)+"/approve", dk.AccessToken, nil)
	require.Equal(t, http.StatusForbidden, status, string(body))
	require.Contains(t, as.Approve(t, authtest.SignIn(t, as.Client, owner).AccessToken, id), "code=", "the request stays pending for a session")

	status, code := tokenError(t, as, authtest.TokenRequest{ClientID: oauthAdminUI, DPoP: authtest.NewDPoPKey(t), Params: url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:token-exchange"}, "subject_token": {dk.AccessToken},
		"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
	}})
	require.Equal(t, http.StatusBadRequest, status)
	require.Equal(t, "invalid_grant", code)
}

// TestOAuthEndSessionAndCORS: RP-initiated logout ends the sign-in the ID
// token names; browser clients may call the token and userinfo endpoints
// from their own origin.
func TestOAuthEndSessionAndCORS(t *testing.T) {
	as, _, _ := newOAuthServer(t)
	user := authtest.NewUser(t, as.Client)
	tokens := as.Authorize(t, user, consoleFlow())

	req, _ := http.NewRequest(http.MethodOptions, as.URL+iam.OAuthTokenPath, nil)
	req.Header.Set("Origin", "https://console.example.com")
	req.Header.Set("Access-Control-Request-Method", "POST")
	res, err := as.HTTPClient().Do(req)
	require.NoError(t, err)
	res.Body.Close()
	require.Equal(t, http.StatusNoContent, res.StatusCode)
	require.Equal(t, "https://console.example.com", res.Header.Get("Access-Control-Allow-Origin"))
	require.Contains(t, res.Header.Get("Access-Control-Allow-Headers"), "DPoP")
	req.Header.Set("Origin", "https://evil.example")
	res, err = as.HTTPClient().Do(req)
	require.NoError(t, err)
	res.Body.Close()
	require.Empty(t, res.Header.Get("Access-Control-Allow-Origin"))

	// Only an ID token ends a sign-in: the access token a resource server
	// holds names the same sub and sid.
	for name, hint := range map[string]string{"access token": tokens.AccessToken, "garbage": "not-a-token"} {
		q := url.Values{"id_token_hint": {hint}}
		res, err := as.HTTPClient().Get(as.URL + iam.OAuthEndSessionPath + "?" + q.Encode())
		require.NoError(t, err)
		res.Body.Close()
		require.Equal(t, http.StatusBadRequest, res.StatusCode, "%s as id_token_hint is refused", name)
	}
	var stillSignedIn map[string]any
	require.Equal(t, http.StatusOK, dpopJSON(t, as, http.MethodGet, as.URL+iam.OAuthUserInfoPath, tokens, &stillSignedIn), "a refused hint ends nothing")

	q := url.Values{"id_token_hint": {tokens.IDToken}, "post_logout_redirect_uri": {"https://evil.example/out"}}
	res, err = as.HTTPClient().Get(as.URL + iam.OAuthEndSessionPath + "?" + q.Encode())
	require.NoError(t, err)
	res.Body.Close()
	require.Equal(t, http.StatusBadRequest, res.StatusCode, "an unregistered post-logout URI is refused")

	q = url.Values{"id_token_hint": {tokens.IDToken}, "post_logout_redirect_uri": {oauthConsoleOut}, "state": {"bye"}}
	res, err = as.HTTPClient().Get(as.URL + iam.OAuthEndSessionPath + "?" + q.Encode())
	require.NoError(t, err)
	res.Body.Close()
	require.Equal(t, http.StatusSeeOther, res.StatusCode)
	require.Equal(t, oauthConsoleOut+"?state=bye", res.Header.Get("Location"))

	var info map[string]any
	require.Equal(t, http.StatusUnauthorized, dpopJSON(t, as, http.MethodGet, as.URL+iam.OAuthUserInfoPath, tokens, &info))
	require.Equal(t, "invalid_token", info["error"])
	require.Contains(t, info["error_description"], "has ended", "the proven token is refused because the sign-in ended")
}

// TestOAuthSigningKeyRotationMidFlow: a code approved under one signing key
// redeems after a rotation for tokens a verifier checks against the JWKS it
// refetches.
func TestOAuthSigningKeyRotationMidFlow(t *testing.T) {
	src := &rotatingKeys{}
	src.set(testkeys.RSA("key-1"))
	as, _, _ := newOAuthServer(t, authtest.WithDeps(func(d *authkit.Deps) { d.KeySource = src }))
	user := authtest.NewUser(t, as.Client)
	signedIn := authtest.SignIn(t, as.Client, user)
	verifier := strings.Repeat("r", 43)
	id := as.BeginAuthorization(t, consoleFlow(), verifier, "st")
	loc, err := url.Parse(as.Approve(t, signedIn.AccessToken, id))
	require.NoError(t, err)

	src.set(testkeys.EC("key-2"))
	status, body := as.Token(t, authtest.TokenRequest{ClientID: oauthConsole, DPoP: authtest.NewDPoPKey(t), Params: url.Values{
		"grant_type": {"authorization_code"}, "code": {loc.Query().Get("code")}, "redirect_uri": {oauthConsoleCB}, "code_verifier": {verifier},
	}})
	require.Equal(t, http.StatusOK, status, string(body))
	var tokens authtest.OAuthTokens
	require.NoError(t, json.Unmarshal(body, &tokens))
	_, header := verifyIssuedHeader(t, as, tokens.AccessToken, "at+jwt")
	require.Equal(t, "key-2", header.KeyID)
	verifyIssued(t, as, tokens.IDToken, "JWT")
}

// rotatingKeys is a keys.Source whose active key the test swaps; every key
// it has held stays published.
type rotatingKeys struct {
	active atomic.Pointer[keys.Signer]
	all    atomic.Pointer[map[string]crypto.PublicKey]
}

func (r *rotatingKeys) set(s keys.Signer) {
	public := map[string]crypto.PublicKey{}
	if prev := r.all.Load(); prev != nil {
		for k, v := range *prev {
			public[k] = v
		}
	}
	public[s.KID()] = s.Public()
	r.all.Store(&public)
	r.active.Store(&s)
}

func (r *rotatingKeys) ActiveSigner() keys.Signer { return *r.active.Load() }
func (r *rotatingKeys) PublicKeys() map[string]crypto.PublicKey {
	out := map[string]crypto.PublicKey{}
	for k, v := range *r.all.Load() {
		out[k] = v
	}
	return out
}

// verifyIssued verifies a token as a resource server or client would, from
// the issuer's metadata and JWKS alone, and returns its claims.
func verifyIssued(t *testing.T, as *authtest.AuthorizationServer, token, typ string) map[string]any {
	t.Helper()
	claims, _ := verifyIssuedHeader(t, as, token, typ)
	return claims
}

func verifyIssuedHeader(t *testing.T, as *authtest.AuthorizationServer, token, typ string) (map[string]any, jose.Header) {
	t.Helper()
	var meta struct {
		Issuer  string `json:"issuer"`
		JWKSURI string `json:"jwks_uri"`
	}
	require.Equal(t, http.StatusOK, getJSON(t, as, as.URL+iam.OpenIDConfigurationPath, &meta))
	var set jose.JSONWebKeySet
	require.Equal(t, http.StatusOK, getJSON(t, as, meta.JWKSURI, &set))
	jws, err := jose.ParseSigned(token, []jose.SignatureAlgorithm{jose.RS256, jose.ES256, jose.EdDSA})
	require.NoError(t, err)
	require.Len(t, jws.Signatures, 1)
	header := jws.Signatures[0].Protected
	require.Equal(t, typ, header.ExtraHeaders["typ"])
	keys := set.Key(header.KeyID)
	require.Len(t, keys, 1, "the JWKS publishes the signing key")
	payload, err := jws.Verify(keys[0])
	require.NoError(t, err)
	var claims map[string]any
	require.NoError(t, json.Unmarshal(payload, &claims))
	require.Equal(t, meta.Issuer, claims["iss"])
	require.Greater(t, claims["exp"].(float64), float64(time.Now().Unix()))
	return claims, header
}

// decodeClaims reads a JWT's claims without verifying it.
func decodeClaims(t *testing.T, token string) map[string]any {
	t.Helper()
	jws, err := jose.ParseSigned(token, []jose.SignatureAlgorithm{jose.RS256, jose.ES256, jose.EdDSA})
	require.NoError(t, err)
	var claims map[string]any
	require.NoError(t, json.Unmarshal(jws.UnsafePayloadWithoutVerification(), &claims))
	return claims
}

// dpopJSON calls u with tokens' DPoP-bound access token and a fresh proof.
func dpopJSON(t *testing.T, as *authtest.AuthorizationServer, method, u string, tokens authtest.OAuthTokens, out any) int {
	t.Helper()
	req, _ := http.NewRequest(method, u, nil)
	tokens.DPoP.Authorize(t, req, tokens.AccessToken, "")
	res, err := as.HTTPClient().Do(req)
	require.NoError(t, err)
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	require.NoError(t, json.Unmarshal(body, out), "%d %s", res.StatusCode, body)
	return res.StatusCode
}

// memoryReplay is a single-process DPoP replay store.
func memoryReplay() func(context.Context, string, time.Duration) (bool, error) {
	var mu sync.Mutex
	seen := map[string]bool{}
	return func(_ context.Context, key string, _ time.Duration) (bool, error) {
		mu.Lock()
		defer mu.Unlock()
		if seen[key] {
			return false, nil
		}
		seen[key] = true
		return true, nil
	}
}

func getJSON(t *testing.T, as *authtest.AuthorizationServer, u string, out any) int {
	t.Helper()
	return bearerJSON(t, as, http.MethodGet, u, "", out)
}

func bearerJSON(t *testing.T, as *authtest.AuthorizationServer, method, u, token string, out any) int {
	t.Helper()
	status, body := bearer(t, as, method, u, token)
	require.NoError(t, json.Unmarshal(body, out), "%d %s", status, body)
	return status
}

func bearer(t *testing.T, as *authtest.AuthorizationServer, method, u, token string) (int, []byte) {
	t.Helper()
	req, _ := http.NewRequest(method, u, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res, err := as.HTTPClient().Do(req)
	require.NoError(t, err)
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	return res.StatusCode, body
}

func postJSON(t *testing.T, as *authtest.AuthorizationServer, u, token string, body any) (int, []byte) {
	t.Helper()
	var r io.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		r = strings.NewReader(string(raw))
	}
	req, _ := http.NewRequest(http.MethodPost, u, r)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res, err := as.HTTPClient().Do(req)
	require.NoError(t, err)
	defer res.Body.Close()
	out, _ := io.ReadAll(res.Body)
	return res.StatusCode, out
}
