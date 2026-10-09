package authkit_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/devicekey"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/verify"
)

const (
	grantMachine     = "hub-cli"
	grantMachineCB   = "https://hub.example.com/cli/callback"
	grantMachineType = "machine"
	grantSubmitType  = "job_submission"
	grantPayoutType  = "payout_batch"
	grantClaim       = "https://hub.example.com/grant"
	machineDetails   = `[{"type":"machine","machine_id":"m-1","repositories":["acme/app"]}]`
	submitDetails    = `[{"type":"job_submission","workflow":"render"}]`
	payoutDetails    = `[{"type":"payout_batch","limit":"100.00"}]`
)

// newGrantServer is newOAuthServer with g deciding every grant, a
// key-bound, offline machine client with its own lifetimes, and
// authorization_details types on the exchange and client-credentials
// clients.
func newGrantServer(t *testing.T, g *authtest.GrantAuthorizer, opts ...authtest.Option) (*authtest.AuthorizationServer, iam.Role, iam.Role) {
	t.Helper()
	opts = append([]authtest.Option{
		authtest.WithDeps(func(d *authkit.Deps) { d.OAuthGrants = g.Authorize }),
		authtest.WithConfig(func(c *authkit.Config) {
			as := &c.AuthorizationServer
			for i := range as.Clients {
				switch as.Clients[i].ID {
				case oauthAdminUI:
					as.Clients[i].AuthorizationDetailsTypes = []string{grantSubmitType}
				case oauthWorker:
					as.Clients[i].AuthorizationDetailsTypes = []string{grantPayoutType}
				}
			}
			as.Clients = append(as.Clients, authkit.OAuthClientConfig{
				ID: grantMachine, Name: "Hub CLI", RedirectURIs: []string{grantMachineCB}, Resources: []string{oauthResource},
				GrantTypes:                []authkit.OAuthGrantType{authkit.GrantAuthorizationCode, authkit.GrantRefreshToken},
				AuthorizationDetailsTypes: []string{grantMachineType}, Offline: true, KeyBound: true,
				AccessTokenTTL: time.Minute, RefreshTokenTTL: 7 * 24 * time.Hour,
			})
		}),
	}, opts...)
	return newOAuthServer(t, opts...)
}

func machineFlow(key *authtest.DPoPKey) authtest.CodeFlow {
	return authtest.CodeFlow{
		ClientID: grantMachine, RedirectURI: grantMachineCB, Resource: oauthResource,
		Scopes: []string{"openid", "api:merchant", "offline_access"}, AuthorizationDetails: machineDetails, DPoP: key,
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	raw, err := json.Marshal(v)
	require.NoError(t, err)
	return string(raw)
}

// authorizeError sends an authorization request and returns the error the
// client's redirect carries ("" when it went to the SPA).
func authorizeError(t *testing.T, as *authtest.AuthorizationServer, f authtest.CodeFlow, dpopJKT, prompt string) string {
	t.Helper()
	q := url.Values{
		"response_type": {"code"}, "client_id": {f.ClientID}, "redirect_uri": {f.RedirectURI},
		"scope": {strings.Join(f.Scopes, " ")}, "code_challenge": {authtest.PKCEChallenge("v")}, "code_challenge_method": {"S256"},
	}
	if f.Resource != "" {
		q.Set("resource", f.Resource)
	}
	if f.AuthorizationDetails != "" {
		q.Set("authorization_details", f.AuthorizationDetails)
	}
	if dpopJKT != "" {
		q.Set("dpop_jkt", dpopJKT)
	}
	if prompt != "" {
		q.Set("prompt", prompt)
	}
	res, err := as.HTTPClient().Get(as.URL + iam.OAuthAuthorizePath + "?" + q.Encode())
	require.NoError(t, err)
	res.Body.Close()
	require.Equal(t, http.StatusSeeOther, res.StatusCode)
	location, err := url.Parse(res.Header.Get("Location"))
	require.NoError(t, err)
	return location.Query().Get("error")
}

// TestOAuthGrantAuthorizerDecidesEveryGrant: the host's grant authorizer
// sees every consent, refresh, token exchange and client credentials grant,
// with its authorization_details, key and grant id, and its decision is
// what the tokens carry.
func TestOAuthGrantAuthorizerDecidesEveryGrant(t *testing.T) {
	g := &authtest.GrantAuthorizer{}
	as, admin, _ := newGrantServer(t, g)
	decide := func(perms ...string) func(iam.OAuthGrantRequest) (iam.OAuthGrantDecision, error) {
		return func(req iam.OAuthGrantRequest) (iam.OAuthGrantDecision, error) {
			return iam.OAuthGrantDecision{Permissions: perms, Claims: map[string]any{grantClaim: map[string]any{"grant": req.GrantID, "kind": string(req.Kind)}}}, nil
		}
	}
	g.Decide = decide("merchant:subscriptions:read", "hub:jobs:run")

	var meta map[string]any
	require.Equal(t, http.StatusOK, getJSON(t, as, as.URL+iam.OpenIDConfigurationPath, &meta))
	require.ElementsMatch(t, []any{grantMachineType, grantSubmitType, grantPayoutType}, meta["authorization_details_types_supported"])
	require.Contains(t, meta["scopes_supported"], "offline_access")

	owner := authtest.NewUser(t, as.Client)
	authtest.GrantRole(t, as.Client, iam.RootGroup(), iam.UserSubject(owner.ID), admin)
	signedIn := authtest.SignIn(t, as.Client, owner)
	key := authtest.NewDPoPKey(t)

	// The consent screen shows what the client asks the user to grant.
	pendingID := as.BeginAuthorization(t, machineFlow(key), "0123456789012345678901234567890123456789abc", "state-1")
	var pending map[string]any
	require.Equal(t, http.StatusOK, bearerJSON(t, as, http.MethodGet, as.URL+as.Client.APIBase()+"/oauth2/authorizations/"+pendingID, signedIn.AccessToken, &pending))
	require.JSONEq(t, machineDetails, mustJSON(t, pending["authorization_details"]))

	tokens := as.AuthorizeAs(t, signedIn, machineFlow(key))
	consent, ok := g.Last(iam.OAuthGrantConsent)
	require.True(t, ok)
	require.Len(t, consent.GrantID, 36)
	require.Equal(t, grantMachine, consent.ClientID)
	require.Equal(t, owner.ID, consent.UserID)
	require.NotEmpty(t, consent.SessionID)
	require.Equal(t, oauthResource, consent.Resource)
	require.ElementsMatch(t, []string{"openid", "api:merchant", "offline_access"}, consent.Scopes)
	require.JSONEq(t, machineDetails, string(consent.AuthorizationDetails))
	require.Equal(t, key.Thumbprint(), consent.JWKThumbprint)
	require.True(t, consent.Offline)

	require.JSONEq(t, machineDetails, string(tokens.AuthorizationDetails))
	require.EqualValues(t, 60, tokens.ExpiresIn, "the client's own access token lifetime")
	at := verifyIssued(t, as, tokens.AccessToken, "at+jwt")
	require.Equal(t, []any{"merchant:subscriptions:read"}, at["permissions"], "the decision, within the resource's ceiling")
	require.Equal(t, map[string]any{"grant": consent.GrantID, "kind": "consent"}, at[grantClaim])
	require.JSONEq(t, machineDetails, mustJSON(t, at["authorization_details"]))
	require.Equal(t, map[string]any{"jkt": key.Thumbprint()}, at["cnf"])
	require.Nil(t, at["sid"], "an offline grant names no sign-in")
	require.Nil(t, decodeClaims(t, tokens.IDToken)["sid"])
	require.EqualValues(t, 60, at["exp"].(float64)-at["iat"].(float64))

	// Every refresh is decided again, for the same grant and key.
	g.Decide = decide("merchant:payouts:read")
	refreshed := as.Refresh(t, grantMachine, "", tokens)
	refresh, _ := g.Last(iam.OAuthGrantRefresh)
	require.Equal(t, consent.GrantID, refresh.GrantID)
	require.Equal(t, owner.ID, refresh.UserID)
	require.JSONEq(t, machineDetails, string(refresh.AuthorizationDetails))
	require.Equal(t, key.Thumbprint(), refresh.JWKThumbprint)
	require.True(t, refresh.Offline)
	at = verifyIssued(t, as, refreshed.AccessToken, "at+jwt")
	require.Equal(t, []any{"merchant:payouts:read"}, at["permissions"])
	require.Equal(t, "refresh_token", at[grantClaim].(map[string]any)["kind"])
	require.JSONEq(t, machineDetails, string(refreshed.AuthorizationDetails))

	// A decision without permissions grants the user's live ones.
	g.Decide = nil
	refreshed = as.Refresh(t, grantMachine, "", refreshed)
	at = verifyIssued(t, as, refreshed.AccessToken, "at+jwt")
	require.Equal(t, []any{"merchant:*"}, at["permissions"])
	require.Nil(t, at[grantClaim])

	// Token exchange is decided, and names the client acting for the user.
	exchanged := as.Exchange(t, authtest.TokenExchange{ClientID: oauthAdminUI, SubjectToken: signedIn.AccessToken, Scopes: []string{"api:merchant"}, AuthorizationDetails: submitDetails})
	x, _ := g.Last(iam.OAuthGrantTokenExchange)
	require.Empty(t, x.GrantID, "an exchange has no refresh tokens")
	require.Equal(t, oauthAdminUI, x.ClientID)
	require.Equal(t, owner.ID, x.UserID)
	require.Equal(t, consent.SessionID, x.SessionID)
	require.JSONEq(t, submitDetails, string(x.AuthorizationDetails))
	require.Equal(t, exchanged.DPoP.Thumbprint(), x.JWKThumbprint)
	at = verifyIssued(t, as, exchanged.AccessToken, "at+jwt")
	require.Equal(t, map[string]any{"sub": oauthAdminUI}, at["act"])
	require.JSONEq(t, submitDetails, mustJSON(t, at["authorization_details"]))
	require.JSONEq(t, submitDetails, string(exchanged.AuthorizationDetails))
	require.NotEmpty(t, at["sid"], "an exchange stands on the sign-in")

	// Client credentials are decided; the decision may replace the client's
	// own permissions, still within the resource's ceiling.
	machine := as.RequestClientCredentials(t, authtest.ClientCredentialsRequest{ClientID: oauthWorker, ClientSecret: oauthWorkerSecret, AuthorizationDetails: payoutDetails})
	cc, _ := g.Last(iam.OAuthGrantClientCredentials)
	require.Equal(t, oauthWorker, cc.ClientID)
	require.Empty(t, cc.UserID)
	require.Empty(t, cc.GrantID)
	require.JSONEq(t, payoutDetails, string(cc.AuthorizationDetails))
	at = verifyIssued(t, as, machine.AccessToken, "at+jwt")
	require.JSONEq(t, payoutDetails, mustJSON(t, at["authorization_details"]))
	require.Equal(t, []any{"merchant:payouts:read"}, at["permissions"])
	require.Nil(t, at["act"])
	g.Decide = decide("merchant:subscriptions:read", "hub:queue:drain")
	machine = as.RequestClientCredentials(t, authtest.ClientCredentialsRequest{ClientID: oauthWorker, ClientSecret: oauthWorkerSecret})
	require.Equal(t, []any{"merchant:subscriptions:read"}, verifyIssued(t, as, machine.AccessToken, "at+jwt")["permissions"])

	// A repeated member is granted as checked, never as another parser
	// might read it.
	g.Decide = nil
	machine = as.RequestClientCredentials(t, authtest.ClientCredentialsRequest{ClientID: oauthWorker, ClientSecret: oauthWorkerSecret,
		AuthorizationDetails: `[{"type":"admin","type":"payout_batch"}]`})
	require.Equal(t, `[{"type":"payout_batch"}]`, string(machine.AuthorizationDetails))
	require.Equal(t, `[{"type":"payout_batch"}]`, mustJSON(t, verifyIssued(t, as, machine.AccessToken, "at+jwt")["authorization_details"]))

	// The authorizer may rewrite the details it grants.
	g.Decide = func(req iam.OAuthGrantRequest) (iam.OAuthGrantDecision, error) {
		return iam.OAuthGrantDecision{AuthorizationDetails: json.RawMessage(`[{"type":"payout_batch","limit":"10.00"}]`)}, nil
	}
	machine = as.RequestClientCredentials(t, authtest.ClientCredentialsRequest{ClientID: oauthWorker, ClientSecret: oauthWorkerSecret, AuthorizationDetails: payoutDetails})
	require.JSONEq(t, `[{"type":"payout_batch","limit":"10.00"}]`, string(machine.AuthorizationDetails))
}

// TestOAuthGrantAuthorizerRefusals: a refusal is the protocol's answer at
// each step and ends a refreshed grant; an outage leaves the grant as it was;
// a decision cannot reach past the user's live AuthKit permissions.
func TestOAuthGrantAuthorizerRefusals(t *testing.T) {
	g := &authtest.GrantAuthorizer{}
	as, admin, support := newGrantServer(t, g)
	ctx := context.Background()
	owner := authtest.NewUser(t, as.Client)
	authtest.GrantRole(t, as.Client, iam.RootGroup(), iam.UserSubject(owner.ID), admin)
	signedIn := authtest.SignIn(t, as.Client, owner)
	refuse := func(kind iam.OAuthGrantKind, err error) func(iam.OAuthGrantRequest) (iam.OAuthGrantDecision, error) {
		return func(req iam.OAuthGrantRequest) (iam.OAuthGrantDecision, error) {
			if req.Kind == kind {
				return iam.OAuthGrantDecision{}, err
			}
			return iam.OAuthGrantDecision{}, nil
		}
	}
	outage := errors.New("policy store down")

	// Consent: a refusal sends the client access_denied; an outage keeps the
	// request pending, so a retry can still approve it.
	g.Decide = refuse(iam.OAuthGrantConsent, iam.ErrOAuthGrantRefused)
	callback := as.Consent(t, signedIn, machineFlow(authtest.NewDPoPKey(t)))
	require.Equal(t, "access_denied", callback.Query().Get("error"))
	require.Empty(t, callback.Query().Get("code"))
	g.Decide = refuse(iam.OAuthGrantConsent, outage)
	id := as.BeginAuthorization(t, machineFlow(authtest.NewDPoPKey(t)), "0123456789012345678901234567890123456789abc", "state-2")
	approve := as.URL + as.Client.APIBase() + "/oauth2/authorizations/" + url.PathEscape(id) + "/approve"
	status, body := postJSON(t, as, approve, signedIn.AccessToken, nil)
	require.Equal(t, http.StatusServiceUnavailable, status, string(body))
	require.Contains(t, string(body), "oauth_grant_authorizer_unavailable")
	g.Decide = nil
	require.Contains(t, as.Approve(t, signedIn.AccessToken, id), "code=")

	// Refresh: an outage answers temporarily_unavailable and the token still
	// works; a refusal ends the grant for good.
	key := authtest.NewDPoPKey(t)
	tokens := as.AuthorizeAs(t, signedIn, machineFlow(key))
	refreshReq := func(tokens authtest.OAuthTokens) authtest.TokenRequest {
		return authtest.TokenRequest{ClientID: grantMachine, DPoP: tokens.DPoP, Params: url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tokens.RefreshToken}}}
	}
	g.Decide = refuse(iam.OAuthGrantRefresh, outage)
	status, code := tokenError(t, as, refreshReq(tokens))
	require.Equal(t, http.StatusServiceUnavailable, status)
	require.Equal(t, "temporarily_unavailable", code)
	g.Decide = nil
	tokens = as.Refresh(t, grantMachine, "", tokens)
	g.Decide = refuse(iam.OAuthGrantRefresh, iam.ErrOAuthGrantRefused)
	_, code = tokenError(t, as, refreshReq(tokens))
	require.Equal(t, "invalid_grant", code)
	g.Decide = nil
	_, code = tokenError(t, as, refreshReq(tokens))
	require.Equal(t, "invalid_grant", code, "a refused grant stays ended")

	// Token exchange and client credentials.
	exchange := func() (int, string) {
		return tokenError(t, as, authtest.TokenRequest{ClientID: oauthAdminUI, DPoP: authtest.NewDPoPKey(t), Params: url.Values{
			"grant_type": {"urn:ietf:params:oauth:grant-type:token-exchange"}, "subject_token": {signedIn.AccessToken},
			"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
		}})
	}
	g.Decide = refuse(iam.OAuthGrantTokenExchange, iam.ErrOAuthGrantRefused)
	_, code = exchange()
	require.Equal(t, "invalid_grant", code)
	g.Decide = refuse(iam.OAuthGrantTokenExchange, outage)
	status, code = exchange()
	require.Equal(t, http.StatusServiceUnavailable, status)
	require.Equal(t, "temporarily_unavailable", code)
	clientCredentials := func(params url.Values) (int, string) {
		params.Set("grant_type", "client_credentials")
		return tokenError(t, as, authtest.TokenRequest{ClientID: oauthWorker, ClientSecret: oauthWorkerSecret, Params: params})
	}
	g.Decide = refuse(iam.OAuthGrantClientCredentials, iam.ErrOAuthGrantRefused)
	_, code = clientCredentials(url.Values{})
	require.Equal(t, "unauthorized_client", code)
	g.Decide = refuse(iam.OAuthGrantClientCredentials, outage)
	status, code = clientCredentials(url.Values{})
	require.Equal(t, http.StatusServiceUnavailable, status)
	require.Equal(t, "temporarily_unavailable", code)

	// A decision granting an AuthKit persona's permission the user does not
	// hold refuses the grant; the host's own vocabulary is the host's call.
	agent := authtest.NewUser(t, as.Client)
	authtest.GrantRole(t, as.Client, iam.RootGroup(), iam.UserSubject(agent.ID), support)
	agentIn := authtest.SignIn(t, as.Client, agent)
	g.Decide = func(iam.OAuthGrantRequest) (iam.OAuthGrantDecision, error) {
		return iam.OAuthGrantDecision{Permissions: []string{"merchant:payouts:read"}}, nil
	}
	_, code = tokenError(t, as, authtest.TokenRequest{ClientID: oauthAdminUI, DPoP: authtest.NewDPoPKey(t), Params: url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:token-exchange"}, "subject_token": {agentIn.AccessToken},
		"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
	}})
	require.Equal(t, "invalid_grant", code, "support does not hold payouts")
	callback = as.Consent(t, agentIn, machineFlow(authtest.NewDPoPKey(t)))
	require.NotEmpty(t, callback.Query().Get("code"), "consent is the host's; the mint checks the user")
	g.Decide = func(iam.OAuthGrantRequest) (iam.OAuthGrantDecision, error) {
		return iam.OAuthGrantDecision{Permissions: []string{"merchant:subscriptions:update"}}, nil
	}
	agentTokens := as.AuthorizeAs(t, agentIn, machineFlow(authtest.NewDPoPKey(t)))
	authtest.RevokeRole(t, as.Client, iam.RootGroup(), iam.UserSubject(agent.ID), support)
	_, code = tokenError(t, as, refreshReq(agentTokens))
	require.Equal(t, "invalid_grant", code, "the permission is checked live at every refresh")

	// A malformed decision is the host's bug: the grant cannot be decided.
	for name, d := range map[string]iam.OAuthGrantDecision{
		"bare claim name":     {Claims: map[string]any{"grant": "x"}},
		"registered claim":    {Claims: map[string]any{"sub": "someone-else"}},
		"relative claim name": {Claims: map[string]any{"/grant": "x"}},
		"negative lifetime":   {MaxLifetime: -time.Second},
		"invalid details":     {AuthorizationDetails: json.RawMessage(`{"type":"machine"}`)},
		"invalid permission":  {Permissions: []string{"merchant:*:read"}},
		"undeclared type":     {AuthorizationDetails: json.RawMessage(submitDetails)},
	} {
		g.Decide = func(iam.OAuthGrantRequest) (iam.OAuthGrantDecision, error) { return d, nil }
		status, code = clientCredentials(url.Values{})
		require.Equal(t, http.StatusServiceUnavailable, status, name)
		require.Equal(t, "temporarily_unavailable", code, name)
	}

	// authorization_details the client did not declare, or malformed, never
	// reach the authorizer.
	g.Decide = nil
	before := len(g.Requests())
	flow := machineFlow(authtest.NewDPoPKey(t))
	for name, details := range map[string]string{
		"undeclared type":  submitDetails,
		"not an array":     `{"type":"machine"}`,
		"empty array":      `[]`,
		"untyped":          `[{"machine_id":"m-1"}]`,
		"not json":         `[{"type":`,
		"too many entries": "[" + strings.Repeat(`{"type":"machine"},`, 16) + `{"type":"machine"}]`,
	} {
		flow.AuthorizationDetails = details
		require.Equal(t, "invalid_authorization_details", authorizeError(t, as, flow, flow.DPoP.Thumbprint(), ""), name)
	}
	flow = consoleFlow()
	flow.AuthorizationDetails = machineDetails
	require.Equal(t, "invalid_authorization_details", authorizeError(t, as, flow, "", ""), "the console declares no types")
	_, code = clientCredentials(url.Values{"authorization_details": {submitDetails}})
	require.Equal(t, "invalid_authorization_details", code)
	_, code = tokenError(t, as, authtest.TokenRequest{ClientID: grantMachine, DPoP: tokens.DPoP, Params: url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {tokens.RefreshToken}, "authorization_details": {machineDetails},
	}})
	require.Equal(t, "invalid_request", code, "details are granted at consent, not widened at refresh")
	require.Len(t, g.Requests(), before)
	_ = ctx
}

// TestOAuthOfflineGrants: an offline grant's refresh tokens outlive the
// sign-in, carry the consent's assurance, and end when the account's
// credentials change, the account is banned, or the host revokes the grant.
func TestOAuthOfflineGrants(t *testing.T) {
	g := &authtest.GrantAuthorizer{}
	as, admin, _ := newGrantServer(t, g)
	ctx := context.Background()
	owner := authtest.NewUser(t, as.Client)
	authtest.GrantRole(t, as.Client, iam.RootGroup(), iam.UserSubject(owner.ID), admin)
	refreshReq := func(tokens authtest.OAuthTokens) authtest.TokenRequest {
		return authtest.TokenRequest{ClientID: grantMachine, DPoP: tokens.DPoP, Params: url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tokens.RefreshToken}}}
	}
	signOut := func(signedIn iam.TokenSet) {
		claims, err := as.Client.Verify(ctx, signedIn.AccessToken)
		require.NoError(t, err)
		require.NoError(t, as.Client.RevokeSession(ctx, iam.SystemActor(), owner.ID, claims.SessionID))
	}

	// Signing out of the laptop leaves the machine's grant standing.
	signedIn := authtest.SignIn(t, as.Client, owner)
	tokens := as.AuthorizeAs(t, signedIn, machineFlow(authtest.NewDPoPKey(t)))
	consentAt := verifyIssued(t, as, tokens.AccessToken, "at+jwt")
	signOut(signedIn)
	tokens = as.Refresh(t, grantMachine, "", tokens)
	at := verifyIssued(t, as, tokens.AccessToken, "at+jwt")
	require.Equal(t, []any{"merchant:*"}, at["permissions"], "the user's permissions, read live without a session")
	require.Nil(t, at["sid"])
	require.Equal(t, consentAt["auth_time"], at["auth_time"], "the consent's sign-in assurance")
	require.Equal(t, consentAt["amr"], at["amr"])
	var info map[string]any
	require.Equal(t, http.StatusOK, dpopJSON(t, as, http.MethodGet, as.URL+iam.OAuthUserInfoPath, tokens, &info), info)
	require.Equal(t, owner.ID, info["sub"], "userinfo serves an offline grant's token")

	// A grant without offline_access ends with its sign-in.
	online := authtest.SignIn(t, as.Client, owner)
	flow := machineFlow(authtest.NewDPoPKey(t))
	flow.Scopes = []string{"api:merchant"}
	onlineTokens := as.AuthorizeAs(t, online, flow)
	require.NotEmpty(t, verifyIssued(t, as, onlineTokens.AccessToken, "at+jwt")["sid"])
	signOut(online)
	_, code := tokenError(t, as, refreshReq(onlineTokens))
	require.Equal(t, "invalid_grant", code)

	// The host revokes a grant by the id its authorizer was given.
	revokedTokens := as.AuthorizeAs(t, authtest.SignIn(t, as.Client, owner), machineFlow(authtest.NewDPoPKey(t)))
	consent, _ := g.Last(iam.OAuthGrantConsent)
	require.NoError(t, as.Client.RevokeOAuthGrant(ctx, consent.GrantID))
	_, code = tokenError(t, as, refreshReq(revokedTokens))
	require.Equal(t, "invalid_grant", code)
	require.NoError(t, as.Client.RevokeOAuthGrant(ctx, consent.GrantID), "an ended grant is not an error")
	require.NoError(t, as.Client.RevokeOAuthGrant(ctx, "0199b1a2-7c3d-7e4f-8a9b-0c1d2e3f4a5b"), "nor an unknown one")
	require.Error(t, as.Client.RevokeOAuthGrant(ctx, "not-a-grant"))
	tokens = as.Refresh(t, grantMachine, "", tokens) // other grants stand

	// Containing the account (RevokeAccountSessions) ends its offline
	// grants; one granted afterwards stands.
	contained := as.AuthorizeAs(t, authtest.SignIn(t, as.Client, owner), machineFlow(authtest.NewDPoPKey(t)))
	_, err := as.Client.RevokeAccountSessions(ctx, iam.SystemActor(), owner.ID)
	require.NoError(t, err)
	_, code = tokenError(t, as, refreshReq(contained))
	require.Equal(t, "invalid_grant", code)
	_, code = tokenError(t, as, refreshReq(tokens))
	require.Equal(t, "invalid_grant", code)
	tokens = as.AuthorizeAs(t, authtest.SignIn(t, as.Client, owner), machineFlow(authtest.NewDPoPKey(t)))
	tokens = as.Refresh(t, grantMachine, "", tokens)

	// Changing the password ends offline grants.
	fresh := authtest.SignIn(t, as.Client, owner)
	status, body := putJSON(t, as, as.URL+as.Client.APIBase()+"/me/password", fresh.AccessToken, map[string]string{"new_password": "Another-horse-battery-98"})
	require.Equal(t, http.StatusNoContent, status, string(body))
	_, code = tokenError(t, as, refreshReq(tokens))
	require.Equal(t, "invalid_grant", code)

	// So does a ban.
	owner.Password = "Another-horse-battery-98"
	banned := as.AuthorizeAs(t, authtest.SignIn(t, as.Client, owner), machineFlow(authtest.NewDPoPKey(t)))
	require.NoError(t, as.Client.Ban(ctx, iam.SystemActor(), owner.ID, iam.Ban{Reason: "test"}))
	_, code = tokenError(t, as, refreshReq(banned))
	require.Equal(t, "invalid_grant", code)

	// Nor is either granted without the user: prompt=none needs consent.
	silent := machineFlow(authtest.NewDPoPKey(t))
	require.Equal(t, "consent_required", authorizeError(t, as, silent, silent.DPoP.Thumbprint(), "none"))
	silent.Scopes = []string{"api:merchant"}
	require.Equal(t, "consent_required", authorizeError(t, as, silent, silent.DPoP.Thumbprint(), "none"), "authorization_details too")
	silent.AuthorizationDetails = ""
	require.Empty(t, authorizeError(t, as, silent, silent.DPoP.Thumbprint(), "none"))

	// offline_access is only for clients declared Offline.
	console := consoleFlow()
	console.Scopes = append(console.Scopes, "offline_access")
	require.Equal(t, "invalid_scope", authorizeError(t, as, console, authtest.NewDPoPKey(t).Thumbprint(), ""))
}

// TestOAuthGrantLifetimesAndKeys: per-client lifetimes, the decision's
// lifetime cap on every token of the grant, and key-bound grants that only
// ever redeem with their key.
func TestOAuthGrantLifetimesAndKeys(t *testing.T) {
	g := &authtest.GrantAuthorizer{}
	as, admin, _ := newGrantServer(t, g, authtest.WithConfig(func(c *authkit.Config) {
		for i, cl := range c.AuthorizationServer.Clients {
			switch cl.ID {
			case grantMachine:
				c.AuthorizationServer.Clients[i].RefreshTokenTTL = 4 * time.Second
			case oauthBackend:
				// A confidential, key-bound client.
				c.AuthorizationServer.Clients[i].KeyBound = true
			}
		}
	}))
	owner := authtest.NewUser(t, as.Client)
	authtest.GrantRole(t, as.Client, iam.RootGroup(), iam.UserSubject(owner.ID), admin)
	signedIn := authtest.SignIn(t, as.Client, owner)
	refreshReq := func(tokens authtest.OAuthTokens, key *authtest.DPoPKey) authtest.TokenRequest {
		return authtest.TokenRequest{ClientID: grantMachine, DPoP: key, Params: url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tokens.RefreshToken}}}
	}

	// The decision's MaxLifetime caps the grant from consent: refresh and
	// access tokens alike.
	g.Decide = func(req iam.OAuthGrantRequest) (iam.OAuthGrantDecision, error) {
		return iam.OAuthGrantDecision{MaxLifetime: 2 * time.Second}, nil
	}
	capped := as.AuthorizeAs(t, signedIn, machineFlow(authtest.NewDPoPKey(t)))
	require.LessOrEqual(t, capped.ExpiresIn, int64(2))
	at := verifyIssued(t, as, capped.AccessToken, "at+jwt")
	require.LessOrEqual(t, at["exp"].(float64)-at["iat"].(float64), float64(2))
	machine := as.RequestClientCredentials(t, authtest.ClientCredentialsRequest{ClientID: oauthWorker, ClientSecret: oauthWorkerSecret})
	require.EqualValues(t, 2, machine.ExpiresIn, "client credentials too")

	// The client's refresh lifetime is absolute: rotation never extends it.
	g.Decide = nil
	tokens := as.AuthorizeAs(t, signedIn, machineFlow(authtest.NewDPoPKey(t)))
	time.Sleep(2100 * time.Millisecond)
	_, code := tokenError(t, as, refreshReq(capped, capped.DPoP))
	require.Equal(t, "invalid_grant", code, "past the decision's cap")
	tokens = as.Refresh(t, grantMachine, "", tokens)
	require.LessOrEqual(t, tokens.ExpiresIn, int64(2), "no access token outlives its grant")
	time.Sleep(2 * time.Second)
	_, code = tokenError(t, as, refreshReq(tokens, tokens.DPoP))
	require.Equal(t, "invalid_grant", code, "past the client's refresh lifetime")

	// A key-bound client must name its key at authorization and prove it at
	// every token request; its grant redeems with no other key.
	require.Equal(t, "invalid_request", authorizeError(t, as, machineFlow(nil), "", ""), "dpop_jkt is required")
	key := authtest.NewDPoPKey(t)
	tokens = as.AuthorizeAs(t, signedIn, machineFlow(key))
	_, code = tokenError(t, as, refreshReq(tokens, authtest.NewDPoPKey(t)))
	require.Equal(t, "invalid_dpop_proof", code)
	tokens = as.Refresh(t, grantMachine, "", tokens)
	require.Equal(t, key.Thumbprint(), verifyIssued(t, as, tokens.AccessToken, "at+jwt")["cnf"].(map[string]any)["jkt"])

	backend := authtest.CodeFlow{ClientID: oauthBackend, ClientSecret: oauthBackendToken, RedirectURI: oauthBackendCB, Scopes: []string{"openid"}}
	require.Equal(t, "invalid_request", authorizeError(t, as, backend, "", ""))
	backendKey := authtest.NewDPoPKey(t)
	backend.DPoP = backendKey
	callback, verifier := consentWithVerifier(t, as, signedIn, backend)
	redeem := url.Values{"grant_type": {"authorization_code"}, "code": {callback.Query().Get("code")}, "redirect_uri": {oauthBackendCB}, "code_verifier": {verifier}}
	_, code = tokenError(t, as, authtest.TokenRequest{ClientID: oauthBackend, ClientSecret: oauthBackendToken, Params: redeem})
	require.Equal(t, "invalid_dpop_proof", code, "a key-bound confidential client proves its key too")
}

// TestOAuthResourceServerReadsGrants: a resource server trusting the issuer
// by its JWKS reads a grant's authorization_details, actor and the issuer's
// URI-named claims from verify.Claims.
func TestOAuthResourceServerReadsGrants(t *testing.T) {
	g := &authtest.GrantAuthorizer{Decide: func(req iam.OAuthGrantRequest) (iam.OAuthGrantDecision, error) {
		return iam.OAuthGrantDecision{Claims: map[string]any{grantClaim: map[string]any{"grant": req.GrantID}}}, nil
	}}
	as, admin, _ := newGrantServer(t, g)
	resource := httptest.NewUnstartedServer(nil)
	t.Cleanup(resource.Close)
	v := verify.NewVerifier(verify.WithHTTPClient(as.HTTPClient()), verify.WithDPoP(memoryReplay()), verify.WithPublicURL("http://"+resource.Listener.Addr().String()))
	require.NoError(t, v.AddIssuer(as.URL, []string{oauthResource}, verify.IssuerOptions{JWKSURI: as.URL + iam.JWKSPath}))
	resource.Config.Handler = verify.Required(v)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cl, _ := verify.ClaimsFromContext(r.Context())
		_ = json.NewEncoder(w).Encode(map[string]any{
			"details": cl.AuthorizationDetails, "actor": cl.Actor, "custom": cl.CustomClaims, "sid": cl.SessionID,
		})
	}))
	resource.Start()
	call := func(tokens authtest.OAuthTokens) map[string]any {
		req, _ := http.NewRequest(http.MethodGet, resource.URL+"/v1/jobs", nil)
		tokens.DPoP.Authorize(t, req, tokens.AccessToken, "")
		res, err := resource.Client().Do(req)
		require.NoError(t, err)
		defer res.Body.Close()
		var out map[string]any
		require.NoError(t, json.NewDecoder(res.Body).Decode(&out))
		require.Equal(t, http.StatusOK, res.StatusCode, out)
		return out
	}

	owner := authtest.NewUser(t, as.Client)
	authtest.GrantRole(t, as.Client, iam.RootGroup(), iam.UserSubject(owner.ID), admin)
	signedIn := authtest.SignIn(t, as.Client, owner)
	got := call(as.AuthorizeAs(t, signedIn, machineFlow(authtest.NewDPoPKey(t))))
	consent, _ := g.Last(iam.OAuthGrantConsent)
	require.JSONEq(t, machineDetails, mustJSON(t, got["details"]))
	require.Empty(t, got["actor"])
	require.Empty(t, got["sid"])
	require.Equal(t, map[string]any{grantClaim: map[string]any{"grant": consent.GrantID}}, got["custom"])

	got = call(as.Exchange(t, authtest.TokenExchange{ClientID: oauthAdminUI, SubjectToken: signedIn.AccessToken, AuthorizationDetails: submitDetails}))
	require.JSONEq(t, submitDetails, mustJSON(t, got["details"]))
	require.Equal(t, oauthAdminUI, got["actor"])
	require.Equal(t, map[string]any{grantClaim: map[string]any{"grant": ""}}, got["custom"])
}

func consentWithVerifier(t *testing.T, as *authtest.AuthorizationServer, signedIn iam.TokenSet, f authtest.CodeFlow) (*url.URL, string) {
	t.Helper()
	verifier := "0123456789012345678901234567890123456789xyz"
	id := as.BeginAuthorization(t, f, verifier, "state-3")
	callback, err := url.Parse(as.Approve(t, signedIn.AccessToken, id))
	require.NoError(t, err)
	return callback, verifier
}

func putJSON(t *testing.T, as *authtest.AuthorizationServer, u, token string, body any) (int, []byte) {
	t.Helper()
	raw, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPut, u, strings.NewReader(string(raw)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	res, err := as.HTTPClient().Do(req)
	require.NoError(t, err)
	defer res.Body.Close()
	out, _ := io.ReadAll(res.Body)
	return res.StatusCode, out
}

// TestOAuthDeviceKeySignIns: a device-key sign-in approves and exchanges like
// a session. The grant stands on the device key: its tokens name no sid and
// carry the device-key sign-in's assurance, the authorizer sees the key, a
// fresh sign-in requirement asks the device key to sign in again, and
// revoking the key ends the grant unless it is offline.
func TestOAuthDeviceKeySignIns(t *testing.T) {
	g := &authtest.GrantAuthorizer{}
	as, admin, _ := newGrantServer(t, g, authtest.WithConfig(func(c *authkit.Config) { c.DeviceKeys.Enabled = true }))
	ctx := context.Background()
	owner := authtest.NewUser(t, as.Client)
	authtest.GrantRole(t, as.Client, iam.RootGroup(), iam.UserSubject(owner.ID), admin)
	keys, err := devicekey.NewClient(as.URL+as.Client.APIBase(), as.HTTPClient())
	require.NoError(t, err)
	online := func(key *authtest.DPoPKey) authtest.CodeFlow {
		f := machineFlow(key)
		f.Scopes = []string{"openid", "api:merchant"}
		return f
	}
	refreshReq := func(tokens authtest.OAuthTokens) authtest.TokenRequest {
		return authtest.TokenRequest{ClientID: grantMachine, DPoP: tokens.DPoP, Params: url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tokens.RefreshToken}}}
	}
	signOut := func(token string) {
		status, body := bearer(t, as, http.MethodDelete, as.URL+as.Client.APIBase()+"/logout", token)
		require.Equal(t, http.StatusNoContent, status, string(body))
	}

	dk := authtest.EnrollDeviceKey(t, as.Client, as.Outbox, owner)
	signedIn := iam.TokenSet{AccessToken: dk.AccessToken}
	tokens := as.AuthorizeAs(t, signedIn, online(authtest.NewDPoPKey(t)))
	consent, _ := g.Last(iam.OAuthGrantConsent)
	require.Equal(t, dk.ID, consent.DeviceKeyID)
	require.Empty(t, consent.SessionID)
	require.False(t, consent.Offline)
	at := verifyIssued(t, as, tokens.AccessToken, "at+jwt")
	require.Nil(t, at["sid"], "a device key is no session")
	require.Nil(t, decodeClaims(t, tokens.IDToken)["sid"])
	require.Equal(t, decodeClaims(t, dk.AccessToken)["auth_time"], at["auth_time"], "the device-key sign-in's assurance")
	require.Equal(t, []any{"merchant:*"}, at["permissions"])

	tokens = as.Refresh(t, grantMachine, "", tokens)
	refresh, _ := g.Last(iam.OAuthGrantRefresh)
	require.Equal(t, dk.ID, refresh.DeviceKeyID)
	require.Equal(t, consent.GrantID, refresh.GrantID)
	require.Equal(t, decodeClaims(t, dk.AccessToken)["auth_time"], verifyIssued(t, as, tokens.AccessToken, "at+jwt")["auth_time"])

	// Token exchange stands on the device key too.
	exchanged := as.Exchange(t, authtest.TokenExchange{ClientID: oauthAdminUI, SubjectToken: dk.AccessToken, Scopes: []string{"api:merchant"}})
	x, _ := g.Last(iam.OAuthGrantTokenExchange)
	require.Equal(t, dk.ID, x.DeviceKeyID)
	require.Nil(t, verifyIssued(t, as, exchanged.AccessToken, "at+jwt")["sid"])

	// A fresh sign-in requirement is met by signing in with the key again.
	stale := online(authtest.NewDPoPKey(t))
	zero := 0
	stale.MaxAge = &zero
	time.Sleep(1100 * time.Millisecond)
	id := as.BeginAuthorization(t, stale, "0123456789012345678901234567890123456789abc", "state-dk")
	status, body := postJSON(t, as, as.URL+as.Client.APIBase()+"/oauth2/authorizations/"+url.PathEscape(id)+"/approve", dk.AccessToken, nil)
	require.Equal(t, http.StatusForbidden, status, string(body))
	require.Contains(t, string(body), "step_up_required")
	fresh, err := keys.Login(ctx, dk.ID, dk.Key)
	require.NoError(t, err)
	require.Contains(t, as.Approve(t, fresh.AccessToken, id), "code=")

	// Revoking the device key ends its grants and codes.
	revoked := as.AuthorizeAs(t, iam.TokenSet{AccessToken: fresh.AccessToken}, online(authtest.NewDPoPKey(t)))
	offlineGrant := as.AuthorizeAs(t, iam.TokenSet{AccessToken: fresh.AccessToken}, machineFlow(authtest.NewDPoPKey(t)))
	pending := online(authtest.NewDPoPKey(t))
	code, verifier := consentWithVerifier(t, as, iam.TokenSet{AccessToken: fresh.AccessToken}, pending)
	signOut(fresh.AccessToken)
	_, errCode := tokenError(t, as, refreshReq(revoked))
	require.Equal(t, "invalid_grant", errCode)
	_, errCode = tokenError(t, as, refreshReq(tokens))
	require.Equal(t, "invalid_grant", errCode, "every grant of the key ends")
	_, errCode = tokenError(t, as, authtest.TokenRequest{ClientID: grantMachine, DPoP: pending.DPoP, Params: url.Values{
		"grant_type": {"authorization_code"}, "code": {code.Query().Get("code")}, "redirect_uri": {grantMachineCB}, "code_verifier": {verifier},
	}})
	require.Equal(t, "invalid_grant", errCode, "a code of the revoked key")
	// An offline grant outlives its sign-in, the device key included.
	as.Refresh(t, grantMachine, "", offlineGrant)
	id = as.BeginAuthorization(t, online(authtest.NewDPoPKey(t)), "0123456789012345678901234567890123456789abc", "state-dk2")
	status, _ = postJSON(t, as, as.URL+as.Client.APIBase()+"/oauth2/authorizations/"+url.PathEscape(id)+"/approve", fresh.AccessToken, nil)
	require.Equal(t, http.StatusUnauthorized, status, "a revoked key approves nothing")

	// A second device key of the account stands on its own.
	other := authtest.EnrollDeviceKey(t, as.Client, as.Outbox, owner)
	as.AuthorizeAs(t, iam.TokenSet{AccessToken: other.AccessToken}, online(authtest.NewDPoPKey(t)))
}
