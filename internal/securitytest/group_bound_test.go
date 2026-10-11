package securitytest

import (
	"context"
	"crypto/ecdsa"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/testdpop"
	hauth "github.com/open-rails/helpers/auth"
	conformance "github.com/open-rails/helpers/auth/authtest"
)

// withGroupBound is withBillingHost as its own resource server: tokens
// exchanged for billingResource authenticate at Client.Authenticator(), for
// 15 minutes.
func withGroupBound(c *authkit.Config) {
	withBillingHost(c)
	c.AuthorizationServer.Resources = []authkit.ResourceServerConfig{{ID: billingResource, Scopes: []string{"billing:merchant"}, Permissions: []string{"root:customers:*", "merchant:*"}}}
	c.AuthorizationServer.AccessTokenTTL = 15 * time.Minute
	c.Resource = authkit.ResourceConfig{ID: billingResource}
}

// exchangeFor is an RFC 8693 token exchange of subject for billingResource,
// naming group when set and proving key when given.
func (h *host) exchangeFor(subject, group string, key *ecdsa.PrivateKey) response {
	h.t.Helper()
	form := url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:token-exchange"}, "client_id": {resourceClient},
		"subject_token": {subject}, "subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
		"resource": {billingResource}, "scope": {"billing:merchant"},
	}
	if group != "" {
		form.Set("group_id", group)
	}
	header := http.Header{"Content-Type": {"application/x-www-form-urlencoded"}}
	if key != nil {
		header.Set("DPoP", testdpop.Proof(h.t, key, http.MethodPost, issuer+"/oauth2/token", "", noATH))
	}
	return h.do(request{method: http.MethodPost, path: "//oauth2/token", body: form.Encode(), header: header})
}

// exchanged is exchangeFor's access token, which must be issued.
func (h *host) exchanged(subject, group string, key *ecdsa.PrivateKey) string {
	h.t.Helper()
	resp := h.exchangeFor(subject, group, key)
	require.Equal(h.t, http.StatusOK, resp.status, resp.String())
	var out struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	resp.json(h.t, &out)
	require.EqualValues(h.t, 900, out.ExpiresIn)
	return out.AccessToken
}

// oauthError is a token endpoint refusal's error code.
func oauthError(t *testing.T, r response) string {
	t.Helper()
	require.GreaterOrEqual(t, r.status, 400, r.String())
	var out struct {
		Error string `json:"error"`
	}
	r.json(t, &out)
	return out.Error
}

// TestSecurityGroupBoundTokens (OpenRails #1197): a person's sign-in
// exchanged for one group (RFC 8693, group_id) is bound to that group: it
// holds there what the person holds, and keeps the person's root:
// permissions on root and nothing else (helpers/auth Bound). Only a person
// holding a role in the group, or a root role, gets one, for a live group
// other than root; a DPoP-bound sign-in only with its own key. A host's
// group-bound mint is a customer token: bound, sessionless, holding
// nothing, at most 15 minutes, and refused by AuthKit's own API.
func TestSecurityGroupBoundTokens(t *testing.T) {
	ctx := context.Background()
	h := newHost(t, withHTTP(generousLimits), authtest.WithConfig(withGroupBound))
	a := h.auth.Authenticator()
	root, err := a.(hauth.Root).RootScope(ctx)
	require.NoError(t, err)
	persona, err := h.auth.Persona("merchant")
	require.NoError(t, err)
	newGroup := func() iam.GroupRef {
		g, err := h.auth.CreateGroup(ctx, iam.NewGroup{Persona: persona})
		require.NoError(t, err)
		return iam.GroupByID(g.ID)
	}
	m, n := newGroup(), newGroup()
	scopeM, err := h.auth.Scope(ctx, m)
	require.NoError(t, err)
	scopeN, err := h.auth.Scope(ctx, n)
	require.NoError(t, err)

	support, operator, nobody := h.newAccount("gbsupport"), h.newAccount("gboperator"), h.newAccount("gbnobody")
	h.grant(m, support, "support")
	h.grant(iam.RootGroup(), operator, "billing")
	supportToken, operatorToken := h.login(support).AccessToken, h.login(operator).AccessToken

	verified := func(t *testing.T, token string) hauth.Verified {
		t.Helper()
		v, err := a.Authenticate(bearerRequest(token)())
		require.NoError(t, err)
		return v
	}
	can := func(t *testing.T, v hauth.Verified, scope hauth.Scope, perm string) bool {
		t.Helper()
		ok, err := v.(hauth.PermissionChecker).Can(ctx, scope, perm)
		require.NoError(t, err)
		return ok
	}

	t.Run("the exchanged token is bound to the group, for 15 minutes", func(t *testing.T) {
		token := h.exchanged(supportToken, m.ID(), nil)
		_, claims := splitToken(t, token)
		_, subject := splitToken(t, supportToken)
		require.Equal(t, m.ID(), claims["group_id"])
		require.Equal(t, support.id, claims["sub"])
		require.Equal(t, billingResource, claims["aud"])
		require.Equal(t, resourceClient, claims["client_id"])
		require.Equal(t, subject["sid"], claims["sid"])
		require.Equal(t, subject["auth_time"], claims["auth_time"], "the sign-in's time carries over")
		require.Nil(t, claims["act"], "the person acts as itself")
		require.Nil(t, claims["cnf"], "no proof, a bearer token")
		require.EqualValues(t, 900, claims["exp"].(float64)-claims["iat"].(float64))

		v := verified(t, token)
		require.Equal(t, scopeM, v.(hauth.Bound).BoundScope())
		id := v.Identity()
		require.Equal(t, hauth.SubjectUser, id.SubjectKind)
		require.True(t, id.SelfInvoked())
		require.True(t, can(t, v, scopeM, merchantRefund), "what the person holds in the group")
		require.False(t, can(t, v, scopeN, merchantRefund), "nothing in another group")
		require.False(t, can(t, v, root, customersRead), "a merchant role holds nothing on root")
		require.NoError(t, v.(hauth.RecentSignInChecker).CheckRecentSignIn(ctx), "auth_time carried over")
	})

	t.Run("its recent sign-in is the person's: fresh passes, stale steps up", func(t *testing.T) {
		person := h.newAccount("gbstepup")
		h.grant(iam.RootGroup(), person, "billing")
		v := verified(t, h.exchanged(h.login(person).AccessToken, m.ID(), nil))
		require.NoError(t, v.(hauth.RecentSignInChecker).CheckRecentSignIn(ctx))

		stale := authtest.StaleSession(t, h.auth, h.login(person).AccessToken)
		token := h.exchanged(stale, m.ID(), nil)
		r := bearerRequest(token)()
		v, err := a.Authenticate(r)
		require.NoError(t, err)
		err = v.(hauth.RecentSignInChecker).CheckRecentSignIn(ctx)
		require.ErrorIs(t, err, hauth.ErrStepUpRequired, "auth_time carried over from a stale sign-in")
		require.Equal(t, http.StatusUnauthorized, hauth.Refuse(r, err).Status)

		minted, err := h.auth.MintAccessToken(ctx, person.id, iam.AccessTokenOptions{Group: m})
		require.NoError(t, err)
		require.ErrorIs(t, verified(t, minted.Value).(hauth.RecentSignInChecker).CheckRecentSignIn(ctx), hauth.ErrForbidden, "a sessionless mint has no sign-in")
	})

	t.Run("a person's bound token keeps their root: permissions on root", func(t *testing.T) {
		token := h.exchanged(operatorToken, m.ID(), nil)
		v := verified(t, token)
		require.Equal(t, scopeM, v.(hauth.Bound).BoundScope())
		require.True(t, can(t, v, root, customersRead), "a root role holds on root")
		require.False(t, can(t, v, root, merchantRefund), "on root only root: permissions")
		require.False(t, can(t, v, scopeN, merchantRefund))
		require.False(t, can(t, v, hauth.Scope{Authority: "https://other.example", ID: root.ID}, customersRead), "another authority's root")

		conformance.Check(t, a, conformance.Cases{
			Permissions: []string{customersRead, customersUpdate},
			Staff:       bearerRequest(h.login(operator).AccessToken),
			User:        bearerRequest(h.login(nobody).AccessToken),
			BoundStaff:  bearerRequest(token),
		})
	})

	t.Run("an application's bound credential stays in its group", func(t *testing.T) {
		_, key, err := createKey(h.auth, ctx, iam.SystemIdentity(), m, iam.NewAPIKey{Name: "gb-support", Role: roleIn(t, h.auth, m, "support")})
		require.NoError(t, err)
		v := verified(t, key)
		require.Equal(t, scopeM, v.(hauth.Bound).BoundScope())
		require.True(t, can(t, v, scopeM, merchantRefund))
		require.False(t, can(t, v, root, customersRead))
	})

	t.Run("only a role in the group, or a root role, gets one", func(t *testing.T) {
		nobodyToken := h.login(nobody).AccessToken
		rootID := root.ID
		deleted := newGroup()
		require.NoError(t, h.auth.DeleteGroup(ctx, deleted))
		for name, group := range map[string]string{
			"no role there":    m.ID(),
			"an unknown group": uuid.NewString(),
			"not a uuid":       "merchant-1",
			"the root group":   rootID,
			"a deleted group":  deleted.ID(),
		} {
			require.Equal(t, "invalid_target", oauthError(t, h.exchangeFor(nobodyToken, group, nil)), name)
		}
		require.Equal(t, "invalid_target", oauthError(t, h.exchangeFor(supportToken, n.ID(), nil)), "a role in another group")
		form := url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:token-exchange"}, "client_id": {resourceClient},
			"subject_token": {supportToken}, "subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
			"resource": {billingResource}, "group_id": {m.ID(), n.ID()}}
		resp := h.do(request{method: http.MethodPost, path: "//oauth2/token", body: form.Encode(), header: http.Header{"Content-Type": {"application/x-www-form-urlencoded"}}})
		require.Equal(t, "invalid_request", oauthError(t, resp), "two groups")
	})

	t.Run("a DPoP-bound sign-in is exchanged only with its own key", func(t *testing.T) {
		key, other := testdpop.Key(t), testdpop.Key(t)
		bound := session(t, h.do(request{method: http.MethodPost, path: "/password/login", body: map[string]string{"identifier": support.email, "password": password},
			header: signInProof(t, key, http.MethodPost, "/password/login")}))
		require.Equal(t, "invalid_grant", oauthError(t, h.exchangeFor(bound.AccessToken, m.ID(), nil)), "no proof: never traded for a bearer token")
		require.Equal(t, "invalid_grant", oauthError(t, h.exchangeFor(bound.AccessToken, m.ID(), other)), "another key")
		token := h.exchanged(bound.AccessToken, m.ID(), key)
		_, claims := splitToken(t, token)
		require.Equal(t, map[string]any{"jkt": testdpop.Thumbprint(t, key)}, claims["cnf"])
		require.Equal(t, m.ID(), claims["group_id"])

		bearer := h.exchanged(supportToken, m.ID(), other)
		_, claims = splitToken(t, bearer)
		require.Equal(t, map[string]any{"jkt": testdpop.Thumbprint(t, other)}, claims["cnf"], "a bearer sign-in binds to the proof it is exchanged with")
	})

	t.Run("it ends with its sign-in or its group", func(t *testing.T) {
		g := newGroup()
		h.grant(g, support, "support")
		signedIn := h.login(support)
		token := h.exchanged(signedIn.AccessToken, g.ID(), nil)
		verified(t, token)
		require.NoError(t, h.auth.DeleteGroup(ctx, g))
		_, err := a.Authenticate(bearerRequest(token)())
		require.ErrorIs(t, err, hauth.ErrRevoked, "a deleted group")

		token = h.exchanged(signedIn.AccessToken, m.ID(), nil)
		require.Equal(t, http.StatusNoContent, h.do(request{method: http.MethodDelete, path: "/logout", token: signedIn.AccessToken}).status)
		_, err = a.Authenticate(bearerRequest(token)())
		require.ErrorIs(t, err, hauth.ErrRevoked, "a signed-out session")
	})

	t.Run("a host's group-bound mint is a customer token", func(t *testing.T) {
		customer := h.newAccount("gbcustomer")
		h.grant(m, customer, "support")
		minted, err := h.auth.MintAccessToken(ctx, customer.id, iam.AccessTokenOptions{Group: m})
		require.NoError(t, err)
		_, claims := splitToken(t, minted.Value)
		require.Equal(t, m.ID(), claims["group_id"])
		require.Nil(t, claims["sid"])
		require.LessOrEqual(t, claims["exp"].(float64)-claims["iat"].(float64), float64(15*60))

		v := verified(t, minted.Value)
		id := v.Identity()
		require.Equal(t, customer.id, id.Subject)
		require.Equal(t, hauth.SubjectUser, id.SubjectKind)
		require.True(t, id.SelfInvoked())
		require.Equal(t, hauth.CredentialAccessToken, id.Credential.Kind)
		require.Equal(t, scopeM, v.(hauth.Bound).BoundScope())
		require.False(t, can(t, v, scopeM, merchantRefund), "a customer token holds nothing, whatever its user holds")
		require.ErrorIs(t, v.(hauth.RecentSignInChecker).CheckRecentSignIn(ctx), hauth.ErrForbidden, "no sign-in of its own")
		require.Equal(t, http.StatusForbidden, h.get("/me", minted.Value).status, "never AuthKit's own API")

		for name, o := range map[string]iam.AccessTokenOptions{
			"over 15 minutes": {Group: m, TTL: 16 * time.Minute},
			"with a session":  {Group: m, SessionID: uuid.NewString()},
			"a forged claim":  {Group: m, Claims: map[string]any{"group_id": n.ID()}},
		} {
			_, err := h.auth.MintAccessToken(ctx, customer.id, o)
			require.Error(t, err, name)
		}
		_, err = h.auth.MintAccessToken(ctx, customer.id, iam.AccessTokenOptions{Group: iam.RootGroup()})
		require.ErrorIs(t, err, iam.ErrGroupNotFound, "root")
		_, err = h.auth.MintAccessToken(ctx, customer.id, iam.AccessTokenOptions{Group: iam.GroupByID(uuid.NewString())})
		require.ErrorIs(t, err, iam.ErrGroupNotFound)

		g := newGroup()
		other, err := h.auth.MintAccessToken(ctx, customer.id, iam.AccessTokenOptions{Group: g})
		require.NoError(t, err)
		require.NoError(t, h.auth.DeleteGroup(ctx, g))
		_, err = a.Authenticate(bearerRequest(other.Value)())
		require.ErrorIs(t, err, hauth.ErrRevoked, "a deleted group")
		require.NoError(t, h.auth.Ban(ctx, iam.SystemIdentity(), customer.id, iam.Ban{Reason: "fraud"}))
		_, err = a.Authenticate(bearerRequest(minted.Value)())
		require.ErrorIs(t, err, hauth.ErrRevoked, "a banned user")
	})
}
