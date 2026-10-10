package authkit_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/scim"
	"github.com/open-rails/authkit/internal/testdb"
	hauth "github.com/open-rails/helpers/auth"
)

// resourceDeployment is a resource server for oauthResource whose merchant
// groups trust issuers: an operator role holding subscriptions and payouts,
// not refunds, and scopes capping what each grants.
type resourceDeployment struct {
	auth     *authkit.Client
	operator iam.Role
	a, b     iam.GroupRef
	scopeA   hauth.Scope
	scopeB   hauth.Scope
}

func newResourceDeployment(t *testing.T, opts ...authtest.Option) resourceDeployment {
	t.Helper()
	rbac := authkit.NewRoles()
	merchant := rbac.Persona("merchant", authkit.RemoteApplications)
	merchant.Permission("subscriptions", "read")
	merchant.Permission("subscriptions", "update")
	merchant.Permission("payments", "refund")
	operator := merchant.Role("operator", merchant.Resource("subscriptions").All(), merchant.Permission("payouts", "read"))
	opts = append([]authtest.Option{authtest.WithConfig(func(c *authkit.Config) {
		c.Roles = rbac
		c.Token.AllowPrivateNetworkJWKS = true
		c.Resource = authkit.ResourceConfig{ID: oauthResource, Scopes: map[string][]string{"api:merchant": {"merchant:*"}, "api:self": {}}}
	})}, opts...)
	auth, _ := authtest.New(t, opts...)
	ctx := t.Context()
	d := resourceDeployment{auth: auth, operator: operator}
	for _, g := range []*iam.GroupRef{&d.a, &d.b} {
		created, err := auth.CreateGroup(ctx, iam.NewGroup{Persona: merchant.Persona})
		require.NoError(t, err)
		*g = iam.GroupByID(created.ID)
	}
	var err error
	d.scopeA, err = auth.Scope(ctx, d.a)
	require.NoError(t, err)
	d.scopeB, err = auth.Scope(ctx, d.b)
	require.NoError(t, err)
	return d
}

// jwksKeys are an issuer's published keys, as a remote application pins them.
func jwksKeys(t *testing.T, as *authtest.AuthorizationServer) []iam.RemoteApplicationKey {
	t.Helper()
	var set struct {
		Keys []json.RawMessage `json:"keys"`
	}
	require.Equal(t, http.StatusOK, getJSON(t, as, as.URL+iam.JWKSPath, &set))
	var out []iam.RemoteApplicationKey
	for _, raw := range set.Keys {
		var k iam.JWK
		require.NoError(t, json.Unmarshal(raw, &k))
		out = append(out, iam.RemoteApplicationKey{KID: k.Kid, JWK: &k})
	}
	return out
}

func resourceRequest(t *testing.T, tokens authtest.OAuthTokens, nonce string) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, oauthResource+"/v1/things", nil)
	if tokens.DPoP == nil {
		r.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	} else {
		tokens.DPoP.Authorize(t, r, tokens.AccessToken, nonce)
	}
	return r
}

func can(t *testing.T, v hauth.Verified, scope hauth.Scope, perm string) bool {
	t.Helper()
	ok, err := v.(hauth.PermissionChecker).Can(t.Context(), scope, perm)
	require.NoError(t, err)
	return ok
}

// TestResourceServerTrustedIssuer: with Config.Resource, Client.Authenticator
// admits a trusted issuer's RFC 9068 access tokens, bearer or DPoP-bound as
// the issuer minted them. A token acts only in its application's group
// (BoundScope), with its permissions within the application's live role
// there and the ceilings of its scopes. A bound token needs a fresh proof
// carrying the server's nonce (RFC 9449 §9), spent once, and is never
// accepted as Bearer (§7.2). A disabled application's tokens stop at once.
func TestResourceServerTrustedIssuer(t *testing.T) {
	ctx := context.Background()
	as, admin, _ := newOAuthServer(t)
	d := newResourceDeployment(t)
	a := d.auth.Authenticator()
	declare := func(apps ...iam.RemoteApplication) {
		t.Helper()
		require.NoError(t, d.auth.DeclareRemoteApplications(ctx, d.a, apps))
	}
	trusted := iam.RemoteApplication{Issuer: as.URL, PublicKeys: jwksKeys(t, as), Enabled: true, Role: d.operator}
	declare(trusted)

	owner := authtest.NewUser(t, as.Client)
	authtest.GrantRole(t, as.Client, iam.RootGroup(), iam.UserSubject(owner.ID), admin)
	tokens := as.Authorize(t, owner, consoleFlow())
	require.NotNil(t, tokens.DPoP)

	// The first proof carries no nonce: 401 use_dpop_nonce, with one.
	_, err := a.Authenticate(resourceRequest(t, tokens, ""))
	var challenge *hauth.Challenge
	require.ErrorAs(t, err, &challenge)
	require.ErrorIs(t, err, hauth.ErrSenderProofRequired)
	nonce := challenge.Header.Get("DPoP-Nonce")
	require.NotEmpty(t, nonce)
	require.Contains(t, challenge.Header.Get("WWW-Authenticate"), "use_dpop_nonce")

	r := resourceRequest(t, tokens, nonce)
	v, err := a.Authenticate(r)
	require.NoError(t, err)
	id := v.Identity()
	require.Equal(t, hauth.Identity{
		Issuer: as.URL, Subject: owner.ID, SubjectKind: hauth.SubjectUser,
		Invoker: hauth.Invoker{Issuer: as.URL, ID: owner.ID}, Credential: hauth.Credential{Kind: hauth.CredentialAccessToken, ID: id.Credential.ID},
		Email: owner.Email, EmailVerified: true,
	}, id, "the issuer's user acts themself; contact from the token")
	require.Equal(t, d.scopeA, v.(hauth.Bound).BoundScope())
	require.True(t, can(t, v, d.scopeA, "merchant:subscriptions:update"), "the token's merchant:* within the operator role")
	require.True(t, can(t, v, d.scopeA, "merchant:payouts:read"))
	require.False(t, can(t, v, d.scopeA, "merchant:payments:refund"), "outside the application's role")
	require.False(t, can(t, v, d.scopeB, "merchant:subscriptions:read"), "another group")
	root, err := d.auth.Scope(ctx, iam.RootGroup())
	require.NoError(t, err)
	require.False(t, can(t, v, root, "merchant:subscriptions:read"))
	require.NoError(t, v.(hauth.RecentSignInChecker).CheckRecentSignIn(ctx), "signed in just now")

	_, err = a.Authenticate(r)
	require.ErrorIs(t, err, hauth.ErrUnauthenticated, "a replayed proof")
	downgraded := httptest.NewRequest(http.MethodGet, oauthResource+"/v1/things", nil)
	downgraded.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	_, err = a.Authenticate(downgraded)
	require.ErrorIs(t, err, hauth.ErrUnauthenticated, "a bound token is never a bearer token")

	t.Run("a scope caps the token", func(t *testing.T) {
		flow := consoleFlow()
		flow.Scopes = []string{"openid", "api:self"}
		self := as.Authorize(t, owner, flow)
		v, err := a.Authenticate(resourceRequest(t, self, nonce))
		require.NoError(t, err)
		require.False(t, can(t, v, d.scopeA, "merchant:subscriptions:read"), "api:self grants no permission")
	})

	t.Run("a client's bearer token", func(t *testing.T) {
		worker := as.ClientCredentials(t, oauthWorker, oauthWorkerSecret, oauthResource, []string{"api:merchant"}, nil)
		require.Equal(t, "Bearer", worker.TokenType)
		v, err := a.Authenticate(resourceRequest(t, worker, ""))
		require.NoError(t, err)
		id := v.Identity()
		require.Equal(t, hauth.SubjectApplication, id.SubjectKind)
		require.Equal(t, oauthWorker, id.Subject)
		require.Equal(t, d.scopeA, v.(hauth.Bound).BoundScope())
		require.True(t, can(t, v, d.scopeA, "merchant:payouts:read"), "its own grant, within the role")
		require.False(t, can(t, v, d.scopeA, "merchant:subscriptions:read"), "not its grant")
		require.ErrorIs(t, v.(hauth.RecentSignInChecker).CheckRecentSignIn(ctx), hauth.ErrForbidden)

		declare()
		_, err = a.Authenticate(resourceRequest(t, worker, ""))
		require.ErrorIs(t, err, hauth.ErrUnauthenticated, "a disabled application's token")
		declare(trusted)
		_, err = a.Authenticate(resourceRequest(t, worker, ""))
		require.NoError(t, err)
	})

	t.Run("a deployment without Config.Resource refuses them", func(t *testing.T) {
		plain, _ := authtest.New(t)
		_, err := plain.Authenticator().Authenticate(resourceRequest(t, as.ClientCredentials(t, oauthWorker, oauthWorkerSecret, oauthResource, nil, nil), ""))
		require.ErrorIs(t, err, hauth.ErrUnauthenticated)
	})
}

// fakeIssuer is an issuer this test signs for: RFC 8414 metadata and its
// JWKS over plain HTTP, no jwks_uri registered.
type fakeIssuer struct {
	url string
	key *rsa.PrivateKey
}

func newFakeIssuer(t *testing.T) *fakeIssuer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	f := &fakeIssuer{key: key}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/oauth-authorization-server":
			_ = json.NewEncoder(w).Encode(map[string]any{"issuer": f.url, "jwks_uri": f.url + "/keys"})
		case "/keys":
			_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"}}})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	f.url = srv.URL
	return f
}

func (f *fakeIssuer) token(t *testing.T, typ string, claims jwt.MapClaims) string {
	t.Helper()
	now := time.Now()
	base := jwt.MapClaims{"iss": f.url, "aud": oauthResource, "sub": "u-1", "client_id": "shop-console", "iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(), "jti": uuid.NewString()}
	for k, v := range claims {
		if v == nil {
			delete(base, k)
		} else {
			base[k] = v
		}
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, base)
	tok.Header["typ"], tok.Header["kid"] = typ, "k1"
	s, err := tok.SignedString(f.key)
	require.NoError(t, err)
	return s
}

// TestResourceServerIssuerProfile: a trusted issuer registered by its issuer
// alone has its keys discovered from its RFC 8414 metadata. Its tokens are
// RFC 9068's: typ at+jwt, aud the resource. The invoker is the RFC 8693 act
// claim's, never the client; a stale auth_time is RFC 9470's step-up.
func TestResourceServerIssuerProfile(t *testing.T) {
	ctx := context.Background()
	f := newFakeIssuer(t)
	d := newResourceDeployment(t)
	viewer := iam.RemoteApplication{Issuer: f.url, Enabled: true, Role: d.operator, RoleMap: map[string]iam.Role{"admin": d.operator}}
	require.NoError(t, d.auth.DeclareRemoteApplications(ctx, d.b, []iam.RemoteApplication{viewer}))
	a := d.auth.Authenticator()
	bearer := func(token string) *http.Request {
		r := httptest.NewRequest(http.MethodGet, oauthResource+"/v1/things", nil)
		r.Header.Set("Authorization", "Bearer "+token)
		return r
	}
	fresh := jwt.MapClaims{"scope": "api:merchant", "permissions": []string{"merchant:subscriptions:read"}, "auth_time": time.Now().Unix()}

	v, err := a.Authenticate(bearer(f.token(t, "at+jwt", fresh)))
	require.NoError(t, err, "keys from the issuer's metadata")
	require.Equal(t, d.scopeB, v.(hauth.Bound).BoundScope())
	require.True(t, can(t, v, d.scopeB, "merchant:subscriptions:read"))
	require.True(t, v.Identity().SelfInvoked(), "client_id is no invoker")
	require.NoError(t, v.(hauth.RecentSignInChecker).CheckRecentSignIn(ctx))

	mapped := jwt.MapClaims{"scope": "api:merchant", "roles": []string{"admin"}}
	v, err = a.Authenticate(bearer(f.token(t, "at+jwt", mapped)))
	require.NoError(t, err)
	require.True(t, can(t, v, d.scopeB, "merchant:payouts:read"), "the roles claim, mapped to a role of the group")
	require.False(t, can(t, v, d.scopeB, "merchant:payments:refund"), "never beyond the application's role")

	acted := jwt.MapClaims{"act": map[string]any{"sub": "agent-7"}}
	v, err = a.Authenticate(bearer(f.token(t, "at+jwt", acted)))
	require.NoError(t, err)
	require.Equal(t, hauth.Invoker{Issuer: f.url, ID: "agent-7"}, v.Identity().Invoker, "RFC 8693 act names the invoker")

	stale := jwt.MapClaims{"auth_time": time.Now().Add(-time.Hour).Unix()}
	v, err = a.Authenticate(bearer(f.token(t, "at+jwt", stale)))
	require.NoError(t, err)
	err = v.(hauth.RecentSignInChecker).CheckRecentSignIn(ctx)
	var challenge *hauth.Challenge
	require.ErrorAs(t, err, &challenge)
	require.ErrorIs(t, err, hauth.ErrStepUpRequired)
	require.Equal(t, `Bearer error="insufficient_user_authentication", error_description="A recent sign-in is required", max_age=900`, challenge.Header.Get("WWW-Authenticate"))

	for name, token := range map[string]string{
		"another audience":  f.token(t, "at+jwt", jwt.MapClaims{"aud": "https://elsewhere.example"}),
		"not an at+jwt":     f.token(t, "JWT", nil),
		"no subject":        f.token(t, "at+jwt", jwt.MapClaims{"sub": nil}),
		"expired":           f.token(t, "at+jwt", jwt.MapClaims{"exp": time.Now().Add(-time.Hour).Unix(), "iat": time.Now().Add(-2 * time.Hour).Unix()}),
		"an unknown issuer": newFakeIssuer(t).token(t, "at+jwt", nil),
	} {
		_, err := a.Authenticate(bearer(token))
		require.ErrorIs(t, err, hauth.ErrUnauthenticated, name)
	}
}

// TestResourceServerRemoteAssertion: a trusted application's backend, with
// no authorization server of its own, signs an RFC 7523 assertion for its
// user (iss its issuer, sub the user, aud the token endpoint); its frontend
// redeems it at this deployment's token endpoint for an access token acting
// for that user in the application's group, holding no permissions: bound
// when the frontend proves a DPoP key, bearer otherwise. An assertion is
// spent once.
func TestResourceServerRemoteAssertion(t *testing.T) {
	ctx := context.Background()
	f := newFakeIssuer(t)
	d := newResourceDeployment(t)
	require.NoError(t, d.auth.DeclareRemoteApplications(ctx, d.a, []iam.RemoteApplication{{Issuer: f.url, Enabled: true, Role: d.operator}}))
	srv := httptest.NewServer(d.auth.Handler())
	t.Cleanup(srv.Close)
	endpoint := authtest.Issuer + iam.OAuthTokenPath

	assertion := func(claims jwt.MapClaims) string {
		now := time.Now()
		base := jwt.MapClaims{"aud": endpoint, "sub": "customer-42", "jti": uuid.NewString(), "iat": now.Unix(), "exp": now.Add(2 * time.Minute).Unix(),
			"email": "c42@shop.example", "email_verified": true, "name": "Ada"}
		for k, v := range claims {
			base[k] = v
		}
		return f.token(t, "JWT", base)
	}
	redeem := func(assertion string, key *authtest.DPoPKey, scope string) (int, map[string]any) {
		form := url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"}, "assertion": {assertion}, "scope": {scope}}
		req, err := http.NewRequest(http.MethodPost, srv.URL+iam.OAuthTokenPath, strings.NewReader(form.Encode()))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Origin", "https://shop.example")
		if key != nil {
			req.Header.Set("DPoP", key.Proof(t, http.MethodPost, endpoint, "", ""))
		}
		res, err := srv.Client().Do(req)
		require.NoError(t, err)
		defer res.Body.Close()
		require.Equal(t, "https://shop.example", res.Header.Get("Access-Control-Allow-Origin"), "a trusted application's frontend")
		var out map[string]any
		require.NoError(t, json.NewDecoder(res.Body).Decode(&out))
		return res.StatusCode, out
	}

	status, out := redeem(assertion(nil), nil, "api:self")
	require.Equal(t, http.StatusOK, status, out)
	require.Equal(t, "Bearer", out["token_type"])
	r := httptest.NewRequest(http.MethodGet, oauthResource+"/v1/me", nil)
	r.Header.Set("Authorization", "Bearer "+out["access_token"].(string))
	v, err := d.auth.Authenticator().Authenticate(r)
	require.NoError(t, err)
	id := v.Identity()
	require.Equal(t, hauth.Identity{
		Issuer: f.url, Subject: "customer-42", SubjectKind: hauth.SubjectUser, Invoker: hauth.Invoker{Issuer: f.url, ID: "customer-42"},
		Credential: hauth.Credential{Kind: hauth.CredentialAccessToken, ID: id.Credential.ID}, Email: "c42@shop.example", EmailVerified: true,
	}, id, "the application's user, in its namespace, with the contact it vouched for")
	require.Equal(t, d.scopeA, v.(hauth.Bound).BoundScope())
	require.False(t, can(t, v, d.scopeA, "merchant:subscriptions:read"), "a customer token holds nothing")
	users, err := d.auth.RemoteUserInfo(d.a, f.url).Get(ctx, []string{"customer-42"})
	require.NoError(t, err)
	require.Equal(t, "c42@shop.example", users["customer-42"].Email, "the contact is recorded for the group's directory")
	require.Equal(t, "Ada", users["customer-42"].Name)

	key := authtest.NewDPoPKey(t)
	status, out = redeem(assertion(nil), key, "api:self")
	require.Equal(t, http.StatusOK, status, out)
	require.Equal(t, "DPoP", out["token_type"], "bound when the frontend proves a key")

	spent := assertion(nil)
	status, _ = redeem(spent, nil, "")
	require.Equal(t, http.StatusOK, status)
	for name, tc := range map[string]struct {
		assertion string
		scope     string
	}{
		"a spent assertion":        {spent, ""},
		"another audience":         {assertion(jwt.MapClaims{"aud": "https://elsewhere.example/token"}), ""},
		"too long ahead":           {assertion(jwt.MapClaims{"exp": time.Now().Add(time.Hour).Unix()}), ""},
		"a short jti":              {assertion(jwt.MapClaims{"jti": "short"}), ""},
		"an unknown issuer":        {newFakeIssuer(t).token(t, "JWT", jwt.MapClaims{"aud": endpoint, "jti": uuid.NewString()}), ""},
		"a scope it does not have": {assertion(nil), "api:everything"},
	} {
		status, out := redeem(tc.assertion, nil, tc.scope)
		require.NotEqual(t, http.StatusOK, status, "%s: %v", name, out)
	}
}

// TestResourceServerSCIMPush: a trusted issuer pushes its users to this
// deployment's SCIM directory (RFC 7644) with its own client-credentials
// token, verified like any trusted issuer's token: bound to its
// application's group and holding <persona>:directory:manage there only
// when the token carries it within the application's role.
func TestResourceServerSCIMPush(t *testing.T) {
	const resource = "https://directory.example.com"
	as := authtest.NewAuthorizationServer(t, authtest.WithConfig(func(c *authkit.Config) {
		roles := authkit.NewRoles()
		roles.Persona("merchant", authkit.RemoteApplications)
		c.Roles = roles
		c.AuthorizationServer = authkit.AuthorizationServerConfig{
			Resources: []authkit.ResourceServerConfig{{ID: resource, Permissions: []string{"merchant:*"}}},
			Clients: []authkit.OAuthClientConfig{
				{ID: "pusher", SecretSHA256: authtest.ClientSecretSHA256(oauthWorkerSecret), Resources: []string{resource},
					GrantTypes: []authkit.OAuthGrantType{authkit.GrantClientCredentials}, Permissions: []string{"merchant:directory:manage"}},
				{ID: "reader", SecretSHA256: authtest.ClientSecretSHA256(oauthWorkerSecret), Resources: []string{resource},
					GrantTypes: []authkit.OAuthGrantType{authkit.GrantClientCredentials}, Permissions: []string{"merchant:directory:read"}},
			},
		}
	}))
	b := newDirectoryService(t, authtest.WithConfig(func(c *authkit.Config) { c.Resource = authkit.ResourceConfig{ID: resource} }))
	shop, err := b.CreateGroup(t.Context(), iam.NewGroup{Persona: b.merchant.Persona})
	require.NoError(t, err)
	require.NoError(t, b.DeclareRemoteApplications(t.Context(), iam.GroupByID(shop.ID), []iam.RemoteApplication{
		{Issuer: as.URL, PublicKeys: jwksKeys(t, as), Enabled: true, Role: b.provisioner},
	}))
	pusher := as.ClientCredentials(t, "pusher", oauthWorkerSecret, resource, nil, nil).AccessToken
	reader := as.ClientCredentials(t, "reader", oauthWorkerSecret, resource, nil, nil).AccessToken

	active := true
	user := scim.User{Schemas: []string{scim.SchemaUser}, ExternalID: "u-7", UserName: "seven", Active: &active,
		Emails: []scim.Email{{Value: "seven@a.example", Primary: true}}}
	var created scim.User
	status, _ := b.call(t, pusher, http.MethodPost, "/Users", user, &created)
	require.Equal(t, http.StatusCreated, status)
	got, err := b.RemoteUserInfo(iam.GroupByID(shop.ID), as.URL).Get(t.Context(), []string{"u-7"})
	require.NoError(t, err)
	require.Equal(t, "seven@a.example", got["u-7"].Email)

	status, _ = b.call(t, reader, http.MethodGet, "/Users/"+created.ID, nil, nil)
	require.Equal(t, http.StatusOK, status)
	var e scim.Error
	status, _ = b.call(t, reader, http.MethodDelete, "/Users/"+created.ID, nil, &e)
	require.Equal(t, http.StatusForbidden, status, "its token carries only directory:read")
}

// TestResourceServerFederatedGrants: a group's email invitation is accepted
// by a trusted issuer's user whose token carries that verified address; the
// user then holds its role in the group, so their tokens hold its
// permissions there, within the application's role. The grant ends when
// removed.
func TestResourceServerFederatedGrants(t *testing.T) {
	ctx := context.Background()
	f := newFakeIssuer(t)
	d := newResourceDeployment(t)
	require.NoError(t, d.auth.DeclareRemoteApplications(ctx, d.a, []iam.RemoteApplication{{Issuer: f.url, Enabled: true, Role: d.operator}}))
	a := d.auth.Authenticator()
	verified := func(claims jwt.MapClaims) hauth.Verified {
		t.Helper()
		base := jwt.MapClaims{"sub": "staff-1", "scope": "api:merchant", "email": "Staff@Shop.example", "email_verified": true}
		for k, v := range claims {
			base[k] = v
		}
		r := httptest.NewRequest(http.MethodGet, oauthResource+"/v1/things", nil)
		r.Header.Set("Authorization", "Bearer "+f.token(t, "at+jwt", base))
		v, err := a.Authenticate(r)
		require.NoError(t, err)
		return v
	}

	require.False(t, can(t, verified(nil), d.scopeA, "merchant:subscriptions:read"), "no grant yet")
	_, err := d.auth.CreateInvitation(ctx, iam.SystemIdentity(), d.a, iam.NewInvitation{Email: "staff@shop.example", Role: d.operator})
	require.NoError(t, err)

	none, err := d.auth.RemoteInvitations(ctx, verified(jwt.MapClaims{"email_verified": false}))
	require.NoError(t, err)
	require.Empty(t, none, "an unverified address")
	none, err = d.auth.RemoteInvitations(ctx, verified(jwt.MapClaims{"email": "other@shop.example"}))
	require.NoError(t, err)
	require.Empty(t, none, "another address")

	invites, err := d.auth.RemoteInvitations(ctx, verified(nil))
	require.NoError(t, err)
	require.Len(t, invites, 1)
	require.Equal(t, d.operator, invites[0].Role)
	role, err := d.auth.AcceptRemoteInvitation(ctx, verified(nil), invites[0].ID)
	require.NoError(t, err)
	require.Equal(t, d.operator, role)
	_, err = d.auth.AcceptRemoteInvitation(ctx, verified(nil), invites[0].ID)
	require.ErrorIs(t, err, iam.ErrInvitationNotFound, "once")

	v := verified(nil)
	require.True(t, can(t, v, d.scopeA, "merchant:subscriptions:update"), "the accepted role")
	require.False(t, can(t, v, d.scopeA, "merchant:payments:refund"), "never beyond the application's role")
	require.False(t, can(t, verified(jwt.MapClaims{"sub": "someone-else"}), d.scopeA, "merchant:subscriptions:read"), "only that user")

	roles, err := d.auth.RemoteUserRoles(ctx, d.a)
	require.NoError(t, err)
	require.Len(t, roles, 1)
	require.Equal(t, iam.RemoteUserRole{RemoteUserID: roles[0].RemoteUserID, Issuer: f.url, Subject: "staff-1", Email: "Staff@Shop.example", Role: d.operator, CreatedAt: roles[0].CreatedAt}, roles[0])

	require.NoError(t, d.auth.RemoveRemoteUserRole(ctx, iam.SystemIdentity(), d.a, roles[0].RemoteUserID))
	require.False(t, can(t, verified(nil), d.scopeA, "merchant:subscriptions:read"), "removed")
	require.ErrorIs(t, d.auth.RemoveRemoteUserRole(ctx, iam.SystemIdentity(), d.a, roles[0].RemoteUserID), iam.ErrUserNotFound)
}

// TestResourceServerAssertionReplay: an RFC 7523 assertion's jti is spent
// once (§3), in the store DPoP proofs are spent in: this process's memory
// without Redis, Redis across every instance with it.
func TestResourceServerAssertionReplay(t *testing.T) {
	endpoint := authtest.Issuer + iam.OAuthTokenPath
	redeem := func(t *testing.T, auth *authkit.Client, assertion string) int {
		form := url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"}, "assertion": {assertion}}
		req := httptest.NewRequest(http.MethodPost, endpoint, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		auth.Handler().ServeHTTP(w, req)
		return w.Code
	}
	setup := func(t *testing.T, opts ...authtest.Option) (resourceDeployment, func() string) {
		f := newFakeIssuer(t)
		d := newResourceDeployment(t, opts...)
		require.NoError(t, d.auth.DeclareRemoteApplications(t.Context(), d.a, []iam.RemoteApplication{{Issuer: f.url, Enabled: true, Role: d.operator}}))
		return d, func() string {
			now := time.Now()
			return f.token(t, "JWT", jwt.MapClaims{"aud": endpoint, "sub": "customer-42", "jti": uuid.NewString(), "iat": now.Unix(), "exp": now.Add(2 * time.Minute).Unix()})
		}
	}

	t.Run("one instance without Redis", func(t *testing.T) {
		d, assertion := setup(t)
		spent := assertion()
		require.Equal(t, http.StatusOK, redeem(t, d.auth, spent))
		require.Equal(t, http.StatusBadRequest, redeem(t, d.auth, spent), "a replayed assertion")
	})

	t.Run("two instances sharing a Redis", func(t *testing.T) {
		rdb := testdb.ScratchRedis(t)
		d, assertion := setup(t, authtest.WithDeps(func(deps *authkit.Deps) { deps.Redis = rdb }))
		replica := authtest.Replica(t, d.auth)
		spent := assertion()
		require.Equal(t, http.StatusOK, redeem(t, d.auth, spent))
		require.Equal(t, http.StatusBadRequest, redeem(t, replica, spent), "replayed at another instance")
		require.Equal(t, http.StatusOK, redeem(t, replica, assertion()))
	})
}
