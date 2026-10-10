package authkit_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
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
