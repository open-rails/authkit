package securitytest

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/testdpop"
	"github.com/open-rails/authkit/verify"
	hauth "github.com/open-rails/helpers/auth"
	conformance "github.com/open-rails/helpers/auth/authtest"
	"github.com/stretchr/testify/require"
)

const (
	billingResource = "https://billing.security.test"
	billingBackend  = "billing-backend"
	billingSecret   = "billing-backend-secret-0123456789abcdef0123456789abcdef"
	customersRead   = "root:customers:read"
	customersUpdate = "root:customers:update"
	merchantRefund  = "merchant:payments:refund"
)

// withBillingHost is a host that mounts a library (OpenRails) guarded by
// Client.Authenticator(): root roles holding the library's staff
// permissions, root and merchant API keys, and an authorization server for
// the library's resource with a token-exchange client and a
// client-credentials backend.
func withBillingHost(c *authkit.Config) {
	r := authkit.NewRoles(authkit.APIKeys)
	read, update := r.Root.Permission("customers", "read"), r.Root.Permission("customers", "update")
	r.Root.Role("billing", read, update)
	r.Root.Role("reader", read)
	r.Root.Role("updater", update)
	m := r.Persona("merchant", authkit.APIKeys)
	m.Role("support", m.Permission("payments", "refund"))
	c.Roles = r
	sum := sha256.Sum256([]byte(billingSecret))
	c.AuthorizationServer = authkit.AuthorizationServerConfig{
		Resources: []authkit.ResourceServerConfig{{ID: billingResource, Permissions: []string{"billing:*"}}},
		Clients: []authkit.OAuthClientConfig{
			{ID: resourceClient, Resources: []string{billingResource}, GrantTypes: []authkit.OAuthGrantType{authkit.GrantTokenExchange}},
			{ID: billingBackend, SecretSHA256: hex.EncodeToString(sum[:]), Resources: []string{billingResource},
				GrantTypes: []authkit.OAuthGrantType{authkit.GrantClientCredentials}, Permissions: []string{"billing:customers:read"}},
		},
	}
}

// bearerRequest returns fresh requests bearing token, as a library's route
// receives them.
func bearerRequest(token string) func() *http.Request {
	return func() *http.Request {
		r := httptest.NewRequest(http.MethodPost, issuer+"/billing/v1/admin/refunds", nil)
		r.Header.Set("Authorization", "Bearer "+token)
		return r
	}
}

func basic(user, password string) string {
	return base64.StdEncoding.EncodeToString([]byte(url.QueryEscape(user) + ":" + url.QueryEscape(password)))
}

// TestSecurityAuthenticatorConformance (#444): Client.Authenticator(), and a
// Verifier's for a resource server's audiences, are the helpers/auth
// Authenticator a library guards its own routes with. Against a real AuthKit
// each passes helpers' conformance check (authtest.Check) in the root group's
// Scope: staff holding a root role's permissions, a user holding none,
// one-permission holders, a stale sign-in, a root API key, refused
// credentials (expired, forged, signed out, banned, deleted, a revoked API
// key), and Staff signed out last. A stale sign-in is RFC 9470's step-up and
// a replayed DPoP proof RFC 9449's challenge; behind a gate the request is
// verified once; Scope names a live group and a grant holds only in its own;
// an OAuth client's own token is an application at the Verifier's, holding
// nothing, and refused at the Client's.
func TestSecurityAuthenticatorConformance(t *testing.T) {
	ctx := context.Background()
	h := newHost(t, withHTTP(generousLimits), authtest.WithConfig(withBillingHost))
	verifier, err := h.auth.NewVerifier([]string{audience, billingResource})
	require.NoError(t, err)
	authenticators := map[string]hauth.Authenticator{"Client": h.auth.Authenticator(), "Verifier": verifier.Authenticator()}
	scope, err := h.auth.Scope(ctx, iam.RootGroup())
	require.NoError(t, err)
	root, err := h.auth.Group(ctx, iam.RootGroup())
	require.NoError(t, err)
	require.Equal(t, hauth.Scope{Authority: issuer, ID: root.ID}, scope)

	staff, user, stale := h.newAccount("akstaff"), h.newAccount("akuser"), h.newAccount("akstale")
	reader, updater := h.newAccount("akreader"), h.newAccount("akupdater")
	h.grant(iam.RootGroup(), staff, "billing")
	h.grant(iam.RootGroup(), stale, "billing")
	h.grant(iam.RootGroup(), reader, "reader")
	h.grant(iam.RootGroup(), updater, "updater")
	staffToken := h.login(staff).AccessToken
	userToken, readerToken, updaterToken := h.login(user).AccessToken, h.login(reader).AccessToken, h.login(updater).AccessToken
	staleToken := authtest.StaleSession(t, h.auth, h.login(stale).AccessToken)

	rootKey := func(name string) (iam.APIKey, string) {
		k, secret, err := createKey(h.auth, ctx, iam.SystemIdentity(), iam.RootGroup(), iam.NewAPIKey{Name: name, Role: roleIn(t, h.auth, iam.RootGroup(), "billing")})
		require.NoError(t, err)
		return k, secret
	}
	_, appKey := rootKey("billing-app")
	revoked, revokedKey := rootKey("billing-revoked")
	require.NoError(t, h.auth.RevokeAPIKey(ctx, iam.SystemIdentity(), iam.RootGroup(), revoked.ID))

	signedOut := h.login(h.newAccount("aksignedout")).AccessToken
	require.Equal(t, http.StatusNoContent, h.do(request{method: http.MethodDelete, path: "/logout", token: signedOut}).status)
	banned, deleted := h.newAccount("akbanned"), h.newAccount("akdeleted")
	h.grant(iam.RootGroup(), banned, "billing")
	h.grant(iam.RootGroup(), deleted, "billing")
	bannedToken, deletedToken := h.login(banned).AccessToken, h.login(deleted).AccessToken
	require.NoError(t, h.auth.Ban(ctx, iam.SystemIdentity(), banned.id, iam.Ban{Reason: "fraud"}))
	require.NoError(t, opErr(h.auth.DeleteUsers(ctx, iam.SystemIdentity(), []string{deleted.id})))

	header, claims := splitToken(t, staffToken)
	expiredClaims := maps.Clone(claims)
	expiredClaims["iat"], expiredClaims["exp"] = time.Now().Add(-30*time.Minute).Unix(), time.Now().Add(-10*time.Minute).Unix()
	expired := sign(t, jwt.SigningMethodRS256, signingKey(), header, expiredClaims)
	attacker, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	forged := sign(t, jwt.SigningMethodRS256, attacker, header, claims)

	authenticate := func(t *testing.T, a hauth.Authenticator, r *http.Request) hauth.Verified {
		t.Helper()
		v, err := a.Authenticate(r)
		require.NoError(t, err)
		return v
	}
	client := authenticators["Client"]

	t.Run("a stale sign-in is RFC 9470's step-up", func(t *testing.T) {
		r := bearerRequest(staleToken)()
		err := authenticate(t, client, r).(hauth.RecentSignInChecker).CheckRecentSignIn(ctx)
		var c *hauth.Challenge
		require.ErrorAs(t, err, &c)
		require.ErrorIs(t, err, hauth.ErrStepUpRequired)
		require.Equal(t, 15*time.Minute, c.MaxAge)
		require.Contains(t, c.Metadata["step_up_methods"], "password")
		refusal := hauth.Refuse(r, err)
		require.Equal(t, http.StatusUnauthorized, refusal.Status)
		require.Equal(t, `Bearer error="insufficient_user_authentication", max_age="900"`, refusal.Header.Get("WWW-Authenticate"))
		require.Equal(t, c.Metadata, refusal.Metadata)
	})

	t.Run("a person carries the account's contact", func(t *testing.T) {
		id := authenticate(t, client, bearerRequest(staffToken)()).Identity()
		require.Equal(t, staff.email, id.Email)
		require.Equal(t, staff.username, id.Username)
		require.True(t, id.EmailVerified)
	})

	t.Run("Scope names a live group, and a grant holds only in its own", func(t *testing.T) {
		_, err := h.auth.Scope(ctx, iam.GroupByID(uuid.NewString()))
		require.ErrorIs(t, err, iam.ErrGroupNotFound)
		persona, err := h.auth.Persona("merchant")
		require.NoError(t, err)
		g, err := h.auth.CreateGroup(ctx, iam.NewGroup{Persona: persona})
		require.NoError(t, err)
		merchant := iam.GroupByID(g.ID)
		merchantScope, err := h.auth.Scope(ctx, merchant)
		require.NoError(t, err)
		require.Equal(t, hauth.Scope{Authority: issuer, ID: g.ID}, merchantScope)
		_, key, err := createKey(h.auth, ctx, iam.SystemIdentity(), merchant, iam.NewAPIKey{Name: "support", Role: roleIn(t, h.auth, merchant, "support")})
		require.NoError(t, err)
		can := authenticate(t, client, bearerRequest(key)()).(hauth.PermissionChecker)
		ok, err := can.Can(ctx, merchantScope, merchantRefund)
		require.NoError(t, err)
		require.True(t, ok, "the merchant's key holds its role there")
		ok, _ = can.Can(ctx, scope, merchantRefund)
		require.False(t, ok, "and nothing on root")
		ok, _ = authenticate(t, client, bearerRequest(appKey)()).(hauth.PermissionChecker).Can(ctx, merchantScope, customersRead)
		require.False(t, ok, "a root key holds nothing in the merchant")
		require.NoError(t, h.auth.DeleteGroup(ctx, merchant))
		_, err = h.auth.Scope(ctx, merchant)
		require.ErrorIs(t, err, iam.ErrGroupNotFound, "a deleted group")
	})

	t.Run("behind a gate a DPoP proof is spent once", func(t *testing.T) {
		a := authenticators["Verifier"]
		key := testdpop.Key(t)
		minted := h.resourceToken(staffToken, key)
		proven := func() *http.Request {
			r := httptest.NewRequest(http.MethodPost, issuer+"/billing", nil)
			r.Header.Set("Authorization", "DPoP "+minted)
			r.Header.Set("DPoP", testdpop.Proof(t, key, http.MethodPost, issuer+"/billing", minted, nil))
			return r
		}
		var id hauth.Identity
		var gateErr error
		gated := verify.Required(verifier)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			v, err := a.Authenticate(r)
			if gateErr = err; err == nil {
				id = v.Identity()
			}
			w.WriteHeader(http.StatusNoContent)
		}))
		w := httptest.NewRecorder()
		gated.ServeHTTP(w, proven())
		require.Equal(t, http.StatusNoContent, w.Code, w.Body.String())
		require.NoError(t, gateErr, "the gate's verification is reused")
		require.Equal(t, staff.id, id.Subject)
		require.Equal(t, hauth.Invoker{Issuer: issuer, ID: staff.id}, id.Invoker, "a resource token's user acts themself; its client is no invoker")

		r := proven()
		_, err := a.Authenticate(r)
		require.NoError(t, err)
		_, err = a.Authenticate(r)
		require.ErrorIs(t, err, hauth.ErrSenderProofRequired, "with no gate a second Authenticate replays the proof")
		var c *hauth.Challenge
		require.ErrorAs(t, err, &c)
		refusal := hauth.Refuse(r, err)
		require.Equal(t, http.StatusUnauthorized, refusal.Status)
		require.True(t, strings.HasPrefix(refusal.Header.Get("WWW-Authenticate"), `DPoP error="invalid_dpop_proof"`), refusal.Header.Get("WWW-Authenticate"))

		_, err = client.Authenticate(proven())
		require.ErrorIs(t, err, hauth.ErrUnauthenticated, "the Client's own Authenticator takes no resource token")
	})

	t.Run("an OAuth client's own token is an application holding nothing", func(t *testing.T) {
		form := url.Values{"grant_type": {"client_credentials"}, "resource": {billingResource}}
		resp := h.do(request{method: http.MethodPost, path: "//oauth2/token", body: form.Encode(), header: http.Header{
			"Content-Type":  {"application/x-www-form-urlencoded"},
			"Authorization": {"Basic " + basic(billingBackend, billingSecret)},
		}})
		require.Equal(t, http.StatusOK, resp.status, resp.String())
		var out struct {
			AccessToken string `json:"access_token"`
		}
		resp.json(t, &out)
		v := authenticate(t, authenticators["Verifier"], bearerRequest(out.AccessToken)())
		id := v.Identity()
		require.Equal(t, hauth.Identity{
			Issuer: issuer, Subject: billingBackend, SubjectKind: hauth.SubjectApplication,
			Invoker:    hauth.Invoker{Issuer: issuer, ID: billingBackend},
			Credential: hauth.Credential{Kind: hauth.CredentialAccessToken, ID: id.Credential.ID},
		}, id)
		ok, err := v.(hauth.PermissionChecker).Can(ctx, scope, customersRead)
		require.NoError(t, err)
		require.False(t, ok, "its permissions are the resource server's to read, not a grant in a group")
		require.ErrorIs(t, v.(hauth.RecentSignInChecker).CheckRecentSignIn(ctx), hauth.ErrForbidden)
		_, err = client.Authenticate(bearerRequest(out.AccessToken)())
		require.ErrorIs(t, err, hauth.ErrUnauthenticated)
	})

	for _, name := range []string{"Client", "Verifier"} {
		t.Run("authtest.Check "+name, func(t *testing.T) {
			staffToken := h.login(staff).AccessToken
			conformance.Check(t, authenticators[name], conformance.Cases{
				Scope:       scope,
				Permissions: []string{customersRead, customersUpdate},
				Staff:       bearerRequest(staffToken),
				User:        bearerRequest(userToken),
				Holders: map[string]func() *http.Request{
					customersRead:   bearerRequest(readerToken),
					customersUpdate: bearerRequest(updaterToken),
				},
				Stale:       bearerRequest(staleToken),
				Application: bearerRequest(appKey),
				Refused: map[string]func() *http.Request{
					"expired":         bearerRequest(expired),
					"forged":          bearerRequest(forged),
					"signed-out":      bearerRequest(signedOut),
					"banned":          bearerRequest(bannedToken),
					"deleted":         bearerRequest(deletedToken),
					"revoked API key": bearerRequest(revokedKey),
				},
				Revoke: func() {
					require.Equal(t, http.StatusNoContent, h.do(request{method: http.MethodDelete, path: "/logout", token: staffToken}).status)
				},
			})
		})
	}
}
