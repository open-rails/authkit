package authkit_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"

	"github.com/open-rails/authkit"
	hauth "github.com/open-rails/authkit/auth"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/verify"
)

// entitled is ContentKit's access.Entitled.
type entitled interface{ Entitlements() []string }

// TestAuthenticatorEntitlements (#455): every Verified has Entitlements(),
// its token's entitlements claim (ContentKit's access.Entitled), at
// Client.Authenticator(), a Verifier's, an identity-only verify.Verifier and
// for a trusted issuer's resource token. A token minted with entitlements
// exposes them; one without, an API key and a client's own token none; an
// anonymous request has no Verified.
func TestAuthenticatorEntitlements(t *testing.T) {
	ctx := t.Context()
	rbac := authkit.NewRoles()
	merchant := rbac.Persona("merchant", authkit.RemoteApplications, authkit.APIKeys)
	support := merchant.Role("support", merchant.Permission("payments", "refund"))
	var held sync.Map
	as := authtest.NewAuthorizationServer(t,
		authtest.WithConfig(func(c *authkit.Config) {
			c.Roles = rbac
			c.Token.EntitlementAllowlist = []string{"premium"}
			c.Resource = authkit.ResourceConfig{ID: oauthResource}
		}),
		authtest.WithDeps(func(d *authkit.Deps) {
			d.Entitlements = func(_ context.Context, ids []string) (map[string][]string, error) {
				out := map[string][]string{}
				for _, id := range ids {
					if names, ok := held.Load(id); ok {
						out[id] = names.([]string)
					}
				}
				return out, nil
			}
		}))
	auth := as.Client
	g, err := auth.CreateGroup(ctx, iam.NewGroup{Persona: merchant.Persona})
	require.NoError(t, err)
	group := iam.GroupByID(g.ID)
	f := newFakeIssuer(t)
	require.NoError(t, auth.DeclareRemoteApplications(ctx, group, []iam.RemoteApplication{{Issuer: f.url, Enabled: true, Role: support}}))

	premium, plain := authtest.NewUser(t, auth), authtest.NewUser(t, auth)
	held.Store(premium.ID, []string{"premium", "unselected"})
	premiumToken, plainToken := authtest.SignIn(t, auth, premium).AccessToken, authtest.SignIn(t, auth, plain).AccessToken
	key, err := auth.CreateAPIKey(ctx, iam.SystemIdentity(), group, iam.NewAPIKey{Name: "backend", Role: support})
	require.NoError(t, err)

	verifier, err := auth.NewVerifier([]string{authtest.Audience})
	require.NoError(t, err)
	identityOnly := verify.NewVerifier(verify.WithHTTPClient(as.HTTPClient()))
	t.Cleanup(identityOnly.Close)
	require.NoError(t, identityOnly.AddIssuer(as.URL, []string{authtest.Audience}, verify.IssuerOptions{JWKSURI: as.URL + iam.JWKSPath, IsLocal: true}))

	request := func(token string) *http.Request {
		r := httptest.NewRequest(http.MethodGet, oauthResource+"/v1/things", nil)
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		return r
	}
	type authenticate func(*http.Request) (hauth.Verified, error)
	entitlements := func(t *testing.T, a authenticate, token string) []string {
		t.Helper()
		v, err := a(request(token))
		require.NoError(t, err)
		e, ok := v.(entitled)
		require.True(t, ok, "%T has no Entitlements", v)
		return e.Entitlements()
	}

	for name, a := range map[string]authenticate{
		"Client":   auth.Authenticator().Authenticate,
		"Verifier": verifier.Authenticator().Authenticate,
		"identity-only verify.Verifier": func(r *http.Request) (hauth.Verified, error) {
			return identityOnly.AuthenticateRequest(r.Context(), r)
		},
	} {
		t.Run(name, func(t *testing.T) {
			got := entitlements(t, a, premiumToken)
			require.Equal(t, []string{"premium"}, got, "the allowlisted entitlement minted into the token")
			got[0] = "changed"
			require.Equal(t, []string{"premium"}, entitlements(t, a, premiumToken), "a copy")
			require.Empty(t, entitlements(t, a, plainToken), "a token minted without entitlements")
			_, err := a(request(""))
			require.ErrorIs(t, err, hauth.ErrUnauthenticated, "an anonymous request")
		})
	}

	t.Run("a person carries the account's contact and the token's entitlements", func(t *testing.T) {
		v, err := auth.Authenticator().Authenticate(request(premiumToken))
		require.NoError(t, err)
		require.Equal(t, premium.Email, v.Identity().Email)
		require.Equal(t, []string{"premium"}, v.(entitled).Entitlements())
	})

	t.Run("an API key has none", func(t *testing.T) {
		require.Empty(t, entitlements(t, auth.Authenticator().Authenticate, key.Secret))
		require.Empty(t, entitlements(t, verifier.Authenticator().Authenticate, key.Secret))
	})

	t.Run("a trusted issuer's resource token", func(t *testing.T) {
		a := auth.Authenticator().Authenticate
		require.Equal(t, []string{"gold"}, entitlements(t, a, f.token(t, "at+jwt", jwt.MapClaims{"entitlements": []string{"gold"}})), "the issuer's claim")
		require.Empty(t, entitlements(t, a, f.token(t, "at+jwt", nil)), "a user's token without the claim")
		require.Empty(t, entitlements(t, a, f.token(t, "at+jwt", jwt.MapClaims{"sub": "shop-console"})), "a client's own token")
	})
}
