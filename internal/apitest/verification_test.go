package apitest_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/jose"
	"github.com/open-rails/authkit/internal/testkeys"
	"github.com/open-rails/authkit/keys"
	"github.com/open-rails/authkit/verify"
	"github.com/stretchr/testify/require"
)

// gateStatus is the status verify's middleware gate answers for token.
func gateStatus(t *testing.T, gate func(http.Handler) http.Handler, token string) int {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/resource", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	gate(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })).ServeHTTP(w, r)
	return w.Code
}

// The root_role claim is display only: minted for a root-role holder, it
// grants nothing. A forged or stale one is refused at every permission gate,
// which reads the role live, and a host cannot mint one.
func TestRootRoleClaimIsDisplayOnly(t *testing.T) {
	rbac := authkit.NewRoles()
	admin := rbac.Root.Role("admin", rbac.Root.Users.Read)
	signer := testkeys.RSA("root-role")
	auth, _ := authtest.New(t, authtest.WithConfig(func(c *authkit.Config) {
		c.Roles = rbac
		c.TwoFactor.Mode = iam.TwoFactorDisabled
	}), authtest.WithDeps(func(d *authkit.Deps) { d.KeySource = testkeys.Source(signer) }))
	ctx := t.Context()
	boss, plain := authtest.NewUser(t, auth), authtest.NewUser(t, auth)
	authtest.GrantRole(t, auth, iam.RootGroup(), iam.UserSubject(boss.ID), admin)
	gate := verify.RequirePermissionOn(auth, iam.RootGroup(), rbac.Root.Users.Read)

	bossToken := authtest.SignIn(t, auth, boss).AccessToken
	cl, err := auth.Verify(ctx, bossToken)
	require.NoError(t, err)
	require.Equal(t, admin.String(), cl.RootRole)
	require.Equal(t, http.StatusNoContent, gateStatus(t, gate, bossToken), "control: the holder passes")

	session, err := auth.Verify(ctx, authtest.SignIn(t, auth, plain).AccessToken)
	require.NoError(t, err)
	require.Empty(t, session.RootRole)
	now := time.Now()
	forged, err := jose.Sign(ctx, signer, jose.AccessTokenType, map[string]any{
		"iss": authtest.Issuer, "aud": []string{authtest.Audience}, "sub": plain.ID, "sid": session.SessionID,
		"iat": now.Unix(), "exp": now.Add(time.Minute).Unix(), "root_role": admin.String(),
	})
	require.NoError(t, err)
	cl, err = auth.Verify(ctx, forged)
	require.NoError(t, err)
	require.Equal(t, admin.String(), cl.RootRole, "the claim is surfaced for display")
	require.Equal(t, http.StatusForbidden, gateStatus(t, gate, forged), "a claimed role grants nothing")

	require.NoError(t, auth.RemoveGroupMember(ctx, iam.SystemIdentity(), iam.RootGroup(), iam.UserSubject(boss.ID)))
	require.Contains(t, []int{http.StatusUnauthorized, http.StatusForbidden}, gateStatus(t, gate, bossToken), "a stale role grants nothing")

	_, err = auth.MintAccessToken(ctx, plain.ID, iam.AccessTokenOptions{Claims: map[string]any{"root_role": admin.String()}})
	e, ok := iam.AsError(err)
	require.True(t, ok, "a host cannot mint the claim: %v", err)
	require.Equal(t, "claims.root_role", e.Param())
}

// A remote application is a registry entry a resource server trusts: its
// issuer, keys and the ceiling its role confers, read live. AuthKit itself
// authenticates none of its tokens. A disabled one is read as disabled at
// once.
func TestRemoteApplicationRegistry(t *testing.T) {
	m := newOrgModel()
	auth, _ := authtest.New(t, authtest.WithConfig(func(c *authkit.Config) {
		m.config(c)
		c.Token.AllowPrivateNetworkJWKS = true
	}))
	ctx := t.Context()
	owner := authtest.NewUser(t, auth)
	group := newGroup(t, auth, m.org.Persona, owner.ID)
	signer := testkeys.RSA("app-1")
	app, err := auth.UpsertRemoteApplication(ctx, iam.SystemIdentity(), group, iam.RemoteApplication{
		Issuer: "https://verification-app.test", Enabled: true,
		PublicKeys: []iam.RemoteApplicationKey{{KID: signer.KID(), PublicKeyPEM: publicKeyPEM(t, signer.Public())}},
	})
	require.NoError(t, err)
	authtest.GrantRole(t, auth, group, iam.RemoteApplicationSubject(app.ID), m.member)
	const resource = "https://partner.example"
	sign := func(s keys.Signer, typ string, claims map[string]any) string {
		t.Helper()
		now := time.Now()
		base := map[string]any{"iss": app.Issuer, "aud": []string{resource}, "iat": now.Unix(), "exp": now.Add(time.Minute).Unix(), "sub": "customer-1", "client_id": "app"}
		for k, v := range claims {
			base[k] = v
		}
		token, err := jose.Sign(ctx, s, typ, base)
		require.NoError(t, err)
		return token
	}
	// trusted is a resource server's view of the registry.
	trusted := func(t *testing.T) (iam.RemoteApplication, *verify.Verifier, error) {
		t.Helper()
		got, err := auth.RemoteApplication(ctx, iam.AppByIssuer(app.Issuer))
		if err == nil && !got.Enabled {
			err = iam.ErrRemoteApplicationNotFound
		}
		if err != nil {
			return got, nil, err
		}
		v := verify.NewVerifier(verify.WithHTTPClient(http.DefaultClient))
		opts := verify.IssuerOptions{Keys: got.PublicKeys}
		if got.Mode == iam.RemoteApplicationModeJWKS {
			opts = verify.IssuerOptions{JWKSURI: got.JWKSURI}
		}
		require.NoError(t, v.AddIssuer(got.Issuer, []string{resource}, opts))
		return got, v, nil
	}

	got, v, err := trusted(t)
	require.NoError(t, err)
	require.Equal(t, group.ID(), got.GroupID)
	require.Equal(t, []iam.Perm{m.catalog}, got.Permissions, "the ceiling is its role's grants")
	cl, err := v.Verify(ctx, sign(signer, jose.ResourceAccessTokenType, nil))
	require.NoError(t, err)
	require.Equal(t, "customer-1", cl.Subject)
	require.Equal(t, app.Issuer, cl.Issuer)

	// AuthKit authenticates no application token, whatever its type.
	for _, typ := range []string{jose.ResourceAccessTokenType, jose.AccessTokenType, "remote-application-access+jwt", "delegated-access+jwt"} {
		_, err := auth.Verify(ctx, sign(signer, typ, map[string]any{"aud": []string{authtest.Audience}, "delegated_sub": "customer-1"}))
		require.Error(t, err, typ)
	}

	// Rotating the static key takes effect on the next read; a JWK names
	// its own kid.
	rotated := testkeys.RSA("app-2")
	jwk := keys.PublicJWK(rotated.Public(), rotated.KID(), "")
	app.PublicKeys = []iam.RemoteApplicationKey{{JWK: &jwk}}
	app, err = auth.UpsertRemoteApplication(ctx, iam.SystemIdentity(), group, app)
	require.NoError(t, err)
	_, v, err = trusted(t)
	require.NoError(t, err)
	_, err = v.Verify(ctx, sign(signer, jose.ResourceAccessTokenType, nil))
	require.Error(t, err, "the retired key")
	_, err = v.Verify(ctx, sign(rotated, jose.ResourceAccessTokenType, nil))
	require.NoError(t, err)

	// Switching to JWKS mode trusts only the endpoint's keys.
	published := testkeys.EC("app-3")
	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(keys.JWKS{Keys: []keys.JWK{keys.PublicJWK(published.Public(), published.KID(), "")}})
	}))
	t.Cleanup(jwks.Close)
	app.Mode, app.JWKSURI, app.PublicKeys = iam.RemoteApplicationModeJWKS, jwks.URL, nil
	app, err = auth.UpsertRemoteApplication(ctx, iam.SystemIdentity(), group, app)
	require.NoError(t, err)
	_, v, err = trusted(t)
	require.NoError(t, err)
	_, err = v.Verify(ctx, sign(rotated, jose.ResourceAccessTokenType, nil))
	require.Error(t, err, "the static key no longer verifies")
	_, err = v.Verify(ctx, sign(published, jose.ResourceAccessTokenType, nil))
	require.NoError(t, err)

	// A resource server trusts a disabled application no more.
	app.Enabled = false
	_, err = auth.UpsertRemoteApplication(ctx, iam.SystemIdentity(), group, app)
	require.NoError(t, err)
	_, _, err = trusted(t)
	require.ErrorIs(t, err, iam.ErrRemoteApplicationNotFound)
}
