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
	"github.com/open-rails/authkit/internal/errmodel"
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
		c.Keys.Source = testkeys.Source(signer)
	}))
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

	_, err = auth.RemoveGroupMembers(ctx, iam.SystemActor(), iam.RootGroup(), []iam.Subject{iam.UserSubject(boss.ID)})
	require.NoError(t, err)
	require.Contains(t, []int{http.StatusUnauthorized, http.StatusForbidden}, gateStatus(t, gate, bossToken), "a stale role grants nothing")

	minted, err := auth.MintAccessToken(ctx, plain.ID, iam.AccessTokenOptions{Claims: map[string]any{"root_role": admin.String()}})
	require.NoError(t, err)
	cl, err = auth.Verify(ctx, minted.Value)
	require.NoError(t, err)
	require.Empty(t, cl.RootRole, "a host cannot mint the claim")
}

// A remote application's tokens authenticate through the Client and through
// a Client-built Verifier for another audience, bounded by its stored
// authority. Its live row decides at once: a key rotation or trust-mode
// change needs no restart, and a disabled application's tokens stop.
func TestRemoteApplicationTokens(t *testing.T) {
	m := newOrgModel()
	auth, _ := authtest.New(t, authtest.WithConfig(func(c *authkit.Config) {
		m.config(c)
		c.Applications.AllowPrivateNetworkJWKS = true
	}))
	ctx := t.Context()
	owner := authtest.NewUser(t, auth)
	group := newGroup(t, auth, m.org.Persona, owner.ID)
	signer := testkeys.RSA("app-1")
	app, err := auth.UpsertRemoteApplication(ctx, iam.SystemActor(), group, iam.RemoteApplication{
		Slug: "verification-app", Issuer: "https://verification-app.test", Enabled: true,
		PublicKeys: []iam.RemoteApplicationKey{{KID: signer.KID(), PublicKeyPEM: publicKeyPEM(t, signer.Public())}},
	})
	require.NoError(t, err)
	authtest.GrantRole(t, auth, group, iam.RemoteApplicationSubject(app.ID), m.member)
	sign := func(s keys.Signer, typ, aud string, claims map[string]any) string {
		t.Helper()
		now := time.Now()
		base := map[string]any{"iss": app.Issuer, "aud": []string{aud}, "iat": now.Unix(), "exp": now.Add(time.Minute).Unix()}
		for k, v := range claims {
			base[k] = v
		}
		token, err := jose.Sign(ctx, s, typ, base)
		require.NoError(t, err)
		return token
	}
	catalog := m.catalog.String()

	// The application acting as itself carries its stored grants, bound to
	// its group; a permissions claim only narrows them.
	cl, err := auth.Verify(ctx, sign(signer, jose.RemoteApplicationAccessTokenType, authtest.Audience, nil))
	require.NoError(t, err)
	require.Equal(t, iam.ActorRemoteApplication, cl.Kind)
	require.Equal(t, app.ID, cl.RemoteApplicationID)
	require.Equal(t, group.ID(), cl.Group.GroupID)
	require.Equal(t, authtest.Issuer, cl.Group.AuthorityIssuer)
	require.Equal(t, []string{catalog}, cl.Permissions)
	_, err = auth.Verify(ctx, sign(signer, jose.RemoteApplicationAccessTokenType, authtest.Audience, map[string]any{"permissions": []string{m.org.Members.Manage.String()}}))
	require.Equal(t, errmodel.CodePermissionNotGranted, errmodel.CodeOf(err), "a claim cannot widen the stored grants")

	// Its delegation grants what it names, within the same ceiling.
	cl, err = auth.Verify(ctx, sign(signer, jose.DelegatedAccessTokenType, authtest.Audience, map[string]any{"delegated_sub": "customer-1", "permissions": []string{catalog}, "sid": "app-session"}))
	require.NoError(t, err)
	require.Equal(t, iam.ActorDelegated, cl.Kind)
	require.Equal(t, app.ID, cl.RemoteApplicationID)
	require.Equal(t, []string{catalog}, cl.Permissions)
	require.Empty(t, cl.SessionID, "an application's sign-ins are not AuthKit's")
	actor, ok := verify.ActorFromClaims(cl)
	require.True(t, ok)
	allowed, err := auth.Can(ctx, actor, group, m.catalog)
	require.NoError(t, err)
	require.True(t, allowed)
	_, err = auth.Verify(ctx, sign(signer, jose.DelegatedAccessTokenType, authtest.Audience, map[string]any{"delegated_sub": "customer-1", "permissions": []string{m.org.All().String()}}))
	require.Equal(t, errmodel.CodePermissionNotGranted, errmodel.CodeOf(err))
	_, err = auth.Verify(ctx, sign(signer, jose.AccessTokenType, authtest.Audience, map[string]any{"sub": owner.ID}))
	require.Equal(t, errmodel.CodeBadIssuer, errmodel.CodeOf(err), "an application mints no user tokens")

	// A Client-built Verifier serves another audience, which the Client
	// itself refuses; it verifies the application's service JWTs too.
	partner, err := auth.NewVerifier([]string{"partner-api"}, verify.WithRequestOrigin("https://partner.example"))
	require.NoError(t, err)
	forPartner := sign(signer, jose.RemoteApplicationAccessTokenType, "partner-api", nil)
	_, err = auth.Verify(ctx, forPartner)
	require.Equal(t, errmodel.CodeBadAudience, errmodel.CodeOf(err))
	cl, err = partner.Verify(ctx, forPartner)
	require.NoError(t, err)
	require.Equal(t, app.ID, cl.RemoteApplicationID)
	service, err := partner.VerifyServiceJWT(ctx, sign(signer, jose.ServiceJWTType, "partner-api", map[string]any{
		"sub": "billing", "jti": "svc-1", "nbf": time.Now().Unix(), "token_use": iam.ServiceJWTTokenUse, "permissions": []string{"ledger:write"},
	}))
	require.NoError(t, err)
	require.Equal(t, app.Issuer, service.Issuer)
	require.Equal(t, http.StatusNoContent, gateStatus(t, verify.RequirePermissionOn(partner, group, m.catalog), forPartner), "the Verifier is an Authority")

	// Rotating the static key takes effect on the next request.
	rotated := testkeys.RSA("app-2")
	app.PublicKeys = []iam.RemoteApplicationKey{{KID: rotated.KID(), PublicKeyPEM: publicKeyPEM(t, rotated.Public())}}
	app, err = auth.UpsertRemoteApplication(ctx, iam.SystemActor(), group, app)
	require.NoError(t, err)
	_, err = auth.Verify(ctx, sign(signer, jose.RemoteApplicationAccessTokenType, authtest.Audience, nil))
	require.Error(t, err, "the retired key")
	_, err = auth.Verify(ctx, sign(rotated, jose.RemoteApplicationAccessTokenType, authtest.Audience, nil))
	require.NoError(t, err)

	// Switching to JWKS mode trusts only the endpoint's keys.
	published := testkeys.EC("app-3")
	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(keys.JWKS{Keys: []keys.JWK{keys.PublicJWK(published.Public(), published.KID(), "")}})
	}))
	t.Cleanup(jwks.Close)
	app.Mode, app.JWKSURI, app.PublicKeys = iam.RemoteApplicationModeJWKS, jwks.URL, nil
	app, err = auth.UpsertRemoteApplication(ctx, iam.SystemActor(), group, app)
	require.NoError(t, err)
	_, err = auth.Verify(ctx, sign(rotated, jose.RemoteApplicationAccessTokenType, authtest.Audience, nil))
	require.Error(t, err, "the static key no longer verifies")
	_, err = auth.Verify(ctx, sign(published, jose.RemoteApplicationAccessTokenType, authtest.Audience, nil))
	require.NoError(t, err)
	require.NoError(t, auth.CheckIssuerKeys(ctx))
	statuses := auth.IssuerKeyStatuses()
	require.Len(t, statuses, 1)
	require.Equal(t, app.Issuer, statuses[0].Issuer)
	require.True(t, statuses[0].Fresh)

	// Disabling the application stops its tokens everywhere at once.
	app.Enabled = false
	_, err = auth.UpsertRemoteApplication(ctx, iam.SystemActor(), group, app)
	require.NoError(t, err)
	_, err = auth.Verify(ctx, sign(published, jose.RemoteApplicationAccessTokenType, authtest.Audience, nil))
	require.Error(t, err)
	_, err = partner.Verify(ctx, sign(published, jose.RemoteApplicationAccessTokenType, "partner-api", nil))
	require.Error(t, err)
}
