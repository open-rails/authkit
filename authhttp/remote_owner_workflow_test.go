package authhttp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/embedded"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/open-rails/authkit/jwtkit"
	"github.com/open-rails/authkit/verify"
	"github.com/stretchr/testify/require"
)

func TestRemoteOwnerOperatesGroupHTTP(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	cfg := instanceCreateTestConfig()
	client := newServerClient(t, cfg, pg.Pool)
	ctx := context.Background()
	require.NoError(t, client.SeedPermissionGroupContainment(ctx))
	_, err := client.EnsureRootGroup(ctx)
	require.NoError(t, err)
	srv, err := newTestService(client, workflowHTTPConfig())
	require.NoError(t, err)
	owner, ownerToken := newInstanceTestUser(t, srv, "remoteowner")
	peer, _ := newInstanceTestUser(t, srv, "remotepeer")
	for _, slug := range []string{"remote-owned", "other-owned"} {
		w := postOrg(srv, ownerToken, `{"slug":"`+slug+`"}`)
		require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	}
	group := authkit.GroupRef{Persona: "org", Instance: "remote-owned"}
	gid, err := client.ResolveGroupIDForSlug(ctx, group)
	require.NoError(t, err)
	signer, err := jwtkit.NewRSASigner(2048, "remote-owner")
	require.NoError(t, err)
	app, err := client.UpsertRemoteApplication(ctx, authkit.RemoteApplication{
		Slug: "operable-owner", PermissionGroupID: gid, Issuer: "https://operable-owner.test", Enabled: true,
		PublicKeys: []authkit.RemoteAppKey{{KID: signer.KID(), PublicKeyPEM: adminTestPublicKeyPEM(t, signer.PublicKey())}},
	})
	require.NoError(t, err)
	require.NoError(t, client.OperatorAssignGroupRole(ctx, group, authkit.RemoteAppSubject(app.ID), "owner"))
	mint := func(perms []string) string {
		t.Helper()
		token, err := embedded.MintRemoteApplicationAccessToken(ctx, signer, authkit.RemoteApplicationAccessParams{Issuer: app.Issuer, Audiences: cfg.Token.ExpectedAudiences, TTL: time.Minute, Permissions: perms})
		require.NoError(t, err)
		return token
	}
	token := mint(nil)
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	verified, err := srv.verifier.VerifyRequest(request)
	require.NoError(t, err)
	// Verification is not a lease on database authority: a change between
	// verification and mutation must be seen inside the mutation transaction.
	require.NoError(t, client.OperatorAssignGroupRole(ctx, group, authkit.RemoteAppSubject(app.ID), "member"))
	require.ErrorIs(t, client.AssignGroupRoleFromClaims(ctx, verified, group, authkit.UserSubject(peer), "member"), authkit.ErrInsufficientRoleAuthority)
	require.NoError(t, client.OperatorAssignGroupRole(ctx, group, authkit.RemoteAppSubject(app.ID), "owner"))
	for _, mutate := range []func(*verify.Claims){
		func(c *verify.Claims) { c.Issuer = "https://another-issuer.test" },
		func(c *verify.Claims) { c.PermissionGroupAuthorityIssuer = "https://another-authority.test" },
		func(c *verify.Claims) { c.PermissionGroupPersona = "root" },
		func(c *verify.Claims) { c.TokenTyp = verify.DelegatedAccessTokenType; c.DelegatedSubject = "external" },
		func(c *verify.Claims) { c.TokenType = verify.APIKeyPrincipalType },
	} {
		invalid := verified
		mutate(&invalid)
		require.ErrorIs(t, client.AssignGroupRoleFromClaims(ctx, invalid, group, authkit.UserSubject(peer), "member"), authkit.ErrInsufficientRoleAuthority)
	}
	call := func(method, path, body, bearer string, status int) {
		t.Helper()
		w := serveAuthJSON(srv, method, path, body, bearer)
		require.Equal(t, status, w.Code, w.Body.String())
	}
	base := "/org/remote-owned/members/"
	// A signed app-self credential can manage existing users on its own group.
	call(http.MethodPost, "/org/remote-owned/members", `{"user_id":"`+peer+`","role":"member"}`, token, http.StatusOK)
	call(http.MethodPut, base+peer+"/roles/owner", "", mint([]string{"org:members:manage"}), http.StatusForbidden)
	call(http.MethodPut, base+peer+"/roles/member", "", mint([]string{}), http.StatusForbidden)
	call(http.MethodPut, "/org/other-owned/members/"+peer+"/roles/member", "", token, http.StatusForbidden)
	// Full live authority cannot widen a downscoped credential when replacing
	// an existing owner, even if the requested replacement is a lesser role.
	call(http.MethodPut, base+peer+"/roles/owner", "", token, http.StatusOK)
	call(http.MethodPut, base+peer+"/roles/member", "", mint([]string{"org:members:manage", "org:catalog:read"}), http.StatusForbidden)
	call(http.MethodDelete, base+peer, "", token, http.StatusOK)
	call(http.MethodDelete, base+owner, "", ownerToken, http.StatusOK)
	// The last native owner may leave: the remaining remote owner can restore
	// native ownership through exactly the supported signed HTTP interface.
	call(http.MethodPut, base+peer+"/roles/owner", "", token, http.StatusOK)
	call(http.MethodGet, "/org/remote-owned/members", "", token, http.StatusOK)
	call(http.MethodPost, "/org/remote-owned/members", `{"email":"unregistered@example.test","role":"member"}`, token, http.StatusForbidden)
	// Sender metadata on a delegated credential is never app-self authority.
	delegated, err := signer.SignWithHeaders(ctx, map[string]any{"iss": app.Issuer, "aud": cfg.Token.ExpectedAudiences, "exp": time.Now().Add(time.Minute).Unix(), "delegated_sub": "external-customer", "permissions": []string{"org:*"}}, map[string]any{"typ": verify.DelegatedAccessTokenType})
	require.NoError(t, err)
	w := serveAuthJSON(srv, http.MethodPut, base+owner+"/roles/owner", "", delegated)
	require.Contains(t, []int{http.StatusUnauthorized, http.StatusForbidden}, w.Code, w.Body.String())
	// A cached signature/issuer never preserves disabled application authority.
	app.Enabled = false
	_, err = client.UpsertRemoteApplication(ctx, *app)
	require.NoError(t, err)
	w = serveAuthJSON(srv, http.MethodPut, base+owner+"/roles/owner", "", token)
	require.Contains(t, []int{http.StatusUnauthorized, http.StatusForbidden}, w.Code, w.Body.String())
}

func TestCrossControlRemoteOwnerDoesNotSatisfyOwnerInvariant(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	client := newServerClient(t, instanceCreateTestConfig(), pg.Pool)
	ctx := context.Background()
	require.NoError(t, client.SeedPermissionGroupContainment(ctx))
	_, err := client.EnsureRootGroup(ctx)
	require.NoError(t, err)
	srv, err := newTestService(client, workflowHTTPConfig())
	require.NoError(t, err)
	owner, token := newInstanceTestUser(t, srv, "phantomowner")
	for _, slug := range []string{"control-one", "control-two"} {
		w := postOrg(srv, token, `{"slug":"`+slug+`"}`)
		require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	}
	first := authkit.GroupRef{Persona: "org", Instance: "control-one"}
	second := authkit.GroupRef{Persona: "org", Instance: "control-two"}
	gid, err := client.ResolveGroupIDForSlug(ctx, first)
	require.NoError(t, err)
	other, err := client.ResolveGroupIDForSlug(ctx, second)
	require.NoError(t, err)
	app, err := client.UpsertRemoteApplication(ctx, authkit.RemoteApplication{Slug: "wrong-control", PermissionGroupID: gid, Issuer: "https://wrong-control.test", JWKSURI: "https://wrong-control.test/jwks", Enabled: true})
	require.NoError(t, err)
	require.ErrorIs(t, client.OperatorAssignGroupRole(ctx, second, authkit.RemoteAppSubject(app.ID), "owner"), authkit.ErrInsufficientRoleAuthority)
	// Simulate an old invalid assignment: it must not allow the real owner to
	// depart, although ordinary non-owner ancestor assignments remain valid.
	_, err = client.Postgres().Exec(ctx, `INSERT INTO group_remote_application_roles(permission_group_id,remote_application_id,role) VALUES($1,$2,'owner')`, other, app.ID)
	require.NoError(t, err)
	w := serveAuthJSON(srv, http.MethodDelete, "/org/control-two/members/"+owner, "", token)
	require.Equal(t, http.StatusConflict, w.Code, w.Body.String())
	requireErrorCode(t, w.Body.String(), string(authkit.CodeCannotRemoveLastOwner))
}
