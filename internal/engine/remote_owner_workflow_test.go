package engine

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/internal/ident"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/open-rails/authkit/jwtkit"
	"github.com/open-rails/authkit/verify"
	"github.com/stretchr/testify/require"
)

func TestRemoteOwnerOperatesGroupHTTP(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	cfg := orgTestConfig()
	client := newServerClient(t, cfg, pg.Pool)
	ctx := context.Background()
	_, err := client.ensureRootGroup(ctx)
	require.NoError(t, err)
	srv, err := newTestService(client, workflowHTTPConfig())
	require.NoError(t, err)
	owner, ownerToken := newInstanceTestUser(t, srv, "remoteowner")
	peer, _ := newInstanceTestUser(t, srv, "remotepeer")
	gid, err := seedGroup(ctx, client, ident.Persona("org"), owner)
	require.NoError(t, err)
	otherID, err := seedGroup(ctx, client, ident.Persona("org"), owner)
	require.NoError(t, err)
	group := iam.GroupByID(gid)
	signer, err := jwtkit.NewRSASigner(2048, "remote-owner")
	require.NoError(t, err)
	app, err := client.UpsertRemoteApplication(ctx, iam.SystemActor(), iam.GroupByID(gid), iam.RemoteApplication{
		Slug: "operable-owner", Issuer: "https://operable-owner.test", Enabled: true,
		PublicKeys: []iam.RemoteApplicationKey{{KID: signer.KID(), PublicKeyPEM: adminTestPublicKeyPEM(t, signer.PublicKey())}},
	})
	require.NoError(t, err)
	grantRole(t, client, group, iam.RemoteApplicationSubject(app.ID), "owner")
	mint := func(perms []string) string {
		t.Helper()
		return mintRemoteApplicationToken(t, signer, app.Issuer, cfg.Token.ExpectedAudiences, perms)
	}
	token := mint(nil)
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	verified, err := srv.Verifier().VerifyRequest(request)
	require.NoError(t, err)
	// Verification is not a lease on database authority: a change between
	// verification and mutation must be seen inside the mutation transaction.
	actor, ok := verify.ActorFromClaims(verified)
	require.True(t, ok)
	require.Equal(t, iam.ActorRemoteApplication, actor.Kind())
	grantRole(t, client, group, iam.RemoteApplicationSubject(app.ID), "member")
	require.ErrorIs(t, assignRole(ctx, client, actor, group, iam.UserSubject(peer), "member"), iam.ErrInsufficientAuthority)
	grantRole(t, client, group, iam.RemoteApplicationSubject(app.ID), "owner")
	// Application authority is bound to its controlling group and its ceiling.
	require.ErrorIs(t, assignRole(ctx, client, actor, iam.GroupByID(otherID), iam.UserSubject(peer), "member"), iam.ErrInsufficientAuthority)
	require.ErrorIs(t, assignRole(ctx, client, actor.Within(ident.Perm("org:catalog:read")), group, iam.UserSubject(peer), "member"), iam.ErrInsufficientAuthority)
	forged := verified
	forged.TokenType = verify.APIKeyPrincipalType
	_, ok = verify.ActorFromClaims(forged)
	require.False(t, ok)
	_, err = client.AssignGroupRoles(ctx, iam.Actor{}, group, []iam.Subject{iam.UserSubject(peer)}, mustRole("org:member"))
	require.ErrorIs(t, err, iam.ErrInsufficientAuthority)
	call := func(method, path, body, bearer string, status int) {
		t.Helper()
		w := serveAuthJSON(srv, method, path, body, bearer)
		require.Equal(t, status, w.Code, w.Body.String())
	}
	base := "/groups/" + gid + "/members/"
	// A signed app-self credential can manage existing users on its own group.
	call(http.MethodPost, "/groups/"+gid+"/members", `{"user_id":"`+peer+`","role":"member"}`, token, http.StatusOK)
	call(http.MethodPut, base+peer+"/roles/owner", "", mint([]string{"org:members:manage"}), http.StatusForbidden)
	call(http.MethodPut, base+peer+"/roles/member", "", mint([]string{}), http.StatusForbidden)
	call(http.MethodPut, "/groups/"+otherID+"/members/"+peer+"/roles/member", "", token, http.StatusForbidden)
	// Full live authority cannot widen a downscoped credential when replacing
	// an existing owner, even if the requested replacement is a lesser role.
	call(http.MethodPut, base+peer+"/roles/owner", "", token, http.StatusOK)
	call(http.MethodPut, base+peer+"/roles/member", "", mint([]string{"org:members:manage", "org:catalog:read"}), http.StatusForbidden)
	call(http.MethodDelete, base+peer, "", token, http.StatusNoContent)
	call(http.MethodDelete, base+owner, "", ownerToken, http.StatusNoContent)
	// The last native owner may leave: the remaining remote owner can restore
	// native ownership through exactly the supported signed HTTP interface.
	call(http.MethodPut, base+peer+"/roles/owner", "", token, http.StatusOK)
	call(http.MethodGet, "/groups/"+gid+"/members", "", token, http.StatusOK)
	call(http.MethodPost, "/groups/"+gid+"/members", `{"email":"unregistered@example.test","role":"member"}`, token, http.StatusForbidden)
	// Sender metadata on a delegated credential is never app-self authority.
	delegated, err := signer.SignWithHeaders(ctx, map[string]any{"iss": app.Issuer, "aud": cfg.Token.ExpectedAudiences, "exp": time.Now().Add(time.Minute).Unix(), "delegated_sub": "external-customer", "permissions": []string{"org:*"}}, map[string]any{"typ": jwtkit.DelegatedAccessTokenType})
	require.NoError(t, err)
	w := serveAuthJSON(srv, http.MethodPut, base+owner+"/roles/owner", "", delegated)
	require.Contains(t, []int{http.StatusUnauthorized, http.StatusForbidden}, w.Code, w.Body.String())
	// A cached signature/issuer never preserves disabled application authority.
	app.Enabled = false
	_, err = client.UpsertRemoteApplication(ctx, iam.SystemActor(), iam.GroupByID(app.PermissionGroupID), *app)
	require.NoError(t, err)
	w = serveAuthJSON(srv, http.MethodPut, base+owner+"/roles/owner", "", token)
	require.Contains(t, []int{http.StatusUnauthorized, http.StatusForbidden}, w.Code, w.Body.String())
}

func TestCrossControlRemoteOwnerDoesNotSatisfyOwnerInvariant(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	client := newServerClient(t, orgTestConfig(), pg.Pool)
	ctx := context.Background()
	_, err := client.ensureRootGroup(ctx)
	require.NoError(t, err)
	srv, err := newTestService(client, workflowHTTPConfig())
	require.NoError(t, err)
	owner, token := newInstanceTestUser(t, srv, "phantomowner")
	gid, err := seedGroup(ctx, client, ident.Persona("org"), owner)
	require.NoError(t, err)
	other, err := seedGroup(ctx, client, ident.Persona("org"), owner)
	require.NoError(t, err)
	second := iam.GroupByID(other)
	app, err := client.UpsertRemoteApplication(ctx, iam.SystemActor(), iam.GroupByID(gid), iam.RemoteApplication{Slug: "wrong-control", Issuer: "https://wrong-control.test", JWKSURI: "https://wrong-control.test/jwks", Enabled: true})
	require.NoError(t, err)
	require.ErrorIs(t, assignRole(ctx, client, iam.SystemActor(), second, iam.RemoteApplicationSubject(app.ID), "owner"), iam.ErrRemoteApplicationNotFound)
	// Simulate an old invalid assignment: it must not allow the real owner to
	// depart, although ordinary non-owner ancestor assignments remain valid.
	_, err = client.pg.Exec(ctx, `INSERT INTO group_remote_application_roles(permission_group_id,remote_application_id,role) VALUES($1,$2,'owner')`, other, app.ID)
	require.NoError(t, err)
	w := serveAuthJSON(srv, http.MethodDelete, "/groups/"+other+"/members/"+owner, "", token)
	require.Equal(t, http.StatusConflict, w.Code, w.Body.String())
	requireErrorCode(t, w.Body.String(), string(errmodel.CodeLastOwner))
}
