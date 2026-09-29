package engine

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/open-rails/authkit/iam"
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
	_, err := client.ensureRootGroup(ctx)
	require.NoError(t, err)
	srv, err := newTestService(client, workflowHTTPConfig())
	require.NoError(t, err)
	owner, ownerToken := newInstanceTestUser(t, srv, "remoteowner")
	peer, _ := newInstanceTestUser(t, srv, "remotepeer")
	for _, slug := range []string{"remote-owned", "other-owned"} {
		w := postOrg(srv, ownerToken, `{"slug":"`+slug+`"}`)
		require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	}
	group := iam.GroupBySlug("org", "remote-owned")
	gid, err := client.ResolveGroupIDForSlug(ctx, group)
	require.NoError(t, err)
	signer, err := jwtkit.NewRSASigner(2048, "remote-owner")
	require.NoError(t, err)
	app, err := client.UpsertRemoteApplication(ctx, iam.RemoteApplication{
		Slug: "operable-owner", PermissionGroupID: gid, Issuer: "https://operable-owner.test", Enabled: true,
		PublicKeys: []iam.RemoteApplicationKey{{KID: signer.KID(), PublicKeyPEM: adminTestPublicKeyPEM(t, signer.PublicKey())}},
	})
	require.NoError(t, err)
	grantRole(t, client, group, iam.RemoteApplicationSubject(app.ID), "owner")
	mint := func(perms []string) string {
		t.Helper()
		token, err := MintRemoteApplicationAccessToken(ctx, signer, iam.RemoteApplicationAccessParams{Issuer: app.Issuer, Audiences: cfg.Token.ExpectedAudiences, TTL: time.Minute, Permissions: perms})
		require.NoError(t, err)
		return token
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
	require.ErrorIs(t, assignRole(ctx, client, actor, group, iam.UserSubject(peer), "member"), iam.ErrInsufficientRoleAuthority)
	grantRole(t, client, group, iam.RemoteApplicationSubject(app.ID), "owner")
	// Application authority is bound to its controlling group and its ceiling.
	require.ErrorIs(t, assignRole(ctx, client, actor, iam.GroupBySlug("org", "other-owned"), iam.UserSubject(peer), "member"), iam.ErrInsufficientRoleAuthority)
	require.ErrorIs(t, assignRole(ctx, client, actor.Within("org:catalog:read"), group, iam.UserSubject(peer), "member"), iam.ErrInsufficientRoleAuthority)
	forged := verified
	forged.TokenType = verify.APIKeyPrincipalType
	_, ok = verify.ActorFromClaims(forged)
	require.False(t, ok)
	_, err = client.AssignGroupRoles(ctx, iam.Actor{}, group, []iam.Subject{iam.UserSubject(peer)}, "member")
	require.ErrorIs(t, err, iam.ErrInsufficientRoleAuthority)
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
	delegated, err := signer.SignWithHeaders(ctx, map[string]any{"iss": app.Issuer, "aud": cfg.Token.ExpectedAudiences, "exp": time.Now().Add(time.Minute).Unix(), "delegated_sub": "external-customer", "permissions": []string{"org:*"}}, map[string]any{"typ": jwtkit.DelegatedAccessTokenType})
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
	_, err := client.ensureRootGroup(ctx)
	require.NoError(t, err)
	srv, err := newTestService(client, workflowHTTPConfig())
	require.NoError(t, err)
	owner, token := newInstanceTestUser(t, srv, "phantomowner")
	for _, slug := range []string{"control-one", "control-two"} {
		w := postOrg(srv, token, `{"slug":"`+slug+`"}`)
		require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	}
	first := iam.GroupBySlug("org", "control-one")
	second := iam.GroupBySlug("org", "control-two")
	gid, err := client.ResolveGroupIDForSlug(ctx, first)
	require.NoError(t, err)
	other, err := client.ResolveGroupIDForSlug(ctx, second)
	require.NoError(t, err)
	app, err := client.UpsertRemoteApplication(ctx, iam.RemoteApplication{Slug: "wrong-control", PermissionGroupID: gid, Issuer: "https://wrong-control.test", JWKSURI: "https://wrong-control.test/jwks", Enabled: true})
	require.NoError(t, err)
	require.ErrorIs(t, assignRole(ctx, client, iam.OperatorActor(), second, iam.RemoteApplicationSubject(app.ID), "owner"), iam.ErrRemoteApplicationNotFound)
	// Simulate an old invalid assignment: it must not allow the real owner to
	// depart, although ordinary non-owner ancestor assignments remain valid.
	_, err = client.pg.Exec(ctx, `INSERT INTO group_remote_application_roles(permission_group_id,remote_application_id,role) VALUES($1,$2,'owner')`, other, app.ID)
	require.NoError(t, err)
	w := serveAuthJSON(srv, http.MethodDelete, "/org/control-two/members/"+owner, "", token)
	require.Equal(t, http.StatusConflict, w.Code, w.Body.String())
	requireErrorCode(t, w.Body.String(), string(iam.CodeCannotRemoveLastOwner))
}
