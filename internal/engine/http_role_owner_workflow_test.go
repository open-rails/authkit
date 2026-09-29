package engine

import (
	"context"
	"net/http"
	"testing"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/stretchr/testify/require"
)

func TestRoleOwnerHTTPWorkflow(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	cfg := instanceCreateTestConfig()
	cfg.Roles.Roles = append(cfg.Roles.Roles, Role{Persona: "org", Name: "manager", Permissions: []string{"org:members:manage", "org:credentials:manage", "org:catalog:read"}})
	client := newServerClient(t, cfg, pg.Pool)
	ctx := context.Background()
	_, err := client.EnsureRootGroup(ctx)
	require.NoError(t, err)
	srv, err := newTestService(client, workflowHTTPConfig())
	require.NoError(t, err)
	owner, token := newInstanceTestUser(t, srv, "ownerflow")
	manager, managerToken := newInstanceTestUser(t, srv, "managerflow")
	peer, _ := newInstanceTestUser(t, srv, "peerflow")
	group := iam.GroupBySlug("org", "owner-flow")
	w := postOrg(srv, token, `{"slug":"owner-flow"}`)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	grantRole(t, client, group, iam.UserSubject(manager), "manager")
	assign := func(actor, id, role string) int {
		w := serveAuthJSON(srv, http.MethodPut, "/org/owner-flow/members/"+id+"/roles/"+role, "", actor)
		return w.Code
	}
	require.Equal(t, http.StatusForbidden, assign(managerToken, owner, "member"))
	require.Equal(t, http.StatusConflict, assign(token, owner, "member"))
	w = serveAuthJSON(srv, http.MethodPut, "/org/owner-flow/members/"+owner+"/roles/%20owner%20", "", token)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.Contains(t, w.Body.String(), `"role":"owner"`)
	w = serveAuthJSON(srv, http.MethodDelete, "/org/owner-flow/members/"+owner, "", token)
	require.Equal(t, http.StatusConflict, w.Code, w.Body.String())
	requireErrorCode(t, w.Body.String(), string(iam.CodeCannotRemoveLastOwner))
	gid, err := client.ResolveGroupIDForSlug(ctx, group)
	require.NoError(t, err)
	app, err := client.UpsertRemoteApplication(ctx, iam.RemoteApplication{Slug: "owner-app", PermissionGroupID: gid, Issuer: "https://owner-app.test", JWKSURI: "https://owner-app.test/jwks", Enabled: true})
	require.NoError(t, err)
	w = serveAuthJSON(srv, http.MethodPut, "/org/owner-flow/remote-applications/owner-app/roles/owner", "", token)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	w = serveAuthJSON(srv, http.MethodPut, "/org/owner-flow/remote-applications/owner-app/roles/member", "", managerToken)
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
	require.NoError(t, client.DeleteRemoteApplication(ctx, app.Issuer))
	require.Equal(t, http.StatusOK, assign(token, peer, "owner"))
	require.Equal(t, http.StatusOK, assign(token, peer, "member"))
	require.Equal(t, http.StatusOK, assign(token, peer, "owner"))
	w = serveAuthJSON(srv, http.MethodDelete, "/org/owner-flow/members/"+owner, "", token)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	allowed, err := client.Can(ctx, iam.UserSubject(peer), group, "org:members:manage")
	require.NoError(t, err)
	require.True(t, allowed)
}

func TestAdminRootRoleHTTPWorkflow(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	cfg := instanceCreateTestConfig()
	cfg.Roles.Roles = append(cfg.Roles.Roles, Role{Persona: iam.RootPersona, Name: "admin", Permissions: []string{"root:members:*", iam.PermRootUsersRead}})
	cfg.Roles.Personas["root"] = Persona{APIKeys: true}
	client := newServerClient(t, cfg, pg.Pool)
	srv, err := newTestService(client, workflowHTTPConfig())
	require.NoError(t, err)
	owner, ownerToken := newInstanceTestUser(t, srv, "rootowner")
	admin, adminToken := newInstanceTestUser(t, srv, "rootadmin")
	target, targetToken := newInstanceTestUser(t, srv, "roottarget")
	seedRole(t, client, iam.RootGroup(), iam.UserSubject(owner), iam.OwnerRole)
	grantRole(t, client, iam.RootGroup(), iam.UserSubject(admin), "admin")
	call := func(method, user, role, token string, status int) {
		t.Helper()
		w := serveAuthJSON(srv, method, "/admin/users/"+user+"/roles/"+role, "", token)
		require.Equal(t, status, w.Code, w.Body.String())
	}
	rootRole := func(user string) iam.Role {
		t.Helper()
		roles, err := client.GroupRoles(t.Context(), iam.RootGroup(), []iam.Subject{iam.UserSubject(user)})
		require.NoError(t, err)
		return roles[iam.UserSubject(user)]
	}

	// A bounded admin promotes to roles it covers, never to or over an owner.
	call(http.MethodPut, target, "site-admin", adminToken, http.StatusNoContent)
	require.Equal(t, iam.Role("site-admin"), rootRole(target))
	call(http.MethodPut, target, "owner", adminToken, http.StatusForbidden)
	call(http.MethodPut, owner, "site-admin", adminToken, http.StatusForbidden)
	call(http.MethodPut, admin, "site-admin", targetToken, http.StatusForbidden)
	call(http.MethodPut, target, "no-such-role", ownerToken, http.StatusBadRequest)
	call(http.MethodPut, target, "site-admin", "", http.StatusUnauthorized)
	call(http.MethodDelete, target, "site-admin", adminToken, http.StatusNoContent)
	require.Empty(t, rootRole(target))
	call(http.MethodDelete, owner, "owner", ownerToken, http.StatusConflict)

	// Machine and delegated actors never reach the management plane, even
	// with the authority to act.
	_, keyToken, err := client.MintAPIKey(t.Context(), iam.RootGroup(), iam.APIKeyMintOptions{Name: "root-admin-key", Role: "admin", CreatedBy: owner})
	require.NoError(t, err)
	delegated, err := client.MintDelegatedAccessToken(t.Context(), iam.DelegatedAccessParams{Audiences: []string{"test-app"}, DelegatedSubject: admin, Permissions: []string{"root:members:*", iam.PermRootUsersRead}})
	require.NoError(t, err)
	for _, token := range []string{keyToken, delegated} {
		w := serveAuthJSON(srv, http.MethodPut, "/admin/users/"+target+"/roles/site-admin", "", token)
		require.Contains(t, []int{http.StatusUnauthorized, http.StatusForbidden}, w.Code, w.Body.String())
	}
	require.Empty(t, rootRole(target))

	w := serveAuthJSON(srv, http.MethodGet, "/admin/roles", "", adminToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.Contains(t, w.Body.String(), `"site-admin"`)
	require.Contains(t, w.Body.String(), `"owner"`)
	require.Equal(t, http.StatusForbidden, serveAuthJSON(srv, http.MethodGet, "/admin/roles", "", targetToken).Code)
}
