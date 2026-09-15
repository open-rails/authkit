package authhttp

import (
	"context"
	"net/http"
	"testing"

	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/embedded"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/stretchr/testify/require"
)

func TestRoleOwnerHTTPWorkflow(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	cfg := instanceCreateTestConfig()
	cfg.RBAC[1].Roles = append(cfg.RBAC[1].Roles, embedded.RoleDef{Name: "manager", Permissions: []string{"org:members:manage", "org:catalog:read"}})
	client := newServerClient(t, cfg, pg.Pool)
	ctx := context.Background()
	require.NoError(t, client.SeedPermissionGroupContainment(ctx))
	_, err := client.EnsureRootGroup(ctx)
	require.NoError(t, err)
	srv, err := newServer(client, WithoutRateLimiter())
	require.NoError(t, err)
	owner, token := newInstanceTestUser(t, srv, "ownerflow")
	manager, managerToken := newInstanceTestUser(t, srv, "managerflow")
	peer, _ := newInstanceTestUser(t, srv, "peerflow")
	group := authkit.GroupRef{Persona: "org", Instance: "owner-flow"}
	w := postOrg(srv, token, `{"slug":"owner-flow"}`)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	require.NoError(t, client.Genesis().AssignGroupRole(ctx, group, authkit.UserSubject(manager), "manager"))
	assign := func(actor, id, role string) int {
		w := serveAuthJSON(srv, http.MethodPut, "/org/owner-flow/members/"+id+"/roles/"+role, "", actor)
		return w.Code
	}
	require.Equal(t, http.StatusForbidden, assign(managerToken, owner, "member"))
	require.Equal(t, http.StatusConflict, assign(token, owner, "member"))
	w = serveAuthJSON(srv, http.MethodDelete, "/org/owner-flow/members/"+owner, "", token)
	require.Equal(t, http.StatusConflict, w.Code, w.Body.String())
	requireErrorCode(t, w.Body.String(), string(authkit.CodeCannotRemoveLastOwner))
	require.Equal(t, http.StatusOK, assign(token, peer, "owner"))
	require.Equal(t, http.StatusOK, assign(token, peer, "member"))
	require.Equal(t, http.StatusOK, assign(token, peer, "owner"))
	w = serveAuthJSON(srv, http.MethodDelete, "/org/owner-flow/members/"+owner, "", token)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	allowed, err := client.Can(ctx, authkit.UserSubject(peer), group, "org:members:manage")
	require.NoError(t, err)
	require.True(t, allowed)
}
