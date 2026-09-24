package securitytest

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"testing"

	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/embedded"
	"github.com/stretchr/testify/require"
)

const orgPersona authkit.Persona = "org"

func withRBAC(c *embedded.Config) {
	c.RBAC = []embedded.PersonaDef{
		embedded.IntrinsicRootPersona(
			embedded.RoleDef{Name: "moderator", Permissions: []string{embedded.PermRootUsersBan, embedded.PermRootResourcesRead}},
			embedded.RoleDef{Name: "admin", Permissions: embedded.IntrinsicRootPermissions()},
		),
		{
			Name:         orgPersona,
			Parent:       authkit.RootPersona,
			Capabilities: embedded.PersonaCapabilities{RemoteApplications: true, APIKeys: true, CustomRoles: true},
			Roles: []embedded.RoleDef{
				{Name: "member", Permissions: []string{"org:catalog:read"}},
				{Name: "manager", Permissions: []string{"org:members:manage", "org:members:read", "org:credentials:manage", "org:credentials:read", "org:roles:manage", "org:roles:read", "org:catalog:read"}},
			},
		},
	}
}

func (h *host) grant(group authkit.GroupRef, a account, role authkit.Role) {
	h.t.Helper()
	require.NoError(h.t, h.client.OperatorAssignGroupRole(context.Background(), group, authkit.UserSubject(a.id), role))
}

func publicKeyPEM(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

// TestSecurityUnbanRequiresAuthority: lifting a ban restores authority, so it
// needs the same no-escalation check as imposing one, and never applies to the
// actor's own account.
func TestSecurityUnbanRequiresAuthority(t *testing.T) {
	h := newHost(t, withHTTP(generousLimits), withEngine(withRBAC))
	ctx := context.Background()
	root := authkit.RootGroup()
	owner, admin := h.newAccount("owner"), h.newAccount("admin")
	moderator, peer := h.newAccount("moderator"), h.newAccount("peermod")
	h.grant(root, owner, authkit.OwnerRole)
	h.grant(root, admin, "admin")
	h.grant(root, moderator, "moderator")
	h.grant(root, peer, "moderator")
	ownerToken := h.login(owner).AccessToken
	moderatorToken := h.login(moderator).AccessToken
	peerToken := h.login(peer).AccessToken
	unban := func(target account, token string) response {
		return h.post("/admin/users/"+target.id+"/unban", nil, token)
	}
	require.NoError(t, h.client.BanUser(ctx, moderator.id, nil, nil, owner.id))
	require.NoError(t, h.client.BanUser(ctx, admin.id, nil, nil, owner.id))

	for _, tc := range []struct {
		name   string
		target account
		token  string
	}{
		{"banned moderator lifts own ban with a pre-ban token", moderator, moderatorToken},
		{"moderator lifts the ban of a more privileged admin", admin, peerToken},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := unban(tc.target, tc.token)
			require.Equal(t, http.StatusForbidden, resp.status, resp.String())
			u, err := h.client.AdminGetUser(ctx, tc.target.id)
			require.NoError(t, err)
			require.NotNil(t, u.BannedAt, "ban was lifted")
		})
	}
	t.Run("control: owner lifts both bans", func(t *testing.T) {
		require.Equal(t, http.StatusNoContent, unban(moderator, ownerToken).status)
		require.Equal(t, http.StatusNoContent, unban(admin, ownerToken).status)
		h.login(moderator)
	})
}

// TestSecurityRemoteApplicationTakeover: an application's keys are its
// authority. A bounded credentials manager must not swap the keys of, disable
// or delete an application holding a role above their own.
func TestSecurityRemoteApplicationTakeover(t *testing.T) {
	h := newHost(t, withHTTP(generousLimits), withEngine(withRBAC))
	ctx := context.Background()
	owner, manager := h.newAccount("orgowner"), h.newAccount("orgmanager")
	group := authkit.GroupRef{Persona: orgPersona, Instance: unique("org")}
	_, err := h.client.CreatePermissionGroup(ctx, authkit.CreatePermissionGroupRequest{
		Persona: orgPersona, InstanceSlug: group.Instance, ParentPersona: authkit.RootPersona, OwnerSubjectID: owner.id,
	})
	require.NoError(t, err)
	h.grant(group, manager, "manager")
	ownerToken, managerToken := h.login(owner).AccessToken, h.login(manager).AccessToken
	base := "/" + string(orgPersona) + "/" + group.Instance + "/remote-applications"
	register := func(token, slug, issuer, key string, enabled bool) response {
		return h.post(base, map[string]any{"slug": slug, "issuer": issuer, "public_keys": []map[string]string{{"public_key_pem": key}}, "enabled": enabled}, token)
	}
	ownedKey := publicKeyPEM(t)
	resp := register(ownerToken, "owner-app", "https://owner-app.security.test", ownedKey, true)
	require.Equal(t, http.StatusCreated, resp.status, resp.String())
	resp = h.do(request{method: http.MethodPut, path: base + "/owner-app/roles/owner", token: ownerToken})
	require.Equal(t, http.StatusOK, resp.status, resp.String())

	for _, tc := range []struct {
		name   string
		attack func() response
	}{
		{"swap the owner application's keys", func() response {
			return register(managerToken, "owner-app", "https://owner-app.security.test", publicKeyPEM(t), true)
		}},
		{"disable the owner application", func() response {
			return register(managerToken, "owner-app", "https://owner-app.security.test", ownedKey, false)
		}},
		{"delete the owner application", func() response {
			return h.do(request{method: http.MethodDelete, path: base + "/owner-app", token: managerToken})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := tc.attack()
			require.Equal(t, http.StatusForbidden, resp.status, resp.String())
			app, err := h.client.GetRemoteApplication(ctx, "https://owner-app.security.test")
			require.NoError(t, err)
			require.True(t, app.Enabled)
			require.Len(t, app.PublicKeys, 1)
			require.Equal(t, ownedKey, app.PublicKeys[0].PublicKeyPEM)
		})
	}
	t.Run("control: manager operates an application within their authority", func(t *testing.T) {
		resp := register(managerToken, "member-app", "https://member-app.security.test", publicKeyPEM(t), true)
		require.Equal(t, http.StatusCreated, resp.status, resp.String())
		resp = register(managerToken, "member-app", "https://member-app.security.test", publicKeyPEM(t), true)
		require.Equal(t, http.StatusCreated, resp.status, resp.String())
		resp = h.do(request{method: http.MethodDelete, path: base + "/member-app", token: managerToken})
		require.Equal(t, http.StatusOK, resp.status, resp.String())
	})
	t.Run("control: owner rotates the owner application's keys", func(t *testing.T) {
		resp := register(ownerToken, "owner-app", "https://owner-app.security.test", publicKeyPEM(t), true)
		require.Equal(t, http.StatusCreated, resp.status, resp.String())
	})
}

// TestSecurityRoleEscalation keeps the no-escalation rules for direct grants,
// custom roles, invite links and API keys under the embedded HTTP surface.
func TestSecurityRoleEscalation(t *testing.T) {
	h := newHost(t, withHTTP(generousLimits), withEngine(withRBAC))
	ctx := context.Background()
	owner, manager, member := h.newAccount("escowner"), h.newAccount("escmanager"), h.newAccount("escmember")
	group := authkit.GroupRef{Persona: orgPersona, Instance: unique("esc")}
	_, err := h.client.CreatePermissionGroup(ctx, authkit.CreatePermissionGroupRequest{
		Persona: orgPersona, InstanceSlug: group.Instance, ParentPersona: authkit.RootPersona, OwnerSubjectID: owner.id,
	})
	require.NoError(t, err)
	other := authkit.GroupRef{Persona: orgPersona, Instance: unique("other")}
	_, err = h.client.CreatePermissionGroup(ctx, authkit.CreatePermissionGroupRequest{
		Persona: orgPersona, InstanceSlug: other.Instance, ParentPersona: authkit.RootPersona, OwnerSubjectID: owner.id,
	})
	require.NoError(t, err)
	h.grant(group, manager, "manager")
	h.grant(group, member, "member")
	managerToken := h.login(manager).AccessToken
	memberToken := h.login(member).AccessToken
	base := "/" + string(orgPersona) + "/" + group.Instance

	for _, tc := range []struct {
		name  string
		req   request
		allow bool
	}{
		{"manager grants themself owner", request{method: http.MethodPut, path: base + "/members/" + manager.id + "/roles/owner", token: managerToken}, false},
		{"manager grants a member owner", request{method: http.MethodPut, path: base + "/members/" + member.id + "/roles/owner", token: managerToken}, false},
		{"manager demotes the owner", request{method: http.MethodPut, path: base + "/members/" + owner.id + "/roles/member", token: managerToken}, false},
		{"manager removes the owner", request{method: http.MethodDelete, path: base + "/members/" + owner.id, token: managerToken}, false},
		{"manager defines a custom role wider than their own", request{method: http.MethodPost, path: base + "/roles", token: managerToken,
			body: map[string]any{"role": "superuser", "permissions": []string{"org:*"}}}, false},
		{"manager defines a custom role with root permissions", request{method: http.MethodPost, path: base + "/roles", token: managerToken,
			body: map[string]any{"role": "rooted", "permissions": []string{"root:users:ban"}}}, false},
		{"manager mints an owner invite link", request{method: http.MethodPost, path: base + "/invites/links", token: managerToken,
			body: map[string]any{"role": "owner"}}, false},
		{"manager mints an owner API key", request{method: http.MethodPost, path: base + "/api-keys", token: managerToken,
			body: map[string]any{"name": "k", "role": "owner"}}, false},
		{"member grants themself manager", request{method: http.MethodPut, path: base + "/members/" + member.id + "/roles/manager", token: memberToken}, false},
		{"manager acts on a group they do not belong to", request{method: http.MethodPut, path: "/" + string(orgPersona) + "/" + other.Instance + "/members/" + member.id + "/roles/member", token: managerToken}, false},
		{"root admin surface with a group role", request{method: http.MethodGet, path: "/admin/users", token: managerToken}, false},
		{"control: manager assigns member", request{method: http.MethodPut, path: base + "/members/" + member.id + "/roles/member", token: managerToken}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := h.do(tc.req)
			if tc.allow {
				require.Less(t, resp.status, 300, resp.String())
				return
			}
			require.Contains(t, []int{http.StatusBadRequest, http.StatusForbidden, http.StatusNotFound, http.StatusConflict, http.StatusUnprocessableEntity}, resp.status, resp.String())
		})
	}
	ownerAllowed, err := h.client.Can(ctx, authkit.UserSubject(manager.id), group, "org:*")
	require.NoError(t, err)
	require.False(t, ownerAllowed)
	stillOwner, err := h.client.Can(ctx, authkit.UserSubject(owner.id), group, "org:members:manage")
	require.NoError(t, err)
	require.True(t, stillOwner)
}
