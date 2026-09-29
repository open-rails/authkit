package httpapi

import (
	"net/http"
	"strings"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/ident"
	"github.com/open-rails/authkit/internal/rbac"
)

// Group-management routes live under /groups/:group_id and are gated by a
// built-in permission of the addressed group's persona (`<persona>:members:
// manage`, ...). A route whose capability no persona enables is not mounted
// (404); a group whose persona lacks it is refused like an unknown group.

// GroupRoute is one group-management endpoint.
type GroupRoute struct {
	Method string
	Path   string // e.g. /groups/:group_id/members
	Op     GroupOp
}

// GroupOp is the operation a group route performs.
type GroupOp int

const (
	OpMembersList GroupOp = iota + 1
	OpMemberAdd
	OpMemberRemove
	OpMemberRoleAssign
	OpRolesList
	OpRoleDefine
	OpRoleDelete
	OpAPIKeysList
	OpAPIKeyMint
	OpAPIKeyRevoke
	OpRemoteAppsList
	OpRemoteAppRegister
	OpRemoteAppDelete
	OpRemoteAppRoleAssign
	OpInviteLinkList
	OpInviteLinkMint
	OpInviteLinkRevoke
)

// GroupRoutes is the whole group-management surface.
var GroupRoutes = []GroupRoute{
	{http.MethodGet, "/groups/:group_id/members", OpMembersList},
	{http.MethodPost, "/groups/:group_id/members", OpMemberAdd},
	{http.MethodDelete, "/groups/:group_id/members/:user", OpMemberRemove},
	{http.MethodPut, "/groups/:group_id/members/:user/roles/:role", OpMemberRoleAssign},
	{http.MethodGet, "/groups/:group_id/roles", OpRolesList},
	{http.MethodPost, "/groups/:group_id/roles", OpRoleDefine},
	{http.MethodDelete, "/groups/:group_id/roles/:role", OpRoleDelete},
	{http.MethodGet, "/groups/:group_id/api-keys", OpAPIKeysList},
	{http.MethodPost, "/groups/:group_id/api-keys", OpAPIKeyMint},
	{http.MethodDelete, "/groups/:group_id/api-keys/:key", OpAPIKeyRevoke},
	{http.MethodGet, "/groups/:group_id/remote-applications", OpRemoteAppsList},
	{http.MethodPost, "/groups/:group_id/remote-applications", OpRemoteAppRegister},
	{http.MethodDelete, "/groups/:group_id/remote-applications/:app", OpRemoteAppDelete},
	{http.MethodPut, "/groups/:group_id/remote-applications/:app/roles/:role", OpRemoteAppRoleAssign},
	{http.MethodGet, "/groups/:group_id/invites/links", OpInviteLinkList},
	{http.MethodPost, "/groups/:group_id/invites/links", OpInviteLinkMint},
	{http.MethodDelete, "/groups/:group_id/invites/links/:link", OpInviteLinkRevoke},
}

// Available reports whether groups of persona p have the operation. Root's
// members are managed through the admin routes.
func (op GroupOp) Available(p rbac.Persona) bool {
	switch op {
	case OpMembersList, OpMemberAdd, OpMemberRemove, OpMemberRoleAssign, OpInviteLinkList, OpInviteLinkMint, OpInviteLinkRevoke:
		return p.Name != iam.RootPersona
	case OpRolesList:
		return p.Name != iam.RootPersona || p.CustomRoles
	case OpRoleDefine, OpRoleDelete:
		return p.CustomRoles
	case OpAPIKeysList, OpAPIKeyMint, OpAPIKeyRevoke:
		return p.APIKeys
	case OpRemoteAppsList, OpRemoteAppRegister, OpRemoteAppDelete, OpRemoteAppRoleAssign:
		return p.RemoteApplications
	}
	return false
}

// Perms returns the permissions of persona p that admit the operation: any
// one of them suffices.
func (op GroupOp) Perms(p rbac.Persona) []iam.Perm {
	switch op {
	case OpMembersList, OpInviteLinkList:
		return []iam.Perm{iam.PermMembersRead(p.Name)}
	case OpRolesList:
		if p.CustomRoles {
			return []iam.Perm{iam.PermMembersRead(p.Name), iam.PermRolesManage(p.Name)}
		}
		return []iam.Perm{iam.PermMembersRead(p.Name)}
	case OpMemberAdd, OpMemberRemove, OpMemberRoleAssign, OpInviteLinkMint, OpInviteLinkRevoke:
		return []iam.Perm{iam.PermMembersManage(p.Name)}
	case OpRoleDefine, OpRoleDelete:
		return []iam.Perm{iam.PermRolesManage(p.Name)}
	case OpAPIKeysList, OpRemoteAppsList:
		return []iam.Perm{iam.PermCredentialsRead(p.Name)}
	case OpAPIKeyMint, OpAPIKeyRevoke, OpRemoteAppRegister, OpRemoteAppDelete, OpRemoteAppRoleAssign:
		return []iam.Perm{iam.PermCredentialsManage(p.Name)}
	}
	return nil
}

// catalogPermission names the gate in the route catalog, where no persona is
// known yet: `<persona>:members:manage`.
func (op GroupOp) catalogPermission() string {
	const placeholder = "persona"
	perm := op.Perms(rbac.Persona{Name: ident.Persona(placeholder)})[0].String()
	return "<persona>" + strings.TrimPrefix(perm, placeholder)
}

// MountedGroupRoutes returns the group routes some persona of s has.
func MountedGroupRoutes(s *rbac.Schema) []GroupRoute {
	var out []GroupRoute
	for _, gr := range GroupRoutes {
		for _, name := range s.Personas() {
			if p, _ := s.Persona(name); gr.Op.Available(p) {
				out = append(out, gr)
				break
			}
		}
	}
	return out
}
