package httpapi

import (
	"strings"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/ident"
	"github.com/open-rails/authkit/internal/rbac"
)

// Group-management routes live under /groups/{group_id} and are gated by a
// built-in permission of the addressed group's persona (`<persona>:members:
// manage`, ...). A route whose capability no persona enables is not mounted
// (404); a group whose persona lacks it is refused like an unknown group.

// GroupOp is the operation a group route performs.
type GroupOp int

const (
	OpMembersList GroupOp = iota + 1
	OpMemberSet
	OpMemberRemove
	OpRolesList
	OpAPIKeysList
	OpAPIKeyMint
	OpAPIKeyRevoke
	OpInvitationsList
	OpInvitationCreate
	OpInvitationRevoke
)

// Available reports whether groups of persona p have the operation. Every
// group, root included, has members, roles and invitations.
func (op GroupOp) Available(p rbac.Persona) bool {
	switch op {
	case OpMembersList, OpMemberSet, OpMemberRemove, OpRolesList, OpInvitationsList, OpInvitationCreate, OpInvitationRevoke:
		return true
	case OpAPIKeysList, OpAPIKeyMint, OpAPIKeyRevoke:
		return p.APIKeys
	}
	return false
}

// Mutates reports whether the operation changes the group.
func (op GroupOp) Mutates() bool {
	switch op {
	case OpMemberSet, OpMemberRemove, OpAPIKeyMint, OpAPIKeyRevoke, OpInvitationCreate, OpInvitationRevoke:
		return true
	}
	return false
}

// Perms returns the permissions of persona p that admit the operation: any
// one of them suffices. A root invitation without a role invites someone to
// register (root:users:invite); the engine tells the two apart.
func (op GroupOp) Perms(p rbac.Persona) []iam.Perm {
	switch op {
	case OpMembersList, OpRolesList, OpInvitationsList:
		return []iam.Perm{ident.MembersRead(p.Name)}
	case OpMemberSet, OpMemberRemove, OpInvitationRevoke:
		return []iam.Perm{ident.MembersManage(p.Name)}
	case OpInvitationCreate:
		if p.Name == iam.RootPersona {
			return []iam.Perm{ident.MembersManage(p.Name), ident.RootUsersInvite}
		}
		return []iam.Perm{ident.MembersManage(p.Name)}
	case OpAPIKeysList:
		return []iam.Perm{ident.CredentialsRead(p.Name)}
	case OpAPIKeyMint, OpAPIKeyRevoke:
		return []iam.Perm{ident.CredentialsManage(p.Name)}
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
