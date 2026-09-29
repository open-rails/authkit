package authkit

import (
	"context"

	"github.com/open-rails/authkit/iam"
)

// Invitations: single-use invite links into a group, and registration invites.
// Each dies with its creator's authority.

// CreateInviteLink mints a single-use link granting l.Role in ref. The actor
// needs <persona>:members:manage and must cover the role; only a user or the
// system issues credentials. The code is returned once.
func (a *Auth) CreateInviteLink(ctx context.Context, actor iam.Actor, ref iam.GroupRef, l iam.NewInviteLink) (iam.InviteLinkCreated, error) {
	return a.engine.CreateInviteLink(ctx, actor, ref, l)
}

// InviteLinks lists the group's links, newest first (never their codes).
func (a *Auth) InviteLinks(ctx context.Context, ref iam.GroupRef, p iam.PageRequest) (iam.ListPage[iam.InviteLink], error) {
	return a.engine.InviteLinks(ctx, ref, p)
}

// RevokeInviteLink revokes the group's link; it needs the authority to issue
// the link's role. iam.ErrInviteLinkNotFound when no live link matched.
func (a *Auth) RevokeInviteLink(ctx context.Context, actor iam.Actor, ref iam.GroupRef, linkID string) error {
	return a.engine.RevokeInviteLink(ctx, actor, ref, linkID)
}

// CreateAccountInvite invites i.Email to register and emails the link. A plain
// invite needs root:users:invite; with i.Group and i.Role, registering also
// grants the role, and the invite needs that group's members:manage and
// coverage of the role instead.
func (a *Auth) CreateAccountInvite(ctx context.Context, actor iam.Actor, i iam.NewAccountInvite) (iam.AccountInviteCreated, error) {
	return a.engine.CreateAccountInvite(ctx, actor, i)
}
