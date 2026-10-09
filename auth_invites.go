package authkit

import (
	"context"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/helpers/auth"
)

// Invitations into a group: single-use links, and invitations emailed to an
// address that let it register. Each dies with its creator's authority.

// CreateInvitation creates an invite link (n.Email empty) that grants n.Role
// to the signed-in account redeeming it, or emails an invitation to n.Email.
// A link, and an email invitation carrying a role, need the group's
// <persona>:members:manage and coverage of the role; a plain email invitation
// (no role) is created in iam.RootGroup() and needs root:users:invite. Only a
// user or the system issues credentials. The code is returned once.
func (a *Client) CreateInvitation(ctx context.Context, who auth.Identity, ref iam.GroupRef, n iam.NewInvitation, opts ...Option) (iam.InvitationCreated, error) {
	return a.ops.CreateInvitation(ctx, who, ref, n, opts...)
}

// ListInvitations lists the group's invitations, newest first, active or not
// (never their codes). Root's include the plain email invitations.
func (a *Client) ListInvitations(ctx context.Context, ref iam.GroupRef, p iam.PageRequest) (iam.ListPage[iam.Invitation], error) {
	return a.ops.ListInvitations(ctx, ref, p)
}

// RevokeInvitation revokes the group's invitation id; it needs the authority
// to issue it. Revoking a revoked or redeemed invitation is a no-op; an id
// unknown in the group is iam.ErrInvitationNotFound.
func (a *Client) RevokeInvitation(ctx context.Context, who auth.Identity, ref iam.GroupRef, id string, opts ...Option) error {
	return a.ops.RevokeInvitation(ctx, who, ref, id, opts...)
}
