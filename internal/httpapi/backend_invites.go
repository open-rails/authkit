package httpapi

import (
	"context"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/authflow"
)

// invitesBackend is group and account invitations.
type invitesBackend interface {
	CreateInviteLink(ctx context.Context, a iam.Actor, ref iam.GroupRef, l iam.NewInviteLink) (iam.InviteLinkCreated, error)
	InviteLinks(ctx context.Context, ref iam.GroupRef, p iam.PageRequest) (iam.ListPage[iam.InviteLink], error)
	RevokeInviteLink(ctx context.Context, a iam.Actor, ref iam.GroupRef, linkID string) error
	CreateAccountInvite(ctx context.Context, a iam.Actor, i iam.NewAccountInvite) (iam.AccountInviteCreated, error)
	RedeemInviteLink(ctx context.Context, a iam.Actor, code string) (authflow.InviteRedemption, error)
}
