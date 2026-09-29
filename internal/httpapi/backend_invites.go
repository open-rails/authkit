package httpapi

import (
	"context"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/verify"
)

// invitesBackend is group and account invitations.
type invitesBackend interface {
	CreateGroupInviteLink(ctx context.Context, req iam.CreateGroupInviteLinkRequest) (iam.GroupInviteLinkCreated, error)
	ListGroupInviteLinks(ctx context.Context, group iam.GroupRef) ([]iam.GroupInviteLink, error)
	RevokeGroupInviteLinkFromClaims(ctx context.Context, claims verify.Claims, group iam.GroupRef, linkID string) error
	CreateAccountRegistrationInvite(ctx context.Context, req authflow.CreateAccountRegistrationInviteRequest) (authflow.AccountRegistrationInviteCreated, error)
	RedeemGroupInviteLink(ctx context.Context, code, redeemerUserID string) (authflow.RedeemGroupInviteLinkResult, error)
}
