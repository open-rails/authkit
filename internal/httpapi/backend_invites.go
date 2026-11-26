package httpapi

import (
	"context"

	"github.com/open-rails/authkit/auth"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/authflow"
)

// invitesBackend is redeeming an invitation as the signed-in account, and
// spending a setup link on the owner account.
type invitesBackend interface {
	RedeemInvitation(ctx context.Context, a auth.Identity, code string) (authflow.InviteRedemption, error)
	CompleteSetup(ctx context.Context, code string, n iam.NewUser) (iam.User, error)
}
