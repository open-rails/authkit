package httpapi

import (
	"context"

	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/helpers/auth"
)

// invitesBackend is redeeming an invitation as the signed-in account.
type invitesBackend interface {
	RedeemInvitation(ctx context.Context, a auth.Identity, code string) (authflow.InviteRedemption, error)
}
