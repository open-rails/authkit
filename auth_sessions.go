package authkit

import (
	"context"
	"time"

	"github.com/open-rails/authkit/iam"
)

// Sessions and access tokens.

// AdminRevokeAccountSessions revokes the user's refresh sessions on every
// account issuer plus device keys. Unchecked: the host authorizes the actor.
func (a *Auth) AdminRevokeAccountSessions(ctx context.Context, userID string) (iam.AccountSessionRevocation, error) {
	return a.engine.AdminRevokeAccountSessions(ctx, userID)
}

func (a *Auth) MintAccessToken(ctx context.Context, userID string, extra map[string]any) (string, time.Time, error) {
	return a.engine.MintAccessToken(ctx, userID, extra)
}
