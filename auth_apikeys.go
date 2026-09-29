package authkit

import (
	"context"

	"github.com/open-rails/authkit/iam"
)

// API keys: long-lived machine credentials owned by a permission group.

func (a *Auth) MintAPIKey(ctx context.Context, group iam.GroupRef, opts iam.APIKeyMintOptions) (iam.APIKey, string, error) {
	return a.engine.MintAPIKey(ctx, group, opts)
}

func (a *Auth) ListAPIKeys(ctx context.Context, group iam.GroupRef) ([]iam.APIKey, error) {
	return a.engine.ListAPIKeys(ctx, group)
}

func (a *Auth) RevokeAPIKey(ctx context.Context, group iam.GroupRef, tokenID string) (bool, error) {
	return a.engine.RevokeAPIKey(ctx, group, tokenID)
}

func (a *Auth) ResolveAPIKey(ctx context.Context, keyID string, secret string) (string, []string, error) {
	return a.engine.ResolveAPIKey(ctx, keyID, secret)
}
