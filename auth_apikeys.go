package authkit

import (
	"context"

	"github.com/open-rails/authkit/iam"
)

// API keys: long-lived machine credentials owned by a permission group. A key
// holds one role of its group and dies with its creator's authority.

// MintAPIKey issues a key holding k.Role in ref. The actor needs
// <persona>:credentials:manage and must cover the role; only a user or the
// operator issues credentials (the operator's keys have no creator). The
// token is returned once.
func (a *Auth) MintAPIKey(ctx context.Context, actor iam.Actor, ref iam.GroupRef, k iam.NewAPIKey) (iam.APIKey, string, error) {
	return a.engine.MintAPIKey(ctx, actor, ref, k)
}

// APIKeys lists the group's keys, newest first, including revoked and expired ones.
func (a *Auth) APIKeys(ctx context.Context, ref iam.GroupRef, p iam.PageRequest) (iam.ListPage[iam.APIKey], error) {
	return a.engine.APIKeys(ctx, ref, p)
}

// RevokeAPIKey revokes the group's key id; it needs the authority to issue the
// key's role. False means no live key matched.
func (a *Auth) RevokeAPIKey(ctx context.Context, actor iam.Actor, ref iam.GroupRef, id string) (bool, error) {
	return a.engine.RevokeAPIKey(ctx, actor, ref, id)
}

// ResolveAPIKey authenticates a presented token: iam.ErrAPIKeyInvalid,
// iam.ErrAPIKeyRevoked (also when its creator is banned or deleted) or
// iam.ErrAPIKeyExpired. The verifier resolves API keys through it.
func (a *Auth) ResolveAPIKey(ctx context.Context, token string) (iam.APIKeyPrincipal, error) {
	return a.engine.ResolveAPIKey(ctx, token)
}
