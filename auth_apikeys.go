package authkit

import (
	"context"

	"github.com/open-rails/authkit/iam"
)

// API keys: long-lived machine credentials owned by a permission group. A key
// holds one role of its group and dies with its creator's authority.

// CreateAPIKey issues a key holding k.Role in ref. The actor needs
// <persona>:credentials:manage and must cover the role; only a user or the
// system issues credentials (the system's keys have no creator). The secret
// is returned once.
func (a *Client) CreateAPIKey(ctx context.Context, actor iam.Actor, ref iam.GroupRef, k iam.NewAPIKey, opts ...Option) (iam.APIKeyCreated, error) {
	return a.ops.CreateAPIKey(ctx, actor, ref, k, opts...)
}

// ListAPIKeys lists the group's keys, newest first, including revoked and
// expired ones.
func (a *Client) ListAPIKeys(ctx context.Context, ref iam.GroupRef, p iam.PageRequest) (iam.ListPage[iam.APIKey], error) {
	return a.ops.ListAPIKeys(ctx, ref, p)
}

// RevokeAPIKey revokes the group's key id; it needs the authority to issue
// the key's role. Revoking a revoked key is a no-op; an id unknown in the
// group is iam.ErrAPIKeyNotFound.
func (a *Client) RevokeAPIKey(ctx context.Context, actor iam.Actor, ref iam.GroupRef, id string, opts ...Option) error {
	return a.ops.RevokeAPIKey(ctx, actor, ref, id, opts...)
}

// ResolveAPIKey authenticates a presented token: iam.ErrAPIKeyInvalid,
// iam.ErrAPIKeyRevoked (also when its creator is banned or deleted) or
// iam.ErrAPIKeyExpired. The verifier resolves API keys through it.
func (a *Client) ResolveAPIKey(ctx context.Context, token string) (iam.APIKeyPrincipal, error) {
	return a.ops.ResolveAPIKey(ctx, token)
}
