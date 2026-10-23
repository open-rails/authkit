package authkit

import (
	"context"

	"github.com/open-rails/authkit/auth"
	"github.com/open-rails/authkit/iam"
)

// API keys: long-lived machine credentials owned by a permission group. A key
// holds one role of its group. Its creator is audit metadata, not its owner.

// CreateAPIKey issues a key holding k.Role in ref. The identity needs
// <persona>:credentials:manage and must cover the role; only a user or the
// system issues credentials (the system's keys have no creator). The secret
// is returned once.
func (a *Client) CreateAPIKey(ctx context.Context, who auth.Identity, ref iam.GroupRef, k iam.NewAPIKey, opts ...Option) (iam.APIKeyCreated, error) {
	return a.ops.CreateAPIKey(a.operationContext(ctx), who, ref, k, opts...)
}

// ListAPIKeys lists the group's keys, newest first, including revoked and
// expired ones.
func (a *Client) ListAPIKeys(ctx context.Context, ref iam.GroupRef, p iam.PageRequest) (iam.ListPage[iam.APIKey], error) {
	return a.ops.ListAPIKeys(a.operationContext(ctx), ref, p)
}

// RevokeAPIKey revokes the group's key id; it needs the authority to issue
// the key's role. Revoking a revoked key is a no-op; an id unknown in the
// group is iam.ErrAPIKeyNotFound.
func (a *Client) RevokeAPIKey(ctx context.Context, who auth.Identity, ref iam.GroupRef, id string, opts ...Option) error {
	return a.ops.RevokeAPIKey(a.operationContext(ctx), who, ref, id, opts...)
}

// ResolveAPIKey authenticates a presented token: iam.ErrAPIKeyInvalid,
// iam.ErrAPIKeyRevoked or
// iam.ErrAPIKeyExpired. The verifier resolves API keys through it.
func (a *Client) ResolveAPIKey(ctx context.Context, token string) (iam.ResolvedAPIKey, error) {
	return a.ops.ResolveAPIKey(a.operationContext(ctx), token)
}
