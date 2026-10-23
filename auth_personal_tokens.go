package authkit

import (
	"context"

	"github.com/open-rails/authkit/auth"
	"github.com/open-rails/authkit/iam"
)

// Personal tokens are optional, self-managed credentials. Creation and
// revocation require the user's current interactive sign-in and recent proof.
func (a *Client) CreatePersonalAccessToken(ctx context.Context, who auth.Identity, in iam.NewPersonalAccessToken, opts ...Option) (iam.PersonalAccessTokenCreated, error) {
	return a.ops.CreatePersonalAccessToken(a.operationContext(ctx), who, in, opts...)
}

func (a *Client) ListPersonalAccessTokens(ctx context.Context, who auth.Identity, page iam.PageRequest) (iam.ListPage[iam.PersonalAccessToken], error) {
	return a.ops.ListPersonalAccessTokens(a.operationContext(ctx), who, page)
}

func (a *Client) RevokePersonalAccessToken(ctx context.Context, who auth.Identity, id string, opts ...Option) error {
	return a.ops.RevokePersonalAccessToken(a.operationContext(ctx), who, id, opts...)
}

func (a *Client) ResolvePersonalAccessToken(ctx context.Context, token string) (iam.ResolvedPersonalAccessToken, error) {
	return a.ops.ResolvePersonalAccessToken(a.operationContext(ctx), token)
}
