package httpapi

import (
	"context"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/verify"
)

// apiKeysBackend is API-key issuance and resolution.
type apiKeysBackend interface {
	ListAPIKeys(ctx context.Context, group iam.GroupRef) ([]iam.APIKey, error)
	MintAPIKey(ctx context.Context, group iam.GroupRef, opts iam.APIKeyMintOptions) (iam.APIKey, string, error)
	verify.Enricher
	RevokeAPIKeyForActor(ctx context.Context, a iam.Actor, group iam.GroupRef, tokenID string) (bool, error)
}
