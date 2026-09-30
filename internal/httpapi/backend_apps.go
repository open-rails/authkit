package httpapi

import (
	"context"
	"time"

	"github.com/open-rails/authkit/iam"
)

// appsBackend is delegation and DPoP.
type appsBackend interface {
	ClaimDPoPProof(ctx context.Context, key string, ttl time.Duration) (bool, error)
	DelegationAuthorizer() iam.DelegationAuthorizer
}
