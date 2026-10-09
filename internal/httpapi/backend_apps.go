package httpapi

import (
	"context"
	"time"
)

// appsBackend is DPoP replay protection.
type appsBackend interface {
	ClaimDPoPProof(ctx context.Context, key string, ttl time.Duration) (bool, error)
}
