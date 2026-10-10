package engine

import (
	"context"
	"errors"

	"github.com/open-rails/authkit/internal/ratelimit"
	pglimiter "github.com/open-rails/authkit/internal/ratelimit/postgres"
)

// RateLimiter is the limiter every replica shares, in PostgreSQL
// (rate_limits). It runs on the ephemeral pool: each decision is one
// statement outside any transaction.
func (s *Engine) RateLimiter(limits map[string]ratelimit.Limit) (ratelimit.Limiter, error) {
	if !s.useEphemeralStore() {
		return nil, errors.New("authkit: rate limits need Deps.Postgres")
	}
	return pglimiter.New(s.ephemeral.q, limits)
}

// purgeExpiredRateLimits deletes dead budgets in bounded batches.
func (s *Engine) purgeExpiredRateLimits(ctx context.Context) (int64, error) {
	var total int64
	for {
		n, err := s.q.RateLimitsDeleteExpired(ctx, ephemeralSweepBatch)
		total += n
		if err != nil || n < ephemeralSweepBatch {
			return total, err
		}
	}
}
