// Package pglimiter is the sliding-window rate limiter over ratelimit.Limit
// buckets in PostgreSQL (rate_limits), shared by every replica: AuthKit's
// limiter of record, and the Redis limiter's while Redis fails.
package pglimiter

import (
	"context"
	"errors"
	"log/slog"
	"maps"
	"sync/atomic"
	"time"

	"github.com/open-rails/authkit/internal/db"
	"github.com/open-rails/authkit/internal/ratelimit"
	"github.com/open-rails/authkit/internal/secret"
)

// Limiter spends budgets in rate_limits, one row per bucket and key.
type Limiter struct {
	q      *db.Queries
	limits map[string]ratelimit.Limit
	down   atomic.Bool
}

// New is the limiter over q, which resolves AuthKit's schema.
func New(q *db.Queries, limits map[string]ratelimit.Limit) (*Limiter, error) {
	if q == nil {
		return nil, errors.New("ratelimit: PostgreSQL queries required")
	}
	if err := ratelimit.ValidateLimits(limits); err != nil {
		return nil, err
	}
	return &Limiter{q: q, limits: maps.Clone(limits)}, nil
}

// Allow decides in one statement on the database clock. The row is keyed by
// a digest of key, so no address or identifier is stored.
func (l *Limiter) Allow(ctx context.Context, bucket, key string) (ratelimit.Result, error) {
	lim, _ := ratelimit.LookupLimit(l.limits, bucket)
	windowMs, cooldownMs := lim.Window.Milliseconds(), lim.Cooldown.Milliseconds()
	row, err := l.q.RateLimitSpend(ctx, db.RateLimitSpendParams{
		Key:        bucket + ":" + secret.Hash(key),
		WindowMs:   windowMs,
		MaxHits:    int64(lim.Limit),
		CooldownMs: cooldownMs,
	})
	if err == nil && row.NowMs == nil {
		err = errors.New("ratelimit: no database clock")
	}
	if err != nil {
		if ctx.Err() == nil && !l.down.Swap(true) {
			slog.Error("authkit: PostgreSQL rate limiting failed; limited requests are refused until it recovers", "error", err)
		}
		return ratelimit.Result{}, err
	}
	if l.down.Swap(false) {
		slog.Info("authkit: PostgreSQL rate limiting recovered")
	}
	now := *row.NowMs
	live := 0
	for _, at := range row.Before {
		if at > now-windowMs {
			live++
		}
	}
	res := ratelimit.Result{Limit: lim.Limit, Window: lim.Window, Cooldown: lim.Cooldown}
	if len(row.After) > live {
		res.Allowed = true
		res.Remaining = ratelimit.Remaining(lim.Limit, int64(len(row.After)))
		return res, nil
	}
	// Refused: after holds the live hits, oldest first.
	hits := row.After
	res.Remaining = ratelimit.Remaining(lim.Limit, int64(len(hits)))
	var retryMs int64
	res.Reason = ratelimit.ReasonLimitExceeded
	if cooldownMs > 0 && len(hits) > 0 {
		if wait := hits[len(hits)-1] + cooldownMs - now; wait > 0 {
			retryMs, res.Reason = wait, ratelimit.ReasonCooldown
		}
	}
	if len(hits) >= lim.Limit {
		if wait := hits[0] + windowMs - now; wait > retryMs {
			retryMs, res.Reason = wait, ratelimit.ReasonLimitExceeded
		}
	}
	res.RetryAfter = time.Duration(max(retryMs, 1)) * time.Millisecond
	return res, nil
}
