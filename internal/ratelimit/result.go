package ratelimit

import (
	"context"
	"time"
)

const (
	ReasonCooldown      = "cooldown"
	ReasonLimitExceeded = "limit_exceeded"
)

// Limiter spends one request of key's budget in bucket. It has no error: a
// limiter that loses its store decides in process instead, so no failure
// lifts a budget.
type Limiter interface {
	Allow(ctx context.Context, bucket, key string) Result
}

// Result is one decision. A refusal always carries a positive RetryAfter.
type Result struct {
	Allowed    bool
	RetryAfter time.Duration
	Reason     string
	Limit      int
	Remaining  int
	Window     time.Duration
	Cooldown   time.Duration
}
