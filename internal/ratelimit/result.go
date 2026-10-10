package ratelimit

import (
	"context"
	"time"
)

const (
	ReasonCooldown      = "cooldown"
	ReasonLimitExceeded = "limit_exceeded"
)

// Limiter spends one request of key's budget in bucket, in a store every
// replica shares. An error means no store could decide, and the request is
// refused: no failure lifts a budget or counts it per process.
type Limiter interface {
	Allow(ctx context.Context, bucket, key string) (Result, error)
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
