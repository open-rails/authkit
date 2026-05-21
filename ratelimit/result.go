package ratelimit

import "time"

const (
	ReasonCooldown      = "cooldown"
	ReasonLimitExceeded = "limit_exceeded"
)

type Result struct {
	Allowed    bool
	RetryAfter time.Duration
	Reason     string
	Limit      int
	Remaining  int
	Window     time.Duration
	Cooldown   time.Duration
}
