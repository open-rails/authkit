package ratelimit

import (
	"fmt"
	"strings"
	"time"
)

// Limit configures a named rate-limit bucket: at most Limit requests per Window,
// with an optional Cooldown between accepted requests. It is the single shared
// limit type consumed by the memory and redis limiter backends and the HTTP layer.
type Limit struct {
	Limit    int
	Window   time.Duration
	Cooldown time.Duration
}

// ValidateLimits rejects policies that the millisecond-based backends cannot
// enforce identically. Disabling a limiter is an explicit HTTP configuration.
func ValidateLimits(limits map[string]Limit) error {
	for bucket, limit := range limits {
		if strings.TrimSpace(bucket) == "" {
			return fmt.Errorf("ratelimit: empty bucket name")
		}
		if limit.Limit <= 0 || uint64(limit.Limit) > 1<<53-1 {
			return fmt.Errorf("ratelimit %q: limit must be between 1 and 2^53-1", bucket)
		}
		if limit.Window <= 0 || limit.Window%time.Millisecond != 0 {
			return fmt.Errorf("ratelimit %q: window must be positive whole milliseconds", bucket)
		}
		if limit.Cooldown < 0 || limit.Cooldown > limit.Window || limit.Cooldown%time.Millisecond != 0 {
			return fmt.Errorf("ratelimit %q: cooldown must be whole milliseconds between zero and window", bucket)
		}
	}
	return nil
}

// LookupLimit resolves the Limit for a bucket from a limits map: the bucket's own
// entry, else the "default" entry, else a conservative built-in fallback (found is
// false only for that fallback). Shared by the memory and redis backends.
func LookupLimit(limits map[string]Limit, bucket string) (Limit, bool) {
	if v, ok := limits[bucket]; ok {
		return v, true
	}
	if v, ok := limits["default"]; ok {
		return v, true
	}
	return Limit{Limit: 100, Window: time.Minute}, false
}

// Remaining is the non-negative budget left after used requests. used is
// int64 because the Redis backend reads it straight from a Lua reply; it is
// clamped before any narrowing so an out-of-range count cannot wrap.
func Remaining(limit int, used int64) int {
	if used <= 0 {
		return limit
	}
	if used >= int64(limit) {
		return 0
	}
	return int(int64(limit) - used)
}
