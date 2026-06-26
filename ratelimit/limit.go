package ratelimit

import "time"

// Limit configures a named rate-limit bucket: at most Limit requests per Window,
// with an optional Cooldown applied once the limit is hit. It is the single shared
// limit type consumed by the memory and redis limiter backends and the HTTP layer.
type Limit struct {
	Limit    int
	Window   time.Duration
	Cooldown time.Duration
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

// Remaining returns the non-negative requests left given a limit and used count.
func Remaining(limit, used int) int {
	left := limit - used
	if left < 0 {
		return 0
	}
	return left
}
