package netguard

import (
	"math/rand/v2"
	"time"
)

// Backoff is a full-jitter delay for a zero-based retry attempt: uniform in
// [0, min(max, base·2^attempt)].
func Backoff(attempt int, base, max time.Duration) time.Duration {
	ceil := max
	if attempt < 30 {
		if d := base << attempt; d > 0 && d < max {
			ceil = d
		}
	}
	return rand.N(ceil + 1)
}
