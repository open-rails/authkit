package ratelimit

import (
	"math"
	"testing"
)

// Remaining takes used as int64 (the Redis backend reads it from a Lua reply);
// out-of-range values clamp instead of wrapping through an int conversion.
func TestRemainingClampsInt64(t *testing.T) {
	cases := []struct {
		limit int
		used  int64
		want  int
	}{
		{10, 0, 10}, {10, 3, 7}, {10, 10, 0}, {10, 11, 0},
		{10, math.MaxInt64, 0}, {10, -1, 10}, {10, math.MinInt64, 10},
	}
	for _, c := range cases {
		if got := Remaining(c.limit, c.used); got != c.want {
			t.Errorf("Remaining(%d, %d) = %d, want %d", c.limit, c.used, got, c.want)
		}
	}
}
