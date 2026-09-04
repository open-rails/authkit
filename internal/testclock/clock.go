// Package testclock is a settable clock for tests that would otherwise sleep
// through a TTL, grace window or rate-limit window.
package testclock

import (
	"sync"
	"time"
)

// Clock reports either a frozen instant (New) or the wall clock (Wall), in both
// cases shifted by every Advance so far. Frozen suits pure in-memory TTL pins;
// Wall suits integration tests whose other timestamps come from Postgres.
type Clock struct {
	mu     sync.Mutex
	base   time.Time
	offset time.Duration
	frozen bool
}

// New freezes the clock at the current time; only Advance moves it.
func New() *Clock { return &Clock{base: time.Now(), frozen: true} }

// Wall follows the wall clock plus the accumulated Advance offset.
func Wall() *Clock { return &Clock{} }

// Now is the func() time.Time the seams accept.
func (c *Clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.frozen {
		return c.base.Add(c.offset)
	}
	return time.Now().Add(c.offset)
}

func (c *Clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.offset += d
}
