// Package testclock is a settable clock for tests that would otherwise sleep
// through a TTL, grace window or rate-limit window.
package testclock

import (
	"sync"
	"time"
)

// Clock is the wall clock shifted by every Advance so far.
type Clock struct {
	mu     sync.Mutex
	offset time.Duration
}

// Wall follows the wall clock plus the accumulated Advance offset.
func Wall() *Clock { return &Clock{} }

// Now is the func() time.Time the seams accept.
func (c *Clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return time.Now().Add(c.offset)
}

func (c *Clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.offset += d
}
