// Package testclock is a settable clock for tests that would otherwise sleep
// through a TTL, grace window or rate-limit window.
package testclock

import (
	"sync"
	"time"
)

// Use makes an *authkit.Client decide TTLs and grace windows by now; call it
// before the Client serves. Ephemeral state keeps the database clock. The root
// package sets it: hosts have no way to change the clock.
var Use func(client any, now func() time.Time)

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
