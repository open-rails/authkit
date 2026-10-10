// Package redisfallback runs a store's Redis commands with an in-process
// fallback. A command waits at most Timeout, whatever the client's own
// timeouts. While Redis fails, one call tries it again after a backoff that
// doubles from a second to 30 seconds and the rest use the fallback; the
// failure and the recovery are logged once each.
package redisfallback

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// Timeout bounds what one command waits on Redis, so an outage costs a
	// request at most this.
	Timeout    = 250 * time.Millisecond
	minBackoff = time.Second
	maxBackoff = 30 * time.Second
)

// Gate tracks one store's Redis.
type Gate struct {
	failure, recovery string
	down              atomic.Bool
	mu                sync.Mutex // guards backoff and retryAt
	backoff           time.Duration
	retryAt           time.Time
}

// New is a gate that logs failure and recovery when Redis fails and answers
// again.
func New(failure, recovery string) *Gate {
	return &Gate{failure: failure, recovery: recovery}
}

// Run runs cmd on Redis. ok is false when the caller must use its fallback:
// Redis failed, or is down and no retry is due.
func Run[T any](ctx context.Context, g *Gate, cmd func(context.Context) (T, error)) (_ T, ok bool) {
	var zero T
	probe := false
	if g.down.Load() {
		if probe = g.claimProbe(); !probe {
			return zero, false
		}
	}
	v, err := bounded(ctx, cmd)
	if err == nil {
		g.recovered()
		return v, true
	}
	if ctx.Err() == nil { // the caller giving up is no outage
		g.failed(err, probe)
	}
	return zero, false
}

// bounded waits on cmd at most Timeout. The client honors ctx only with
// ContextTimeoutEnabled, so an abandoned command ends at its own timeout.
func bounded[T any](ctx context.Context, cmd func(context.Context) (T, error)) (T, error) {
	ctx, cancel := context.WithTimeout(ctx, Timeout)
	defer cancel()
	type reply struct {
		v   T
		err error
	}
	ch := make(chan reply, 1)
	go func() {
		v, err := cmd(ctx)
		ch <- reply{v, err}
	}()
	select {
	case r := <-ch:
		return r.v, r.err
	case <-ctx.Done():
		var zero T
		return zero, ctx.Err()
	}
}

// claimProbe reports whether this call tries Redis again: the first one after
// the backoff.
func (g *Gate) claimProbe() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := time.Now()
	if now.Before(g.retryAt) {
		return false
	}
	g.retryAt = now.Add(g.backoff)
	return true
}

func (g *Gate) failed(err error, probe bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	switch {
	case !g.down.Load():
		g.backoff = minBackoff
		g.down.Store(true)
		slog.Warn(g.failure, "error", err)
	case probe:
		g.backoff = min(2*g.backoff, maxBackoff)
	default:
		return
	}
	g.retryAt = time.Now().Add(g.backoff)
}

func (g *Gate) recovered() {
	if !g.down.Load() {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.down.Swap(false) {
		slog.Info(g.recovery)
	}
}
