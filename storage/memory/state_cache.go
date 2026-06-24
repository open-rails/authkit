package memorystore

import (
	"context"
	"sync"
	"time"

	oidckit "github.com/open-rails/authkit/oidc"
)

// StateCache is an in-memory implementation of oidckit.StateCache with TTL.
type StateCache struct {
	mu     sync.Mutex
	ttl    time.Duration
	data   map[string]item
	closed chan struct{}
}

type item struct {
	v   oidckit.StateData
	exp time.Time
}

// NewStateCache creates a new in-memory state cache with the given TTL.
// If ttl <= 0, a default of 10 minutes is used.
// Starts a background goroutine to clean up expired entries every minute.
func NewStateCache(ttl time.Duration) *StateCache {
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	c := &StateCache{ttl: ttl, data: make(map[string]item), closed: make(chan struct{})}
	go c.cleanupLoop()
	return c
}

func (s *StateCache) Put(ctx context.Context, state string, v oidckit.StateData) error {
	_ = ctx
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[state] = item{v: v, exp: time.Now().Add(s.ttl)}
	return nil
}

func (s *StateCache) Get(ctx context.Context, state string) (oidckit.StateData, bool, error) {
	_ = ctx
	s.mu.Lock()
	defer s.mu.Unlock()
	it, ok := s.data[state]
	if !ok {
		return oidckit.StateData{}, false, nil
	}
	if time.Now().After(it.exp) {
		delete(s.data, state)
		return oidckit.StateData{}, false, nil
	}
	return it.v, true, nil
}

func (s *StateCache) Del(ctx context.Context, state string) error {
	_ = ctx
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data, state)
	return nil
}

// Consume atomically returns and deletes the state in one locked step, closing
// the replay/TOCTOU window a separate Get+Del leaves open. ok=false if the state
// is absent, expired, or already consumed.
func (s *StateCache) Consume(ctx context.Context, state string) (oidckit.StateData, bool, error) {
	_ = ctx
	s.mu.Lock()
	defer s.mu.Unlock()
	it, ok := s.data[state]
	if !ok {
		return oidckit.StateData{}, false, nil
	}
	delete(s.data, state)
	if time.Now().After(it.exp) {
		return oidckit.StateData{}, false, nil
	}
	return it.v, true, nil
}

// cleanupLoop runs in the background and removes expired entries every minute.
func (s *StateCache) cleanupLoop() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			s.cleanup()
		case <-s.closed:
			return
		}
	}
}

// cleanup removes all expired entries from the cache.
func (s *StateCache) cleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for k, v := range s.data {
		if now.After(v.exp) {
			delete(s.data, k)
		}
	}
}

// Close stops the background cleanup goroutine.
// Should be called when the cache is no longer needed.
func (s *StateCache) Close() error {
	close(s.closed)
	return nil
}
