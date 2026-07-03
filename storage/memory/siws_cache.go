package memorystore

import (
	"context"
	"sync"
	"time"

	"github.com/open-rails/authkit/siws"
)

// SIWSCache stores pending SIWS challenges in memory.
// This is only suitable for single-node deployments or local development.
type SIWSCache struct {
	mu     sync.RWMutex
	data   map[string]siwsEntry
	ttl    time.Duration
	closed chan struct{}
}

type siwsEntry struct {
	data      siws.ChallengeData
	expiresAt time.Time
}

// NewSIWSCache creates a new in-memory SIWS challenge cache.
func NewSIWSCache(ttl time.Duration) *SIWSCache {
	if ttl <= 0 {
		ttl = 15 * time.Minute
	}
	c := &SIWSCache{
		data:   make(map[string]siwsEntry),
		ttl:    ttl,
		closed: make(chan struct{}),
	}
	go c.cleanupLoop()
	return c
}

// Put stores a challenge in memory.
func (c *SIWSCache) Put(ctx context.Context, nonce string, data siws.ChallengeData) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.data[nonce] = siwsEntry{
		data:      data,
		expiresAt: time.Now().Add(c.ttl),
	}
	return nil
}

// Get retrieves a challenge from memory.
func (c *SIWSCache) Get(ctx context.Context, nonce string) (siws.ChallengeData, bool, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	entry, ok := c.data[nonce]
	if !ok {
		return siws.ChallengeData{}, false, nil
	}
	if time.Now().After(entry.expiresAt) {
		return siws.ChallengeData{}, false, nil
	}
	return entry.data, true, nil
}

// Del removes a challenge from memory.
func (c *SIWSCache) Del(ctx context.Context, nonce string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.data, nonce)
	return nil
}

// Consume atomically retrieves and deletes a challenge (single-use). The write
// lock makes get+delete a single-winner operation, so two concurrent callers
// presenting the same nonce can't both verify — closing the SIWS replay window.
func (c *SIWSCache) Consume(ctx context.Context, nonce string) (siws.ChallengeData, bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.data[nonce]
	if !ok {
		return siws.ChallengeData{}, false, nil
	}
	delete(c.data, nonce) // consume even if expired, so it can't be retried
	if time.Now().After(entry.expiresAt) {
		return siws.ChallengeData{}, false, nil
	}
	return entry.data, true, nil
}

// cleanupLoop periodically removes expired entries until Close is called
// (mirrors StateCache — #196's secondary defect was an unstoppable goroutine
// leaked per cache instance).
func (c *SIWSCache) cleanupLoop() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			c.cleanup()
		case <-c.closed:
			return
		}
	}
}

// Close stops the background cleanup goroutine.
// Should be called when the cache is no longer needed.
func (c *SIWSCache) Close() error {
	close(c.closed)
	return nil
}

func (c *SIWSCache) cleanup() {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	for k, v := range c.data {
		if now.After(v.expiresAt) {
			delete(c.data, k)
		}
	}
}
