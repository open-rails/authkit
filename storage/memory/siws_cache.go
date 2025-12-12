package memorystore

import (
	"context"
	"sync"
	"time"

	"github.com/PaulFidika/authkit/siws"
)

// SIWSCache stores pending SIWS challenges in memory.
// This is only suitable for single-node deployments or local development.
type SIWSCache struct {
	mu   sync.RWMutex
	data map[string]siwsEntry
	ttl  time.Duration
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
		data: make(map[string]siwsEntry),
		ttl:  ttl,
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

// cleanupLoop periodically removes expired entries.
func (c *SIWSCache) cleanupLoop() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		c.cleanup()
	}
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
