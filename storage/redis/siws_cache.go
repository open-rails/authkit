package redisstore

import (
	"context"
	"encoding/json"
	"time"

	"github.com/open-rails/authkit/siws"
	"github.com/redis/go-redis/v9"
)

// SIWSCache stores pending SIWS challenges in Redis.
type SIWSCache struct {
	rdb   *redis.Client
	keyNS string
	ttl   time.Duration
}

// NewSIWSCache creates a new Redis-backed SIWS challenge cache.
func NewSIWSCache(rdb *redis.Client, keyPrefix string, ttl time.Duration) *SIWSCache {
	if keyPrefix == "" {
		keyPrefix = "auth:siws:nonce:"
	}
	if ttl <= 0 {
		ttl = 15 * time.Minute
	}
	return &SIWSCache{rdb: rdb, keyNS: keyPrefix, ttl: ttl}
}

func (c *SIWSCache) key(nonce string) string { return c.keyNS + nonce }

// Put stores a challenge in Redis.
func (c *SIWSCache) Put(ctx context.Context, nonce string, data siws.ChallengeData) error {
	b, err := json.Marshal(data)
	if err != nil {
		return err
	}
	return c.rdb.Set(ctx, c.key(nonce), b, c.ttl).Err()
}

// Get retrieves a challenge from Redis.
func (c *SIWSCache) Get(ctx context.Context, nonce string) (siws.ChallengeData, bool, error) {
	val, err := c.rdb.Get(ctx, c.key(nonce)).Bytes()
	if err == redis.Nil {
		return siws.ChallengeData{}, false, nil
	}
	if err != nil {
		return siws.ChallengeData{}, false, err
	}
	var d siws.ChallengeData
	if err := json.Unmarshal(val, &d); err != nil {
		return siws.ChallengeData{}, false, err
	}
	return d, true, nil
}

// Del removes a challenge from Redis.
func (c *SIWSCache) Del(ctx context.Context, nonce string) error {
	return c.rdb.Del(ctx, c.key(nonce)).Err()
}

// Consume atomically retrieves and deletes a challenge (single-use). Redis
// GETDEL guarantees only one concurrent caller receives the value, so a replayed
// SIWS signature can't reuse the same nonce within the challenge TTL.
func (c *SIWSCache) Consume(ctx context.Context, nonce string) (siws.ChallengeData, bool, error) {
	val, err := c.rdb.GetDel(ctx, c.key(nonce)).Bytes()
	if err == redis.Nil {
		return siws.ChallengeData{}, false, nil
	}
	if err != nil {
		return siws.ChallengeData{}, false, err
	}
	var d siws.ChallengeData
	if err := json.Unmarshal(val, &d); err != nil {
		return siws.ChallengeData{}, false, err
	}
	return d, true, nil
}
