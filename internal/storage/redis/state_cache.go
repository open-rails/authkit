package redisstore

import (
	"context"
	"encoding/json"
	"time"

	"github.com/open-rails/authkit/oidckit"
	"github.com/redis/go-redis/v9"
)

type StateCache struct {
	rdb   *redis.Client
	keyNS string
	ttl   time.Duration
}

func NewStateCache(rdb *redis.Client, keyPrefix string, ttl time.Duration) *StateCache {
	if keyPrefix == "" {
		keyPrefix = "auth:oidc:state:"
	}
	if ttl <= 0 {
		ttl = 15 * time.Minute
	}
	return &StateCache{rdb: rdb, keyNS: keyPrefix, ttl: ttl}
}

func (s *StateCache) key(state string) string { return s.keyNS + state }

func (s *StateCache) Put(ctx context.Context, state string, data oidckit.StateData) error {
	b, err := json.Marshal(data)
	if err != nil {
		return err
	}
	return s.rdb.Set(ctx, s.key(state), b, s.ttl).Err()
}

func (s *StateCache) Get(ctx context.Context, state string) (oidckit.StateData, bool, error) {
	val, err := s.rdb.Get(ctx, s.key(state)).Bytes()
	if err == redis.Nil {
		return oidckit.StateData{}, false, nil
	}
	if err != nil {
		return oidckit.StateData{}, false, err
	}
	var d oidckit.StateData
	if err := json.Unmarshal(val, &d); err != nil {
		return oidckit.StateData{}, false, err
	}
	return d, true, nil
}

func (s *StateCache) Del(ctx context.Context, state string) error {
	return s.rdb.Del(ctx, s.key(state)).Err()
}

// Consume atomically returns and deletes the state via Redis GETDEL, closing the
// replay/TOCTOU window a separate Get+Del leaves open. ok=false if absent/consumed.
func (s *StateCache) Consume(ctx context.Context, state string) (oidckit.StateData, bool, error) {
	val, err := s.rdb.GetDel(ctx, s.key(state)).Bytes()
	if err == redis.Nil {
		return oidckit.StateData{}, false, nil
	}
	if err != nil {
		return oidckit.StateData{}, false, err
	}
	var d oidckit.StateData
	if err := json.Unmarshal(val, &d); err != nil {
		return oidckit.StateData{}, false, err
	}
	return d, true, nil
}
