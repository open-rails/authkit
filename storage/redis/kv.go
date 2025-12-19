package redisstore

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

// KV is a Redis-backed ephemeral key-value store with TTL support.
type KV struct {
	rdb *redis.Client
}

func NewKV(rdb *redis.Client) *KV {
	return &KV{rdb: rdb}
}

func (k *KV) Get(ctx context.Context, key string) ([]byte, bool, error) {
	b, err := k.rdb.Get(ctx, key).Bytes()
	if err == redis.Nil {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return b, true, nil
}

func (k *KV) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	return k.rdb.Set(ctx, key, value, ttl).Err()
}

func (k *KV) Del(ctx context.Context, key string) error {
	return k.rdb.Del(ctx, key).Err()
}
