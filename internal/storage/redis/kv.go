package redisstore

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

// KV is the Redis ephemeral store. Every key is namespaced by prefix (#307) so
// several AuthKit deployments can share one Redis database without colliding.
type KV struct {
	rdb    *redis.Client
	prefix string
}

func NewKV(rdb *redis.Client, prefix string) *KV {
	return &KV{rdb: rdb, prefix: prefix}
}

func (k *KV) Client() *redis.Client { return k.rdb }

// Prefix returns the namespace every key is written under.
func (k *KV) Prefix() string { return k.prefix }

func (k *KV) key(key string) string { return k.prefix + key }

func (k *KV) Get(ctx context.Context, key string) ([]byte, bool, error) {
	b, err := k.rdb.Get(ctx, k.key(key)).Bytes()
	if err == redis.Nil {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return b, true, nil
}

func (k *KV) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	return k.rdb.Set(ctx, k.key(key), value, ttl).Err()
}

func (k *KV) Del(ctx context.Context, key string) error {
	return k.rdb.Del(ctx, k.key(key)).Err()
}

func (k *KV) Consume(ctx context.Context, key string) ([]byte, bool, error) {
	b, err := k.rdb.GetDel(ctx, k.key(key)).Bytes()
	if err == redis.Nil {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return b, true, nil
}

// incrScript increments and, only on creation, sets the expiry — one atomic
// server-side step, so concurrent callers observe distinct consecutive values
// and repeated increments never extend the counter's life.
var incrScript = redis.NewScript(`
local n = redis.call('INCR', KEYS[1])
if n == 1 and tonumber(ARGV[1]) > 0 then
  redis.call('PEXPIRE', KEYS[1], ARGV[1])
end
return n
`)

func (k *KV) Incr(ctx context.Context, key string, ttl time.Duration) (int64, error) {
	return incrScript.Run(ctx, k.rdb, []string{key}, ttl.Milliseconds()).Int64()
}
