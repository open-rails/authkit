package memorystore

import (
	"context"
	"sync"
	"time"
)

type kvItem struct {
	value   []byte
	expires time.Time
}

// KV is a simple in-memory key-value store with TTL support.
// It is only safe for single-process deployments.
type KV struct {
	mu    sync.Mutex
	items map[string]kvItem
}

func NewKV() *KV {
	return &KV{items: make(map[string]kvItem)}
}

func (k *KV) Get(ctx context.Context, key string) ([]byte, bool, error) {
	_ = ctx
	k.mu.Lock()
	defer k.mu.Unlock()
	it, ok := k.items[key]
	if !ok {
		return nil, false, nil
	}
	if !it.expires.IsZero() && time.Now().After(it.expires) {
		delete(k.items, key)
		return nil, false, nil
	}
	return it.value, true, nil
}

func (k *KV) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	_ = ctx
	k.mu.Lock()
	defer k.mu.Unlock()
	var exp time.Time
	if ttl > 0 {
		exp = time.Now().Add(ttl)
	}
	k.items[key] = kvItem{value: append([]byte(nil), value...), expires: exp}
	return nil
}

func (k *KV) Del(ctx context.Context, key string) error {
	_ = ctx
	k.mu.Lock()
	defer k.mu.Unlock()
	delete(k.items, key)
	return nil
}
