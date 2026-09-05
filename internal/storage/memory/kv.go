package memorystore

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"time"
)

const (
	DefaultKVSweepInterval = time.Minute
	DefaultKVMaxEntries    = 100_000
)

// ErrKVFull is returned by Set when the store holds MaxEntries live keys and
// sweeping expired ones frees nothing: the bound on heap growth is a hard
// refusal, never a silent eviction of someone else's live token.
var ErrKVFull = errors.New("memorystore: kv entry cap reached")

type kvItem struct {
	value   []byte
	expires time.Time
}

// KV is an in-memory key-value store with TTL support for single-process
// deployments. Expired entries are reclaimed by a background sweep (#305) as
// well as on access, and the live entry count is capped.
type KV struct {
	mu         sync.Mutex
	items      map[string]kvItem
	maxEntries int
	sweep      time.Duration
	closed     chan struct{}
	closeOnce  sync.Once
	now        func() time.Time
}

type KVOption func(*KV)

// WithSweepInterval sets how often expired entries are reclaimed without being
// read. Non-positive disables the sweep.
func WithSweepInterval(d time.Duration) KVOption { return func(k *KV) { k.sweep = d } }

// WithMaxEntries caps the number of live entries; Set refuses beyond it.
func WithMaxEntries(n int) KVOption { return func(k *KV) { k.maxEntries = n } }

// WithKVClock replaces the TTL clock (tests advance it instead of sleeping).
func WithKVClock(now func() time.Time) KVOption { return func(k *KV) { k.now = now } }

func NewKV(opts ...KVOption) *KV {
	k := &KV{
		items:      make(map[string]kvItem),
		maxEntries: DefaultKVMaxEntries,
		sweep:      DefaultKVSweepInterval,
		closed:     make(chan struct{}),
		now:        time.Now,
	}
	for _, opt := range opts {
		opt(k)
	}
	if k.sweep > 0 {
		go k.sweepLoop(k.sweep)
	}
	return k
}

// Close stops the background sweep. Idempotent.
func (k *KV) Close() { k.closeOnce.Do(func() { close(k.closed) }) }

// Len reports the number of stored entries, expired ones included until swept.
func (k *KV) Len() int {
	k.mu.Lock()
	defer k.mu.Unlock()
	return len(k.items)
}

func (k *KV) Get(ctx context.Context, key string) ([]byte, bool, error) {
	_ = ctx
	k.mu.Lock()
	defer k.mu.Unlock()
	it, ok := k.items[key]
	if !ok {
		return nil, false, nil
	}
	if !it.expires.IsZero() && k.now().After(it.expires) {
		delete(k.items, key)
		return nil, false, nil
	}
	return it.value, true, nil
}

func (k *KV) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	_ = ctx
	k.mu.Lock()
	defer k.mu.Unlock()
	if _, exists := k.items[key]; !exists && k.maxEntries > 0 && len(k.items) >= k.maxEntries {
		k.sweepLocked(k.now())
		if len(k.items) >= k.maxEntries {
			return ErrKVFull
		}
	}
	var exp time.Time
	if ttl > 0 {
		exp = k.now().Add(ttl)
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

// Consume atomically returns and deletes a key under a single lock hold, so a
// value is delivered to AT MOST ONE caller even under concurrent reads — the
// in-memory analogue of Redis GETDEL. Required for single-use credentials whose
// KEY is the secret (passkey challenge, password-reset token); a Get+Del pair
// would let two concurrent requests both observe the value before either deletes.
// Missing or expired key => (nil, false, nil).
func (k *KV) Consume(ctx context.Context, key string) ([]byte, bool, error) {
	_ = ctx
	k.mu.Lock()
	defer k.mu.Unlock()
	it, ok := k.items[key]
	if !ok {
		return nil, false, nil
	}
	delete(k.items, key) // delete inside the same lock span: at-most-once delivery
	if !it.expires.IsZero() && k.now().After(it.expires) {
		return nil, false, nil
	}
	return it.value, true, nil
}

// Incr is the in-memory analogue of the Redis INCR+PEXPIRE script: read,
// increment and write happen under one lock hold, so concurrent callers see
// distinct consecutive values. The TTL is set only when the key is created,
// and creation is bounded by the entry cap exactly like Set.
func (k *KV) Incr(ctx context.Context, key string, ttl time.Duration) (int64, error) {
	_ = ctx
	k.mu.Lock()
	defer k.mu.Unlock()
	now := k.now()
	it, ok := k.items[key]
	if ok && !it.expires.IsZero() && now.After(it.expires) {
		delete(k.items, key)
		ok = false
	}
	n := int64(1)
	if ok {
		v, err := strconv.ParseInt(string(it.value), 10, 64)
		if err != nil {
			return 0, err
		}
		n = v + 1
	} else {
		if k.maxEntries > 0 && len(k.items) >= k.maxEntries {
			k.sweepLocked(now)
			if len(k.items) >= k.maxEntries {
				return 0, ErrKVFull
			}
		}
		it = kvItem{}
		if ttl > 0 {
			it.expires = now.Add(ttl)
		}
	}
	it.value = []byte(strconv.FormatInt(n, 10))
	k.items[key] = it
	return n, nil
}

func (k *KV) sweepLoop(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			k.mu.Lock()
			k.sweepLocked(k.now())
			k.mu.Unlock()
		case <-k.closed:
			return
		}
	}
}

func (k *KV) sweepLocked(now time.Time) {
	for key, it := range k.items {
		if !it.expires.IsZero() && now.After(it.expires) {
			delete(k.items, key)
		}
	}
}
