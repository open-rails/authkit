package dpop

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/open-rails/authkit/internal/redisfallback"
)

const (
	replayPrefix = "authkit:spent:"
	// maxSpent bounds the keys held in memory; past it claims are refused
	// until expired ones are swept.
	maxSpent   = 100_000
	sweepEvery = time.Minute
)

var errReplaysFull = errors.New("dpop: in-memory replay store is full")

// Store spends single-use keys for every replica: Claim records key as spent
// for ttl and reports false when it already was (verify.ReplayStore).
type Store interface {
	Claim(ctx context.Context, key string, ttl time.Duration) (bool, error)
}

// Replays records spent single-use proofs (DPoP proofs, JWT-bearer
// assertions) until they expire: in the host's Store when given, whose
// errors refuse; else in Redis, shared by every replica; else in this
// process's memory (one node), which also takes over while Redis fails.
type Replays struct {
	store Store
	rdb   redis.UniversalClient
	gate  *redisfallback.Gate
	mu    sync.Mutex
	spent map[string]time.Time
	swept time.Time
}

// NewReplays spends proofs in store, else in rdb, else in memory.
func NewReplays(rdb redis.UniversalClient, store Store) *Replays {
	if isNil(rdb) {
		rdb = nil
	}
	if isNil(store) {
		store = nil
	}
	return &Replays{store: store, rdb: rdb, spent: map[string]time.Time{}, swept: time.Now(), gate: redisfallback.New(
		"authkit: Redis replay store failed; each process records spent proofs on its own until Redis recovers",
		"authkit: Redis replay store recovered")}
}

// Claim is a ReplayGuard: it records key as spent for ttl, and reports false
// when it already was.
func (r *Replays) Claim(ctx context.Context, key string, ttl time.Duration) (bool, error) {
	if r.store != nil {
		return r.store.Claim(ctx, key, ttl)
	}
	if r.rdb != nil {
		if claimed, ok := redisfallback.Run(ctx, r.gate, func(ctx context.Context) (bool, error) {
			return r.rdb.SetNX(ctx, replayPrefix+key, 1, ttl).Result()
		}); ok {
			return claimed, nil
		}
	}
	return r.claimInMemory(key, ttl)
}

func (r *Replays) claimInMemory(key string, ttl time.Duration) (bool, error) {
	now := time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()
	if until, ok := r.spent[key]; ok && now.Before(until) {
		return false, nil
	}
	if since := now.Sub(r.swept); since >= sweepEvery || (len(r.spent) >= maxSpent && since >= time.Second) {
		for k, until := range r.spent {
			if !now.Before(until) {
				delete(r.spent, k)
			}
		}
		r.swept = now
	}
	if len(r.spent) >= maxSpent {
		return false, errReplaysFull
	}
	r.spent[key] = now.Add(ttl)
	return true, nil
}

// isNil reports a nil interface, including one holding a nil pointer.
func isNil(v any) bool {
	if v == nil {
		return true
	}
	rv := reflect.ValueOf(v)
	return rv.Kind() == reflect.Pointer && rv.IsNil()
}
