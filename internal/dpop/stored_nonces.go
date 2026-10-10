package dpop

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"reflect"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/open-rails/authkit/internal/redisfallback"
)

const noncePrefix = "authkit:dpop-nonce:"

// StoredNonces are random server nonces kept for NonceLifetime: in Redis when
// given, shared by every replica, else in this process's memory (one node),
// which also takes over while Redis fails. No key is configured. A nonce lost
// with its store fails once; the client retries with the fresh one.
type StoredNonces struct {
	rdb    redis.UniversalClient
	gate   *redisfallback.Gate
	mu     sync.Mutex
	issued map[string]time.Time
	swept  time.Time
}

// NewStoredNonces keeps nonces in rdb, or in memory when rdb is nil.
func NewStoredNonces(rdb redis.UniversalClient) *StoredNonces {
	if v := reflect.ValueOf(rdb); rdb != nil && v.Kind() == reflect.Pointer && v.IsNil() {
		rdb = nil
	}
	return &StoredNonces{rdb: rdb, issued: map[string]time.Time{}, swept: time.Now(), gate: redisfallback.New(
		"authkit: Redis DPoP nonce store failed; each process issues nonces on its own until Redis recovers",
		"authkit: Redis DPoP nonce store recovered")}
}

// Issue records a new random nonce.
func (n *StoredNonces) Issue(ctx context.Context) string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	nonce := base64.RawURLEncoding.EncodeToString(b[:])
	if n.rdb != nil {
		if _, ok := redisfallback.Run(ctx, n.gate, func(ctx context.Context) (bool, error) {
			return true, n.rdb.Set(ctx, noncePrefix+nonce, 1, NonceLifetime).Err()
		}); ok {
			return nonce
		}
	}
	now := time.Now()
	n.mu.Lock()
	defer n.mu.Unlock()
	if now.Sub(n.swept) >= sweepEvery || len(n.issued) >= maxSpent {
		for k, until := range n.issued {
			if !now.Before(until) {
				delete(n.issued, k)
			}
		}
		n.swept = now
	}
	if len(n.issued) < maxSpent {
		n.issued[nonce] = now.Add(NonceLifetime)
	}
	return nonce
}

// Valid reports whether nonce was issued and is current.
func (n *StoredNonces) Valid(ctx context.Context, nonce string) bool {
	if len(nonce) != 22 {
		return false
	}
	if n.rdb != nil {
		if found, ok := redisfallback.Run(ctx, n.gate, func(ctx context.Context) (int64, error) {
			return n.rdb.Exists(ctx, noncePrefix+nonce).Result()
		}); ok {
			return found == 1
		}
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	until, ok := n.issued[nonce]
	return ok && time.Now().Before(until)
}
