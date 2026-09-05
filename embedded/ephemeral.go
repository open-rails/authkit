package embedded

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	memorystore "github.com/open-rails/authkit/internal/storage/memory"
	redisstore "github.com/open-rails/authkit/internal/storage/redis"
	"github.com/redis/go-redis/v9"
)

// EphemeralStore is a minimal key-value interface used for short-lived auth state.
// Implementations should honor TTL on Set and treat missing keys as (found=false, err=nil).
type EphemeralStore interface {
	Get(ctx context.Context, key string) ([]byte, bool, error)
	Set(ctx context.Context, key string, value []byte, ttl time.Duration) error
	Del(ctx context.Context, key string) error
	// Consume atomically returns AND deletes a key in a single operation, so the
	// value is delivered to AT MOST ONE caller even under concurrent reads
	// (Redis GETDEL / a single locked get-delete). Single-use credentials whose
	// KEY is the secret — a WebAuthn/passkey challenge, a password-reset token —
	// MUST be read via Consume, never Get+Del: a non-atomic read-then-delete lets
	// two concurrent requests both observe the value before either deletes it,
	// defeating the single-use guarantee (replay). Missing key => (nil, false, nil).
	Consume(ctx context.Context, key string) ([]byte, bool, error)
	// Incr atomically increments the integer at key and returns the new value,
	// creating it as 1 with ttl when absent (the TTL is set once, not on every
	// increment). Attempt caps MUST use it: a Get+Set counter lets K concurrent
	// wrong guesses all read the same n and the cap never fires (#306).
	Incr(ctx context.Context, key string, ttl time.Duration) (int64, error)
}

// EphemeralRedisClient returns the *redis.Client backing the engine's ephemeral
// store when it is Redis-backed (Deps.Redis), or nil for a memory store. The HTTP
// transport reuses it so a host that wired Redis on the engine doesn't also have
// to pass it to authhttp — one Redis client, no split-brain ephemeral state
// (authkit #210). The type assertion is also THE redis-vs-memory discriminator.
func (s *Client) EphemeralRedisClient() *redis.Client {
	if s == nil {
		return nil
	}
	if kv, ok := s.ephemeralStore.(*redisstore.KV); ok {
		return kv.Client()
	}
	return nil
}

// resolveEphemeralStore turns Deps.Redis into the namespaced Redis store once
// the (normalized) config is known (#307).
func (s *Client) resolveEphemeralStore() {
	if s.redisClient == nil {
		return
	}
	if mk, ok := s.ephemeralStore.(*memorystore.KV); ok {
		mk.Close()
	}
	s.ephemeralStore = redisstore.NewKV(s.redisClient, s.cfg.Ephemeral.KeyPrefix)
}

// RedisKeyPrefix is the namespace every Redis key of this deployment is written
// under (ephemeral store, OIDC/SIWS caches, rate-limit counters).
func (s *Client) RedisKeyPrefix() string { return s.cfg.Ephemeral.KeyPrefix }

// EphemeralBackend names the live ephemeral store: "redis", "memory", "custom"
// (a host-supplied EphemeralStore) or "none".
func (s *Client) EphemeralBackend() string {
	switch s.ephemeralStore.(type) {
	case nil:
		return "none"
	case *redisstore.KV:
		return "redis"
	case *memorystore.KV:
		return "memory"
	}
	return "custom"
}

// checkEphemeralBackend refuses the per-process memory store unless
// Ephemeral.AllowMemory opts in (#305), and logs which backend is live so a
// mis-wired deployment is visible at startup.
func (s *Client) checkEphemeralBackend(cfg Config) error {
	backend := s.EphemeralBackend()
	if backend == "memory" && !cfg.Ephemeral.AllowMemory {
		return fmt.Errorf("authkit: in-memory ephemeral store without Ephemeral.AllowMemory: wire Redis, or set Ephemeral.AllowMemory for a single-instance deployment")
	}
	slog.Info("authkit: ephemeral store", "backend", backend)
	return nil
}

func (s *Client) useEphemeralStore() bool {
	return s != nil && s.ephemeralStore != nil
}

func (s *Client) ephemSetJSON(ctx context.Context, key string, value any, ttl time.Duration) error {
	if !s.useEphemeralStore() {
		return fmt.Errorf("ephemeral store unavailable")
	}
	b, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return s.ephemeralStore.Set(ctx, key, b, ttl)
}

func (s *Client) ephemGetJSON(ctx context.Context, key string, out any) (bool, error) {
	if !s.useEphemeralStore() {
		return false, fmt.Errorf("ephemeral store unavailable")
	}
	b, ok, err := s.ephemeralStore.Get(ctx, key)
	if err != nil || !ok {
		return false, err
	}
	return true, json.Unmarshal(b, out)
}

func (s *Client) ephemSetString(ctx context.Context, key, value string, ttl time.Duration) error {
	if !s.useEphemeralStore() {
		return fmt.Errorf("ephemeral store unavailable")
	}
	return s.ephemeralStore.Set(ctx, key, []byte(value), ttl)
}

func (s *Client) ephemGetString(ctx context.Context, key string) (string, bool, error) {
	if !s.useEphemeralStore() {
		return "", false, fmt.Errorf("ephemeral store unavailable")
	}
	b, ok, err := s.ephemeralStore.Get(ctx, key)
	if err != nil || !ok {
		return "", ok, err
	}
	return string(b), true, nil
}

// ephemConsumeJSON atomically reads-and-deletes key (single-use) and unmarshals the
// value into out. Use this — never ephemGetJSON + ephemDel — for credentials whose
// KEY is the secret (passkey challenge, password-reset token): the atomic consume
// guarantees at-most-once delivery so concurrent requests cannot replay the same key.
func (s *Client) ephemConsumeJSON(ctx context.Context, key string, out any) (bool, error) {
	if !s.useEphemeralStore() {
		return false, fmt.Errorf("ephemeral store unavailable")
	}
	b, ok, err := s.ephemeralStore.Consume(ctx, key)
	if err != nil || !ok {
		return false, err
	}
	return true, json.Unmarshal(b, out)
}

func (s *Client) ephemConsumeString(ctx context.Context, key string) (string, bool, error) {
	if !s.useEphemeralStore() {
		return "", false, fmt.Errorf("ephemeral store unavailable")
	}
	b, ok, err := s.ephemeralStore.Consume(ctx, key)
	if err != nil || !ok {
		return "", ok, err
	}
	return string(b), true, nil
}

func (s *Client) ephemIncr(ctx context.Context, key string, ttl time.Duration) (int64, error) {
	if !s.useEphemeralStore() {
		return 0, fmt.Errorf("ephemeral store unavailable")
	}
	return s.ephemeralStore.Incr(ctx, key, ttl)
}

func (s *Client) ephemDel(ctx context.Context, key string) error {
	if !s.useEphemeralStore() {
		return fmt.Errorf("ephemeral store unavailable")
	}
	return s.ephemeralStore.Del(ctx, key)
}
