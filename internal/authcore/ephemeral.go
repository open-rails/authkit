package authcore

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

type EphemeralMode string

const (
	EphemeralMemory EphemeralMode = "memory"
	EphemeralRedis  EphemeralMode = "redis"
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
}

func (s *Service) EphemeralMode() EphemeralMode {
	if s == nil {
		return EphemeralMemory
	}
	if s.ephemeralMode == "" {
		return EphemeralMemory
	}
	return s.ephemeralMode
}

// IsDevEnvironment reports whether a host-provided environment string is non-production.
func IsDevEnvironment(environment string) bool {
	return isDevEnvironment(environment)
}

func (s *Service) useEphemeralStore() bool {
	return s != nil && s.ephemeralStore != nil
}

func (s *Service) ephemSetJSON(ctx context.Context, key string, value any, ttl time.Duration) error {
	if !s.useEphemeralStore() {
		return fmt.Errorf("ephemeral store unavailable")
	}
	b, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return s.ephemeralStore.Set(ctx, key, b, ttl)
}

func (s *Service) ephemGetJSON(ctx context.Context, key string, out any) (bool, error) {
	if !s.useEphemeralStore() {
		return false, fmt.Errorf("ephemeral store unavailable")
	}
	b, ok, err := s.ephemeralStore.Get(ctx, key)
	if err != nil || !ok {
		return false, err
	}
	return true, json.Unmarshal(b, out)
}

func (s *Service) ephemSetString(ctx context.Context, key, value string, ttl time.Duration) error {
	if !s.useEphemeralStore() {
		return fmt.Errorf("ephemeral store unavailable")
	}
	return s.ephemeralStore.Set(ctx, key, []byte(value), ttl)
}

func (s *Service) ephemGetString(ctx context.Context, key string) (string, bool, error) {
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
func (s *Service) ephemConsumeJSON(ctx context.Context, key string, out any) (bool, error) {
	if !s.useEphemeralStore() {
		return false, fmt.Errorf("ephemeral store unavailable")
	}
	b, ok, err := s.ephemeralStore.Consume(ctx, key)
	if err != nil || !ok {
		return false, err
	}
	return true, json.Unmarshal(b, out)
}

func (s *Service) ephemDel(ctx context.Context, key string) error {
	if !s.useEphemeralStore() {
		return fmt.Errorf("ephemeral store unavailable")
	}
	return s.ephemeralStore.Del(ctx, key)
}
