package core

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
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
}

func (s *Service) WithEphemeralStore(store EphemeralStore, mode EphemeralMode) *Service {
	if mode == "" {
		mode = EphemeralMemory
	}
	s.ephemeralStore = store
	s.ephemeralMode = mode
	return s
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

// IsDevEnvironment reports whether the current ENV/APP_ENV/ENVIRONMENT is non-production.
func IsDevEnvironment() bool {
	return isDevEnvironment(getEnvironment())
}

func (s *Service) useEphemeralStore() bool {
	return s != nil && s.ephemeralStore != nil
}

func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

func (s *Service) ephemSetJSON(ctx context.Context, key string, value any, ttl time.Duration) error {
	if !s.useEphemeralStore() {
		return fmt.Errorf("ephemeral store unavailable")
	}
	b, err := marshalJSON(value)
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
	return true, unmarshalJSON(b, out)
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

func (s *Service) ephemDel(ctx context.Context, key string) error {
	if !s.useEphemeralStore() {
		return fmt.Errorf("ephemeral store unavailable")
	}
	return s.ephemeralStore.Del(ctx, key)
}

func marshalJSON(v any) ([]byte, error) {
	type jsonMarshaler interface {
		MarshalJSON() ([]byte, error)
	}
	if jm, ok := v.(jsonMarshaler); ok {
		return jm.MarshalJSON()
	}
	return jsonMarshal(v)
}

func unmarshalJSON(b []byte, v any) error {
	type jsonUnmarshaler interface {
		UnmarshalJSON([]byte) error
	}
	if ju, ok := v.(jsonUnmarshaler); ok {
		return ju.UnmarshalJSON(b)
	}
	return jsonUnmarshal(b, v)
}

func jsonMarshal(v any) ([]byte, error)   { return json.Marshal(v) }
func jsonUnmarshal(b []byte, v any) error { return json.Unmarshal(b, v) }
