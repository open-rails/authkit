package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/open-rails/authkit/internal/db"
	"github.com/open-rails/authkit/internal/oidcstate"
	"github.com/open-rails/authkit/internal/secret"
)

// ephemeralKV is AuthKit's short-lived auth state in Postgres (ephemeral_kv):
// codes, tokens, ceremonies, OIDC/SIWS state and attempt counters. Every
// replica sees the same rows, and each operation is a single statement, so
// single-use claims and counters are atomic across the fleet. Expiry always
// uses the database clock (never the engine clock), so skewed replicas agree on
// what is live. Expired rows are invisible to reads and purged by the
// maintenance job.
type ephemeralKV struct {
	pool *pgxpool.Pool
	q    *db.Queries
}

// ephemeralSweepBatch bounds each purge statement so it never holds many row
// locks at once.
const ephemeralSweepBatch = 1000

func ephemeralTTL(ttl time.Duration) (int64, error) {
	if ttl <= 0 {
		return 0, errors.New("authkit: ephemeral TTL must be positive")
	}
	return ttl.Microseconds(), nil
}

func (k *ephemeralKV) Get(ctx context.Context, key string) ([]byte, bool, error) {
	v, err := k.q.EphemeralGet(ctx, key)
	return ephemeralValue(v, err)
}

func (k *ephemeralKV) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	us, err := ephemeralTTL(ttl)
	if err != nil {
		return err
	}
	if value == nil {
		value = []byte{}
	}
	return k.q.EphemeralSet(ctx, db.EphemeralSetParams{Key: key, Value: value, TtlUs: us})
}

func (k *ephemeralKV) Del(ctx context.Context, key string) error {
	return k.q.EphemeralDelete(ctx, key)
}

// Consume deletes and returns a live key in one statement: of any number of
// concurrent callers, at most one receives the value. Single-use credentials
// whose key is the secret (passkey challenge, reset token) must use it, never
// Get+Del.
func (k *ephemeralKV) Consume(ctx context.Context, key string) ([]byte, bool, error) {
	v, err := k.q.EphemeralConsume(ctx, key)
	return ephemeralValue(v, err)
}

// CompareAndConsume deletes a live key only while it still holds expected, so
// an old reader can neither win twice nor consume a newer issuance.
func (k *ephemeralKV) CompareAndConsume(ctx context.Context, key string, expected []byte) (bool, error) {
	n, err := k.q.EphemeralCompareAndConsume(ctx, db.EphemeralCompareAndConsumeParams{Key: key, Expected: expected})
	return n == 1, err
}

// Incr returns distinct consecutive values to concurrent callers. The TTL is
// set when the counter starts and never extended; attempt caps must use it.
func (k *ephemeralKV) Incr(ctx context.Context, key string, ttl time.Duration) (int64, error) {
	us, err := ephemeralTTL(ttl)
	if err != nil {
		return 0, err
	}
	return k.q.EphemeralIncr(ctx, db.EphemeralIncrParams{Key: key, TtlUs: us})
}

// Swap writes value with a fresh ttl only while key still holds expected (nil:
// while it is absent), reporting whether it did.
func (k *ephemeralKV) Swap(ctx context.Context, key string, expected, value []byte, ttl time.Duration) (bool, error) {
	us, err := ephemeralTTL(ttl)
	if err != nil {
		return false, err
	}
	if expected == nil {
		expected = []byte{}
	}
	n, err := k.q.EphemeralSwap(ctx, db.EphemeralSwapParams{Key: key, Value: value, TtlUs: us, Expected: expected})
	return n == 1, err
}

// purgeExpiredEphemeral deletes expired rows in bounded batches. It runs on
// the main pool so it never occupies the small pool live claims use.
func (s *Engine) purgeExpiredEphemeral(ctx context.Context) (int64, error) {
	var total int64
	for {
		n, err := s.q.EphemeralDeleteExpired(ctx, ephemeralSweepBatch)
		total += n
		if err != nil || n < ephemeralSweepBatch {
			return total, err
		}
	}
}

func ephemeralValue(v []byte, err error) ([]byte, bool, error) {
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return v, true, nil
}

func (s *Engine) useEphemeralStore() bool {
	return s != nil && s.ephemeral != nil
}

func (s *Engine) ephemSetJSON(ctx context.Context, key string, value any, ttl time.Duration) error {
	if !s.useEphemeralStore() {
		return fmt.Errorf("ephemeral store unavailable")
	}
	b, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return s.ephemeral.Set(ctx, key, b, ttl)
}

func (s *Engine) ephemGetJSON(ctx context.Context, key string, out any) (bool, error) {
	_, ok, err := s.ephemReadJSON(ctx, key, out)
	return ok, err
}

// ephemReadJSON retains the exact bytes for a later conditional claim.
func (s *Engine) ephemReadJSON(ctx context.Context, key string, out any) ([]byte, bool, error) {
	if !s.useEphemeralStore() {
		return nil, false, fmt.Errorf("ephemeral store unavailable")
	}
	raw, ok, err := s.ephemeral.Get(ctx, key)
	if err != nil || !ok {
		return nil, false, err
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return nil, false, err
	}
	return raw, true, nil
}

func (s *Engine) claimProof(ctx context.Context, key string, expected []byte) error {
	if !s.useEphemeralStore() || len(expected) == 0 {
		return jwt.ErrTokenUnverifiable
	}
	claimed, err := s.ephemeral.CompareAndConsume(ctx, key, expected)
	if err != nil {
		return err
	}
	if !claimed {
		return jwt.ErrTokenUnverifiable
	}
	return nil
}

func (s *Engine) ephemSetString(ctx context.Context, key, value string, ttl time.Duration) error {
	if !s.useEphemeralStore() {
		return fmt.Errorf("ephemeral store unavailable")
	}
	return s.ephemeral.Set(ctx, key, []byte(value), ttl)
}

func (s *Engine) ephemGetString(ctx context.Context, key string) (string, bool, error) {
	if !s.useEphemeralStore() {
		return "", false, fmt.Errorf("ephemeral store unavailable")
	}
	b, ok, err := s.ephemeral.Get(ctx, key)
	if err != nil || !ok {
		return "", ok, err
	}
	return string(b), true, nil
}

// ephemConsumeJSON atomically reads-and-deletes key (single-use) and unmarshals the
// value into out. Use this — never ephemGetJSON + ephemDel — for credentials whose
// KEY is the secret (passkey challenge, password-reset token): the atomic consume
// guarantees at-most-once delivery so concurrent requests cannot replay the same key.
func (s *Engine) ephemConsumeJSON(ctx context.Context, key string, out any) (bool, error) {
	if !s.useEphemeralStore() {
		return false, fmt.Errorf("ephemeral store unavailable")
	}
	b, ok, err := s.ephemeral.Consume(ctx, key)
	if err != nil || !ok {
		return false, err
	}
	return true, json.Unmarshal(b, out)
}

// updateEphemeralJSON is an atomic read-modify-write of key's JSON value
// (zero when absent): edit changes it and reports whether to write it, which
// renews ttl. A concurrent writer makes it re-read and edit again.
func updateEphemeralJSON[T any](ctx context.Context, s *Engine, key string, ttl time.Duration, edit func(*T) bool) error {
	if !s.useEphemeralStore() {
		return fmt.Errorf("ephemeral store unavailable")
	}
	for range 16 {
		var v T
		raw, _, err := s.ephemReadJSON(ctx, key, &v)
		if err != nil {
			return err
		}
		if !edit(&v) {
			return nil
		}
		b, err := json.Marshal(v)
		if err != nil {
			return err
		}
		if ok, err := s.ephemeral.Swap(ctx, key, raw, b, ttl); err != nil || ok {
			return err
		}
	}
	return fmt.Errorf("ephemeral update of %s kept conflicting", key)
}

func (s *Engine) ephemIncr(ctx context.Context, key string, ttl time.Duration) (int64, error) {
	if !s.useEphemeralStore() {
		return 0, fmt.Errorf("ephemeral store unavailable")
	}
	return s.ephemeral.Incr(ctx, key, ttl)
}

func (s *Engine) ephemDel(ctx context.Context, key string) error {
	if !s.useEphemeralStore() {
		return fmt.Errorf("ephemeral store unavailable")
	}
	return s.ephemeral.Del(ctx, key)
}

// ClaimDPoPProof implements dpop.ReplayGuard using the configured shared
// ephemeral store. Replay keys have a fixed length and expire within 121s.
func (s *Engine) ClaimDPoPProof(ctx context.Context, key string, ttl time.Duration) (bool, error) {
	if len(key) != 43 || ttl <= 0 || ttl > 121*time.Second {
		return false, fmt.Errorf("invalid DPoP replay claim")
	}
	n, err := s.ephemIncr(ctx, "dpop:proof:"+key, ttl)
	return n == 1 && err == nil, err
}

const (
	keyOIDCState  = "oidc:state:"
	oidcStateTTL  = 15 * time.Minute
	keyOIDCResult = "oidc:result:" // +hash of the one-time code
	oidcResultTTL = 2 * time.Minute
)

// PutOIDCState records a pending browser login for the provider callback.
func (s *Engine) PutOIDCState(ctx context.Context, state string, data oidcstate.StateData) error {
	return s.ephemSetJSON(ctx, keyOIDCState+state, data, oidcStateTTL)
}

// ConsumeOIDCState claims a pending browser login once; concurrent callbacks
// cannot both win it.
func (s *Engine) ConsumeOIDCState(ctx context.Context, state string) (oidcstate.StateData, bool, error) {
	var d oidcstate.StateData
	ok, err := s.ephemConsumeJSON(ctx, keyOIDCState+state, &d)
	return d, ok, err
}

// PutOIDCResult keeps a browser OIDC result for its one-time code; the key is
// the code's hash, so the store never holds a usable code.
func (s *Engine) PutOIDCResult(ctx context.Context, code string, result json.RawMessage) error {
	return s.ephemSetJSON(ctx, keyOIDCResult+secret.Hash(code), result, oidcResultTTL)
}

// ConsumeOIDCResult trades a one-time code for its result, once.
func (s *Engine) ConsumeOIDCResult(ctx context.Context, code string) (json.RawMessage, bool, error) {
	var result json.RawMessage
	ok, err := s.ephemConsumeJSON(ctx, keyOIDCResult+secret.Hash(code), &result)
	return result, ok, err
}
