package embedded

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
	"github.com/open-rails/authkit/oidckit"
)

// ephemeralKV is AuthKit's short-lived auth state in Postgres (ephemeral_kv):
// codes, tokens, ceremonies, OIDC/SIWS state and attempt counters. Every
// replica sees the same rows, and each operation is a single statement, so
// single-use claims and counters are atomic across the fleet. Expiry always
// uses the database clock (never Deps.Clock), so skewed replicas agree on
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

// purgeExpiredEphemeral deletes expired rows in bounded batches. It runs on
// the main pool so it never occupies the small pool live claims use.
func (s *engine) purgeExpiredEphemeral(ctx context.Context) (int64, error) {
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

func (s *engine) useEphemeralStore() bool {
	return s != nil && s.ephemeral != nil
}

func (s *engine) ephemSetJSON(ctx context.Context, key string, value any, ttl time.Duration) error {
	if !s.useEphemeralStore() {
		return fmt.Errorf("ephemeral store unavailable")
	}
	b, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return s.ephemeral.Set(ctx, key, b, ttl)
}

func (s *engine) ephemGetJSON(ctx context.Context, key string, out any) (bool, error) {
	_, ok, err := s.ephemReadJSON(ctx, key, out)
	return ok, err
}

// ephemReadJSON retains the exact bytes for a later conditional claim.
func (s *engine) ephemReadJSON(ctx context.Context, key string, out any) ([]byte, bool, error) {
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

func (s *engine) claimProof(ctx context.Context, key string, expected []byte) error {
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

func (s *engine) ephemSetString(ctx context.Context, key, value string, ttl time.Duration) error {
	if !s.useEphemeralStore() {
		return fmt.Errorf("ephemeral store unavailable")
	}
	return s.ephemeral.Set(ctx, key, []byte(value), ttl)
}

func (s *engine) ephemGetString(ctx context.Context, key string) (string, bool, error) {
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
func (s *engine) ephemConsumeJSON(ctx context.Context, key string, out any) (bool, error) {
	if !s.useEphemeralStore() {
		return false, fmt.Errorf("ephemeral store unavailable")
	}
	b, ok, err := s.ephemeral.Consume(ctx, key)
	if err != nil || !ok {
		return false, err
	}
	return true, json.Unmarshal(b, out)
}

func (s *engine) ephemConsumeString(ctx context.Context, key string) (string, bool, error) {
	if !s.useEphemeralStore() {
		return "", false, fmt.Errorf("ephemeral store unavailable")
	}
	b, ok, err := s.ephemeral.Consume(ctx, key)
	if err != nil || !ok {
		return "", ok, err
	}
	return string(b), true, nil
}

func (s *engine) ephemIncr(ctx context.Context, key string, ttl time.Duration) (int64, error) {
	if !s.useEphemeralStore() {
		return 0, fmt.Errorf("ephemeral store unavailable")
	}
	return s.ephemeral.Incr(ctx, key, ttl)
}

func (s *engine) ephemDel(ctx context.Context, key string) error {
	if !s.useEphemeralStore() {
		return fmt.Errorf("ephemeral store unavailable")
	}
	return s.ephemeral.Del(ctx, key)
}

// ClaimDPoPProof implements dpop.ReplayGuard using the configured shared
// ephemeral store. Replay keys have a fixed length and expire within 121s.
func (s *engine) ClaimDPoPProof(ctx context.Context, key string, ttl time.Duration) (bool, error) {
	if len(key) != 43 || ttl <= 0 || ttl > 121*time.Second {
		return false, fmt.Errorf("invalid DPoP replay claim")
	}
	n, err := s.ephemIncr(ctx, "dpop:proof:"+key, ttl)
	return n == 1 && err == nil, err
}

const (
	keyOIDCState = "oidc:state:"
	oidcStateTTL = 15 * time.Minute
)

// PutOIDCState records a pending browser login for the provider callback.
func (s *engine) PutOIDCState(ctx context.Context, state string, data oidckit.StateData) error {
	return s.ephemSetJSON(ctx, keyOIDCState+state, data, oidcStateTTL)
}

// ConsumeOIDCState claims a pending browser login once; concurrent callbacks
// cannot both win it.
func (s *engine) ConsumeOIDCState(ctx context.Context, state string) (oidckit.StateData, bool, error) {
	var d oidckit.StateData
	ok, err := s.ephemConsumeJSON(ctx, keyOIDCState+state, &d)
	return d, ok, err
}
