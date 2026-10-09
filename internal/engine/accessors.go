package engine

import (
	"context"
	"crypto"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/db"
	"github.com/open-rails/authkit/internal/jose"
	"github.com/open-rails/authkit/keys"
)

// Plain accessors and small setters on engine: keys/JWKS, config, the DB pool
// and schema, and the verify-time Keyfunc.

// JWKS publishes the CURRENT public keys, read from the KeySource on every
// call, so a rotation shows on the very next request (#238).
func (s *Engine) JWKS() keys.JWKS { return jose.JWKS(s.keys) }

// DelegationAuthorizer returns the host-injected delegated-token authorizer
// (#277), nil when none was wired.
func (s *Engine) DelegationAuthorizer() iam.DelegationAuthorizer {
	return s.delegationAuthorizer
}

// PublicKeysByKID returns the CURRENT public keys indexed by key ID, read
// fresh from the KeySource on every call (#238).
func (s *Engine) PublicKeysByKID() map[string]crypto.PublicKey {
	return s.keys.PublicKeys()
}

// SetClock replaces the engine clock of TTL and grace-window decisions, for
// AuthKit's own tests (internal/testclock); call it before the engine serves.
// Ephemeral state (codes, claims, counters) keeps the database clock.
func (s *Engine) SetClock(now func() time.Time) { s.now = now }

// nowTime is the engine clock (time.Now unless SetClock replaced it).
func (s *Engine) nowTime() time.Time {
	if s == nil || s.now == nil {
		return time.Now()
	}
	return s.now()
}

// Close stops what Start started and releases AuthKit-owned resources,
// including its schema-bound pool. ctx bounds stopping AuthKit's own River.
// Injected dependencies, including the host pool, a host River fleet, stores
// and keys, stay host-owned.
func (s *Engine) Close(ctx context.Context) error {
	if s == nil {
		return nil
	}
	s.closeOnce.Do(func() { s.closeErr = s.close(ctx) })
	return s.closeErr
}

func (s *Engine) close(ctx context.Context) error {
	s.stopSenderHealth()
	riverPool, err := s.closeRiver(ctx)
	if s.ownedKeySource != nil {
		s.ownedKeySource.Close()
		s.ownedKeySource = nil
	}
	// Keep database handles immutable: background last-used writes may still
	// be starting. pgxpool safely rejects work after Close; clearing the
	// handles instead races readers and can turn that error into a panic.
	pools := []*pgxpool.Pool{riverPool, s.pg}
	if s.ephemeral != nil {
		pools = append(pools, s.ephemeral.pool)
	}
	release := func() {
		for _, pool := range pools {
			if pool != nil {
				pool.Close()
			}
		}
	}
	if err != nil {
		go release() // ctx ended first: River's cancelled workers still hold connections
		return err
	}
	release()
	return nil
}

// dbSchema returns the validated schema name, defaulting for zero-value
// Services (some tests construct engine{} directly).
func (s *Engine) dbSchema() string {
	if s == nil || s.schema == "" {
		return db.DefaultSchema
	}
	return s.schema
}

// qtx returns Queries bound to a transaction. The transaction comes from
// AuthKit's schema-bound pool, so all generated SQL resolves in the configured
// namespace through that connection's search_path.
func (s *Engine) qtx(tx pgx.Tx) *db.Queries {
	return db.New(tx)
}
