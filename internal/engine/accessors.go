package engine

import (
	"crypto"
	"time"

	"github.com/jackc/pgx/v5"

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

// nowTime is the engine clock (time.Now unless WithClock replaced it).
func (s *Engine) nowTime() time.Time {
	if s == nil || s.now == nil {
		return time.Now()
	}
	return s.now()
}

// Close releases AuthKit-owned resources, including its schema-bound pool.
// Injected dependencies, including the host pool, stores and keys, stay host-owned.
func (s *Engine) Close() {
	if s == nil {
		return
	}
	s.closeOnce.Do(s.close)
}

func (s *Engine) close() {
	s.stopSMSHealth()
	s.closeRiver()
	if s.ownedKeySource != nil {
		s.ownedKeySource.Close()
		s.ownedKeySource = nil
	}
	if s.pg != nil {
		// Keep database handles immutable: background last-used writes may still
		// be starting. pgxpool safely rejects work after Close; clearing the
		// handles instead races readers and can turn that error into a panic.
		s.pg.Close()
	}
	if s.ephemeral != nil {
		s.ephemeral.pool.Close()
	}
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
