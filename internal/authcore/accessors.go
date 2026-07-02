package authcore

import (
	"context"
	"crypto"
	"fmt"
	"sort"
	"strings"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/open-rails/authkit/internal/db"
	jwtkit "github.com/open-rails/authkit/jwt"
	"github.com/open-rails/authkit/password"
)

// Plain accessors and small setters on Service: keys/JWKS, config, the DB pool
// and schema, and the verify-time Keyfunc. isDevEnvironment pairs a free
// function (pure logic on an env string, callable before a Service exists,
// e.g. from ephemeral.go/service_solana.go during options resolution) with a
// nil-safe Service method wrapper used everywhere else.

// JWKS returns a JWKS built from configured public keys.
func (s *Service) JWKS() jwtkit.JWKS {
	// Build a deterministic, sorted JWKS. For current RSA keysets, include alg
	// to make verifier policy and key intent explicit.
	ks := jwtkit.JWKS{Keys: make([]jwtkit.JWK, 0, len(s.keys.PublicKeys))}
	activeKID := ""
	activeAlg := ""
	if s.keys.Active != nil {
		activeKID = strings.TrimSpace(s.keys.Active.KID())
		activeAlg = strings.TrimSpace(s.keys.Active.Algorithm())
	}
	kids := make([]string, 0, len(s.keys.PublicKeys))
	for kid := range s.keys.PublicKeys {
		kids = append(kids, kid)
	}
	sort.Strings(kids)
	for _, kid := range kids {
		pub := s.keys.PublicKeys[kid]
		alg := activeAlg
		if strings.TrimSpace(kid) != activeKID || strings.TrimSpace(alg) == "" {
			alg = jwtkit.AlgorithmForPublicKey(pub)
		}
		ks.Keys = append(ks.Keys, jwtkit.PublicToJWK(pub, kid, alg))
	}
	return ks
}

// AdminSetPassword force-sets a user's password
// (admin only, no current password required)
func (s *Service) AdminSetPassword(ctx context.Context, userID, new string) error {
	if s.pg == nil {
		return fmt.Errorf("postgres not configured")
	}
	if strings.TrimSpace(userID) == "" {
		return fmt.Errorf("invalid_user")
	}
	if err := ValidatePassword(new); err != nil {
		return err
	}
	phc, err := password.HashArgon2id(new)
	if err != nil {
		return err
	}
	if err := s.upsertPasswordHash(ctx, userID, phc, "argon2id", nil); err != nil {
		return err
	}
	// Revoke all sessions for security
	ctx = WithSessionRevokeReason(ctx, SessionRevokeReasonAdminSetPassword)
	if err := s.RevokeAllSessions(ctx, userID, nil); err != nil {
		return err
	}
	return nil
}

func (s *Service) EntitlementsProvider() EntitlementsProvider {
	return s.entitlements
}

// --- Refresh tokens are implemented via server-side sessions in service_sessions.go ---

// Options exposes immutable configuration for callers that need to validate claims.
func (s *Service) Options() Options {
	return s.opts
}

// Config returns the host Config this Service was built from. The client-first
// HTTP transport reads it for HTTP-layer config (OIDC providers/descriptors) that
// rides in Config but the engine doesn't consume. Zero value for a Service built
// via NewService (config-less, e.g. some tests).
func (s *Service) Config() Config { return s.cfg }

// PublicKeysByKID returns the public keys indexed by key ID.
func (s *Service) PublicKeysByKID() map[string]crypto.PublicKey {
	return s.keys.PublicKeys
}

func (s *Service) isDevEnvironment() bool {
	if s == nil {
		return true
	}
	return isDevEnvironment(s.opts.Environment)
}

// Postgres returns the attached pgx pool (may be nil).
func (s *Service) Postgres() *pgxpool.Pool { return s.pg }

// Schema returns the Postgres schema AuthKit's tables live in ("profiles"
// unless configured otherwise via Config.Schema/Options.Schema).
func (s *Service) Schema() string { return s.dbSchema() }

// dbSchema returns the validated schema name, defaulting for zero-value
// Services (some tests construct Service{} directly).
func (s *Service) dbSchema() string {
	if s == nil || s.schema == "" {
		return db.DefaultSchema
	}
	return s.schema
}

// qtx returns Queries bound to tx with the service's schema rewrite applied.
// Always use this instead of s.qtx(tx): WithTx is sqlc-generated and
// wraps the raw tx, which would bypass the schema rewrite.
func (s *Service) qtx(tx pgx.Tx) *db.Queries {
	return db.New(db.ForSchema(tx, s.dbSchema()))
}

// SetEntitlementsProvider installs the entitlements provider AFTER construction.
//
// This is the ONE sanctioned post-construction setter — #108 otherwise removed
// every mutating builder in favor of constructor options. It exists for a
// genuine initialization CYCLE: an embedded billing engine (e.g. OpenRails)
// authenticates through this Service — it needs the Verifier/Core, so the
// Service must exist first — yet that same engine is the SOURCE of the
// entitlements provider, so the provider cannot exist at construction time. The
// host builds the Service, builds the engine with it, then installs the engine's
// provider here. Safe because entitlements are read LAZILY at token-mint time;
// call it during wiring, before serving requests. Hosts WITHOUT this cycle
// should prefer the WithEntitlements construction option instead.
func (s *Service) SetEntitlementsProvider(p EntitlementsProvider) { s.entitlements = p }

// Keyfunc looks up a public key by KID, falling back to the active key if missing.
func (s *Service) Keyfunc() func(token *jwt.Token) (any, error) {
	return func(token *jwt.Token) (any, error) {
		if kid, _ := token.Header["kid"].(string); kid != "" {
			if pub, ok := s.keys.PublicKeys[kid]; ok {
				return pub, nil
			}
		}
		if ps, ok := s.keys.Active.(jwtkit.PublicKeySigner); ok {
			if pub := ps.PublicKey(); pub != nil {
				return pub, nil
			}
		}
		return nil, jwt.ErrTokenUnverifiable
	}
}

// isDevEnvironment returns true unless the environment is explicitly set to prod/production
func isDevEnvironment(env string) bool {
	e := strings.ToLower(strings.TrimSpace(env))
	// Only production environments are considered non-dev
	if e == "prod" || e == "production" {
		return false
	}
	// Everything else (dev, development, local, staging, empty, etc.) is considered dev
	return true
}
