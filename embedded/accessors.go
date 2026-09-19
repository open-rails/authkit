package embedded

import (
	"context"
	"crypto"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/open-rails/authkit/internal/db"
	"github.com/open-rails/authkit/jwtkit"
)

// Plain accessors and small setters on Client: keys/JWKS, config, the DB pool
// and schema, and the verify-time Keyfunc.

// JWKS returns a JWKS built from the CURRENT public keys — read fresh from the
// KeySource on every call, so a rotation is reflected on the very next request
// (#238).
func (s *Client) JWKS() jwtkit.JWKS {
	active := s.keys.ActiveSigner()
	pubs := s.keys.PublicKeys()

	// Build a deterministic, sorted JWKS. For current RSA keysets, include alg
	// to make verifier policy and key intent explicit.
	ks := jwtkit.JWKS{Keys: make([]jwtkit.JWK, 0, len(pubs))}
	activeKID := ""
	activeAlg := ""
	if active != nil {
		activeKID = strings.TrimSpace(active.KID())
		activeAlg = strings.TrimSpace(active.Algorithm())
	}
	kids := make([]string, 0, len(pubs))
	for kid := range pubs {
		kids = append(kids, kid)
	}
	sort.Strings(kids)
	for _, kid := range kids {
		pub := pubs[kid]
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
func (s *Client) AdminSetPassword(ctx context.Context, userID, new string) error {
	return s.changePassword(ctx, userID, new, nil, nil, nil, SessionRevokeReasonAdminSetPassword)
}

func (s *Client) EntitlementsProvider() EntitlementsProvider {
	return s.entitlements
}

// DelegationAuthorizer returns the host-injected delegated-token authorizer
// (#277), nil when none was wired.
func (s *Client) DelegationAuthorizer() DelegationAuthorizer {
	return s.delegationAuthorizer
}

// Config returns THE configuration (#237): the host Config, normalized once at
// construction. Both the engine and the HTTP transport read it — there is no
// parallel flat options struct (#236 bug class is structurally impossible).
func (s *Client) Config() Config { return s.cfg }

// PublicKeysByKID returns the CURRENT public keys indexed by key ID, read
// fresh from the KeySource on every call (#238).
func (s *Client) PublicKeysByKID() map[string]crypto.PublicKey {
	return s.keys.PublicKeys()
}

// nowTime is the engine clock (time.Now unless WithClock replaced it).
func (s *Client) nowTime() time.Time {
	if s == nil || s.now == nil {
		return time.Now()
	}
	return s.now()
}

// Postgres returns AuthKit's schema-bound pgx pool (may be nil). It is an
// AuthKit-owned clone of Deps.Postgres; callers must not close it directly.
func (s *Client) Postgres() *pgxpool.Pool { return s.pg }

// Close releases AuthKit-owned resources, including its schema-bound pool.
// The pool supplied through Deps.Postgres remains owned by the host.
func (s *Client) Close() {
	if s != nil && s.pg != nil {
		s.pg.Close()
		s.pg = nil
		s.q = nil
	}
}

// Schema returns the Postgres schema AuthKit's tables live in ("profiles"
// unless configured otherwise via Config.Schema).
func (s *Client) Schema() string { return s.dbSchema() }

// dbSchema returns the validated schema name, defaulting for zero-value
// Services (some tests construct Client{} directly).
func (s *Client) dbSchema() string {
	if s == nil || s.schema == "" {
		return db.DefaultSchema
	}
	return s.schema
}

// qtx returns Queries bound to a transaction. The transaction comes from
// AuthKit's schema-bound pool, so all generated SQL resolves in the configured
// namespace through that connection's search_path.
func (s *Client) qtx(tx pgx.Tx) *db.Queries {
	return db.New(tx)
}

// SetEntitlementsProvider installs the entitlements provider AFTER construction.
//
// This is the ONE sanctioned post-construction setter — #108 otherwise removed
// every mutating builder in favor of constructor options. It exists for a
// genuine initialization CYCLE: an embedded billing engine (e.g. OpenRails)
// authenticates through this Client — it needs the Verifier/Core, so the
// Client must exist first — yet that same engine is the SOURCE of the
// entitlements provider, so the provider cannot exist at construction time. The
// host builds the Client, builds the engine with it, then installs the engine's
// provider here. Safe because entitlements are read LAZILY at token-mint time;
// call it during wiring, before serving requests. Hosts WITHOUT this cycle
// should set Deps.Entitlements instead.
func (s *Client) SetEntitlementsProvider(p EntitlementsProvider) { s.entitlements = p }
