package authkit

import (
	"context"
	"crypto"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/open-rails/authkit/authprovider"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/db"
	"github.com/open-rails/authkit/internal/password"
	"github.com/open-rails/authkit/jwtkit"
)

// Plain accessors and small setters on engine: keys/JWKS, config, the DB pool
// and schema, and the verify-time Keyfunc.

// JWKS returns a JWKS built from the CURRENT public keys — read fresh from the
// KeySource on every call, so a rotation is reflected on the very next request
// (#238).
func (s *engine) JWKS() jwtkit.JWKS {
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
func (s *engine) AdminSetPassword(ctx context.Context, userID, new string) error {
	return s.changePassword(ctx, userID, new, nil, nil, nil, authflow.SessionRevokeReasonAdminSetPassword)
}

func (s *engine) EntitlementsProvider() EntitlementsProvider {
	return s.entitlementsProvider()
}

// DelegationAuthorizer returns the host-injected delegated-token authorizer
// (#277), nil when none was wired.
func (s *engine) DelegationAuthorizer() iam.DelegationAuthorizer {
	return s.delegationAuthorizer
}

// Config returns THE configuration (#237): the host Config, normalized once at
// construction. Both the engine and the HTTP transport read it — there is no
// parallel flat options struct (#236 bug class is structurally impossible).
func (s *engine) Config() Config { return s.cfg }

// PublicKeysByKID returns the CURRENT public keys indexed by key ID, read
// fresh from the KeySource on every call (#238).
func (s *engine) PublicKeysByKID() map[string]crypto.PublicKey {
	return s.keys.PublicKeys()
}

// nowTime is the engine clock (time.Now unless WithClock replaced it).
func (s *engine) nowTime() time.Time {
	if s == nil || s.now == nil {
		return time.Now()
	}
	return s.now()
}

// Postgres returns AuthKit's schema-bound pgx pool (may be nil). It is an
// AuthKit-owned clone of Deps.Postgres; callers must not close it directly.
func (s *engine) Postgres() *pgxpool.Pool { return s.pg }

// Close releases AuthKit-owned resources, including its schema-bound pool.
// Injected dependencies, including the host pool, stores and keys, stay host-owned.
func (s *engine) Close() {
	if s == nil {
		return
	}
	s.closeOnce.Do(s.close)
}

func (s *engine) close() {
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

// Schema returns the Postgres schema AuthKit's tables live in ("profiles"
// unless configured otherwise via Config.Schema).
func (s *engine) Schema() string { return s.dbSchema() }

// dbSchema returns the validated schema name, defaulting for zero-value
// Services (some tests construct engine{} directly).
func (s *engine) dbSchema() string {
	if s == nil || s.schema == "" {
		return db.DefaultSchema
	}
	return s.schema
}

// qtx returns Queries bound to a transaction. The transaction comes from
// AuthKit's schema-bound pool, so all generated SQL resolves in the configured
// namespace through that connection's search_path.
func (s *engine) qtx(tx pgx.Tx) *db.Queries {
	return db.New(tx)
}

// entitlementsBox lets a nil provider be stored atomically.
type entitlementsBox struct{ provider EntitlementsProvider }

func (s *engine) setEntitlements(p EntitlementsProvider) {
	s.entitlements.Store(&entitlementsBox{provider: p})
}

// entitlementsProvider is read on request paths, concurrently with
// Auth.SetEntitlements during wiring.
func (s *engine) entitlementsProvider() EntitlementsProvider {
	if b := s.entitlements.Load(); b != nil {
		return b.provider
	}
	return nil
}

// Settings derives the configuration the HTTP layer reads.
func (s *engine) Settings() authflow.Settings {
	c := s.cfg
	readers := make([]authflow.DocumentReader, 0, len(c.Documents.Readers))
	for _, r := range c.Documents.Readers {
		readers = append(readers, authflow.DocumentReader{ID: r.ID, Domain: r.Domain, Issuer: r.Issuer})
	}
	return authflow.Settings{
		Issuer:                   c.Token.Issuer,
		AccountIssuers:           append([]string(nil), c.Token.AccountIssuers...),
		ExpectedAudiences:        append([]string(nil), c.Token.ExpectedAudiences...),
		RefreshTokenDuration:     c.Token.RefreshTokenDuration,
		APIKeyPrefix:             c.APIKeys.Prefix,
		Schema:                   s.dbSchema(),
		RequireMFAEnrollment:     c.TwoFactor.Mode == iam.TwoFactorRequired,
		AllowPrivateNetworkJWKS:  c.Applications.AllowPrivateNetworkJWKS,
		ApplicationRegistration:  c.Applications.SelfRegistration,
		DeviceKeys:               c.DeviceKeys.Enabled,
		PasswordlessLogin:        c.Registration.PasswordlessLogin,
		SolanaNetwork:            c.SolanaNetwork,
		Providers:                append([]authprovider.Provider(nil), c.Identity.Providers...),
		FrontendBaseURL:          c.Frontend.BaseURL,
		OIDCReturnPath:           c.Frontend.OIDCReturnPath,
		RegistrationMode:         c.Registration.NativeUserMode,
		RegistrationVerification: c.Registration.Verification,
		Username:                 c.Username,
		Password:                 password.Policy(c.Password),
		Delegated: authflow.DelegatedSettings{
			Audiences:  append([]string(nil), c.Delegated.Audiences...),
			AllowDPoP:  c.Delegated.AllowDPoP,
			TTLFloor:   c.Delegated.TTLFloor,
			TTLDefault: c.Delegated.TTLDefault,
			TTLCeiling: c.Delegated.TTLCeiling,
		},
		Documents: authflow.DocumentSettings{Readers: readers, AllowRegisteredTier: c.Documents.AllowRegisteredTier},
	}
}
