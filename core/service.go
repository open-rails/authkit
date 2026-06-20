package core

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	stdlog "log"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/open-rails/authkit/internal/db"
	jwtkit "github.com/open-rails/authkit/jwt"
	authlang "github.com/open-rails/authkit/lang"
	"github.com/open-rails/authkit/password"
)

// Options configures issued tokens and identifiers.
type Options struct {
	Issuer               string
	IssuedAudiences      []string // JWT audiences - tokens issued will contain ALL of these audiences
	ExpectedAudiences    []string
	AccessTokenDuration  time.Duration
	RefreshTokenDuration time.Duration
	SessionMaxPerUser    int
	// Optional link building (paths are fixed: /reset and /verify)
	BaseURL string
	// FrontendCallbackPath is the host-owned frontend route that receives full-page OIDC login results.
	FrontendCallbackPath string
	// Schema is the Postgres schema AuthKit's tables live in. Empty defaults to
	// "profiles". Must match ^[a-z_][a-z0-9_]*$ (max 63 bytes); NewService
	// panics on an invalid non-empty value because a malformed name would be
	// spliced into SQL text (see internal/db.ForSchema). Prefer NewFromConfig,
	// which returns the validation error instead.
	Schema string
	// RegistrationVerification controls whether registration verification is disabled,
	// non-blocking, or required.
	RegistrationVerification RegistrationVerificationPolicy

	// VerificationSendTimeout bounds each in-line email/SMS provider send
	// (verification codes, password-reset links, login codes) so a configured
	// but misconfigured/unreachable provider cannot hang the request that
	// triggered it (e.g. registration). Empty/<=0 defaults to 15 seconds.
	VerificationSendTimeout time.Duration

	// AutoCreatePersonalOrgs creates a personal org for each native user at
	// signup (direct opt-in; authkit issue 60). False keeps native users
	// org-free by default.
	AutoCreatePersonalOrgs bool

	// NativeUserRegistrationMode controls public native-user self-registration.
	NativeUserRegistrationMode RegistrationMode
	// OrgRegistrationMode controls public org onboarding/management.
	OrgRegistrationMode RegistrationMode

	// Environment is host-provided runtime mode used for dev/prod behavior checks.
	Environment string
	// SolanaNetwork is host-provided chain selector for SIWS flows.
	SolanaNetwork string
	// SolanaSNSEnabled enables AuthKit-owned Solana Name Service resolution for SIWS-linked wallets.
	SolanaSNSEnabled bool
	// SolanaSNSResolver resolves a verified Solana wallet address to its primary .sol name.
	SolanaSNSResolver SolanaSNSResolver
	// SolanaSNSLookupTimeout bounds resolver calls. Empty defaults to 3 seconds.
	SolanaSNSLookupTimeout time.Duration
	// SolanaSNSCacheTTL controls when cached SNS metadata is considered stale. Empty defaults to 24 hours.
	SolanaSNSCacheTTL time.Duration

	// APIKeyPrefix is the issuing application's brand prefix for generated API
	// keys (validated lowercase-alnum, 1-16 chars; empty -> bare st_).
	APIKeyPrefix string
	// APIKeyMaxTTL caps a minted API key's expiry (0 = no cap).
	APIKeyMaxTTL time.Duration
	// ResourceScopeAuthorizer optionally authorizes host-defined API-key resource
	// scopes during HTTP minting. Nil means AuthKit stores valid scopes
	// opaquely for callers who may manage API keys for the org.
	ResourceScopeAuthorizer ResourceScopeAuthorizer
	// Permissions is the app's permission vocabulary (merged with authkit's
	// base `org:` permissions). DefaultRoles are role templates seeded per org.
	Permissions  []PermissionDef
	DefaultRoles []DefaultRole
}

// Keyset holds the active signer and the public keys exposed via JWKS.
type Keyset struct {
	Active     jwtkit.Signer
	PublicKeys map[string]crypto.PublicKey // kid -> pub
}

// EntitlementsProvider returns the names of a user's currently active
// application entitlements (e.g., billing tiers). Names are the ONLY shape
// AuthKit consumes — they are baked verbatim into the `entitlements` claim of
// access tokens and surfaced on admin user views. Providers should return
// active grants only; expired/revoked entitlements are the provider's concern,
// not AuthKit's.
type EntitlementsProvider interface {
	ListEntitlements(ctx context.Context, userID string) ([]string, error)
}

// BatchEntitlementsProvider is an optional upgrade of EntitlementsProvider:
// one call answers many users, so list renders (AdminListUsers) cost one
// provider round trip instead of one per row. Detected by type assertion;
// providers without it get the per-user fallback. Unknown user ids may be
// absent from the result.
type BatchEntitlementsProvider interface {
	ListEntitlementsBatch(ctx context.Context, userIDs []string) (map[string][]string, error)
}

// EntitlementFilterProvider is the REVERSE of EntitlementsProvider: given an
// entitlement key, it returns the subject ids that currently hold it. AuthKit
// owns the user DIRECTORY; the billing system (OpenRails) owns "who is entitled",
// so filtering the directory BY entitlement delegates here instead of joining
// across schemas. Subject ids ARE user ids (UUID-only payable identity). Detected
// by type assertion on the entitlements provider; when absent, AdminListUsers
// with an Entitlement filter fails with ErrEntitlementFilterUnavailable so the
// misconfiguration is loud rather than silently returning everyone.
type EntitlementFilterProvider interface {
	ListSubjectsWithEntitlement(ctx context.Context, entitlement string) ([]string, error)
}

// HashAlgoLegacyResetRequired marks profiles.user_passwords rows migrated from
// legacy systems whose stored hashes can never verify (DES crypt, md5-crypt,
// corrupted values). The raw legacy hash is preserved in password_hash for
// forensics only; the sole way forward for these accounts is a password reset.
const HashAlgoLegacyResetRequired = "legacy-reset-required"

var (
	// ErrUserBanned indicates the account is blocked from authenticating.
	ErrUserBanned = errors.New("user_banned")
	// ErrPasswordResetRequired indicates the account's stored password hash is
	// flagged HashAlgoLegacyResetRequired: no plaintext can ever verify against
	// it, so the user must complete a password reset before password auth (login,
	// reauth, change-password) can succeed. HTTP layers map this to the stable
	// code "password_reset_required".
	ErrPasswordResetRequired = errors.New("password_reset_required")
	// ErrUserNotFound indicates a user does not exist (or is not visible).
	ErrUserNotFound = errors.New("user_not_found")
	// ErrEmailAlreadyVerified indicates an email verification request targeted an already-verified email.
	ErrEmailAlreadyVerified = errors.New("email_already_verified")
	// ErrPhoneAlreadyVerified indicates a phone verification request targeted an already-verified phone.
	ErrPhoneAlreadyVerified = errors.New("phone_already_verified")
	// ErrPendingRegistrationNotFound indicates a registration resend request did not match a pending registration.
	ErrPendingRegistrationNotFound = errors.New("pending_registration_not_found")
	// ErrRegistrationDisabled indicates a public user-creation path was attempted
	// while native-user registration is bootstrap-only. Existing-user
	// authentication is unaffected; only NEW account creation through
	// public/auto-registration is blocked.
	ErrRegistrationDisabled = errors.New("registration_disabled")
	// ErrVerificationLinkExpired indicates a verification link/token no longer has a pending verification record.
	ErrVerificationLinkExpired = errors.New("verification_link_expired")
	// ErrOrgManagementDisabled indicates a public org onboarding/management path
	// was attempted while org registration is bootstrap-only. Embedded
	// bootstrap/admin core APIs remain available.
	ErrOrgManagementDisabled = errors.New("org_management_disabled")
)

const defaultFrontendCallbackPath = "/login/callback"

// (storage layer collapsed into direct Postgres/Redis helpers)

// Service is the core auth service used by HTTP adapters.
type Service struct {
	opts           Options
	keys           Keyset
	email          EmailSender
	sms            SMSSender
	pg             *pgxpool.Pool
	q              *db.Queries
	schema         string // validated Postgres schema name; db.DefaultSchema when unset
	entitlements   EntitlementsProvider
	authlog        AuthEventLogger
	ephemeralStore EphemeralStore
	ephemeralMode  EphemeralMode
	verifyWarnOnce sync.Once

	// SMS deliverability health, populated by CheckSMSHealth. Until a check has
	// run, SMS is considered available whenever a sender is configured (legacy
	// behavior). Once a check runs, phone flows gate on the result.
	smsHealthChecked atomic.Bool
	smsHealthy       atomic.Bool
	smsHealthReason  atomic.Value // string
}

func NewService(opts Options, keys Keyset) *Service {
	if mode, err := normalizeRegistrationMode(opts.NativeUserRegistrationMode); err == nil {
		opts.NativeUserRegistrationMode = mode
	}
	if mode, err := normalizeRegistrationMode(opts.OrgRegistrationMode); err == nil {
		opts.OrgRegistrationMode = mode
	}
	if strings.TrimSpace(opts.FrontendCallbackPath) == "" {
		opts.FrontendCallbackPath = defaultFrontendCallbackPath
	}
	opts.APIKeyPrefix = strings.TrimSpace(opts.APIKeyPrefix)
	schema := strings.TrimSpace(opts.Schema)
	if schema == "" {
		schema = db.DefaultSchema
	}
	if !db.ValidSchemaName(schema) {
		// A malformed schema name would be spliced into SQL text; refusing to
		// construct the service is the injection guard for the Options path
		// (NewFromConfig returns this as an error instead).
		panic(fmt.Sprintf("authkit: invalid Schema %q (want lowercase identifier matching ^[a-z_][a-z0-9_]*$, max 63 bytes)", opts.Schema))
	}
	opts.Schema = schema
	return &Service{opts: opts, keys: keys, schema: schema, ephemeralMode: EphemeralMemory}
}

// NewFromConfig creates a Service from high-level Config + Stores.
// If Keys is nil, auto-discovers keys from environment variables, filesystem, or generates development keys.
func NewFromConfig(cfg Config) (*Service, error) {
	// Handle nil Keys - auto-discover from env vars, <KeysPath>/keys.json, or
	// generate for dev. The filesystem directory is host-overridable via
	// cfg.KeysPath, then the AUTHKIT_KEYS_PATH env var, defaulting to
	// /vault/auth so existing embedders are unchanged.
	keySource := cfg.Keys
	if keySource == nil && cfg.VerifyOnly {
		// #87: explicit verify-only — NO signer and NO key discovery. Minting
		// returns ErrMissingSigner; verification, RBAC reads, and the (empty)
		// JWKS endpoint all work. A pure resource-server / control-plane boots
		// without any env/file/dev key.
		keySource = jwtkit.StaticKeySource{}
	}
	if keySource == nil {
		keysPath := strings.TrimSpace(cfg.KeysPath)
		if keysPath == "" {
			keysPath = strings.TrimSpace(os.Getenv("AUTHKIT_KEYS_PATH"))
		}
		var err error
		keySource, err = jwtkit.NewAutoKeySourceWithPath(keysPath)
		if err != nil {
			return nil, fmt.Errorf("authkit: failed to auto-discover JWT keys: %w", err)
		}
	}

	ks := Keyset{Active: keySource.ActiveSigner(), PublicKeys: keySource.PublicKeys()}

	// Require critical JWT configuration.
	issuer := strings.TrimSpace(cfg.Issuer)
	if issuer == "" {
		return nil, fmt.Errorf("authkit: Issuer is required (e.g., \"https://myapp.com\")")
	}
	baseURL := strings.TrimSpace(cfg.BaseURL)
	issuerIsURL := isWellFormattedURL(issuer)
	if !issuerIsURL {
		stdlog.Printf("authkit: warning: Issuer is not a well-formatted URL: %q", issuer)
	}
	if baseURL == "" {
		if issuerIsURL {
			baseURL = issuer
		} else {
			return nil, fmt.Errorf("authkit: BaseURL is required when Issuer is not a well-formatted URL (issuer=%q)", issuer)
		}
	}
	frontendCallbackPath, err := normalizeFrontendCallbackPath(cfg.FrontendCallbackPath)
	if err != nil {
		return nil, err
	}

	issuedAudiences := cfg.IssuedAudiences
	if len(issuedAudiences) == 0 {
		return nil, fmt.Errorf("authkit: IssuedAudiences is required (e.g., []string{\"myapp\", \"billing-app\"})")
	}
	expectedAudiences := cfg.ExpectedAudiences
	if len(expectedAudiences) == 0 {
		return nil, fmt.Errorf("authkit: ExpectedAudiences is required (e.g., []string{\"myapp\"})")
	}

	maxSess := cfg.SessionMaxPerUser
	if maxSess == 0 {
		maxSess = 3
	}
	accessTTL := cfg.AccessTokenDuration
	if accessTTL == 0 {
		// Short default bounds revocation lag (logout / ban / password-change)
		// to one TTL window; refresh-token rotation re-issues silently. See
		// authkit #90 — we deliberately rely on this bound instead of a
		// per-request jti/liveness lookup.
		accessTTL = 15 * time.Minute
	}
	refTTL := cfg.RefreshTokenDuration // 0 or less => indefinite sessions

	registrationVerification, err := normalizeRegistrationVerification(cfg.RegistrationVerification)
	if err != nil {
		return nil, err
	}
	nativeUserRegistrationMode, err := normalizeRegistrationMode(cfg.NativeUserRegistrationMode)
	if err != nil {
		return nil, fmt.Errorf("authkit: invalid NativeUserRegistrationMode %q (want one of: open, invite_only, admin_only, admin_bootstrap_only, closed)", cfg.NativeUserRegistrationMode)
	}
	orgRegistrationMode, err := normalizeRegistrationMode(cfg.OrgRegistrationMode)
	if err != nil {
		return nil, fmt.Errorf("authkit: invalid OrgRegistrationMode %q (want one of: open, invite_only, admin_only, admin_bootstrap_only, manifest_only, closed)", cfg.OrgRegistrationMode)
	}
	tokenPrefix := strings.TrimSpace(cfg.APIKeyPrefix)
	if !validAPIKeyPrefix(tokenPrefix) {
		return nil, fmt.Errorf("authkit: invalid APIKeyPrefix %q (want lowercase alphanumeric, 1-16 chars, or empty)", tokenPrefix)
	}
	maxTTL := cfg.APIKeyMaxTTL
	schema := strings.TrimSpace(cfg.Schema)
	if schema == "" {
		schema = db.DefaultSchema
	}
	if !db.ValidSchemaName(schema) {
		return nil, fmt.Errorf("authkit: invalid Schema %q (want lowercase identifier matching ^[a-z_][a-z0-9_]*$, max 63 bytes)", cfg.Schema)
	}
	opts := Options{
		Issuer:                     issuer,
		IssuedAudiences:            issuedAudiences,
		ExpectedAudiences:          expectedAudiences,
		AccessTokenDuration:        accessTTL,
		RefreshTokenDuration:       refTTL,
		SessionMaxPerUser:          maxSess,
		BaseURL:                    baseURL,
		FrontendCallbackPath:       frontendCallbackPath,
		Schema:                     schema,
		RegistrationVerification:   registrationVerification,
		AutoCreatePersonalOrgs:     cfg.AutoCreatePersonalOrgs,
		NativeUserRegistrationMode: nativeUserRegistrationMode,
		OrgRegistrationMode:        orgRegistrationMode,
		Environment:                strings.TrimSpace(cfg.Environment),
		SolanaNetwork:              strings.TrimSpace(cfg.SolanaNetwork),
		SolanaSNSEnabled:           cfg.SolanaSNSEnabled,
		SolanaSNSResolver:          cfg.SolanaSNSResolver,
		SolanaSNSLookupTimeout:     cfg.SolanaSNSLookupTimeout,
		SolanaSNSCacheTTL:          cfg.SolanaSNSCacheTTL,
		APIKeyPrefix:               tokenPrefix,
		APIKeyMaxTTL:               maxTTL,
		ResourceScopeAuthorizer:    cfg.ResourceScopeAuthorizer,
		Permissions:                cfg.Permissions,
		DefaultRoles:               cfg.DefaultRoles,
	}
	return NewService(opts, ks), nil
}

// validAPIKeyPrefix reports whether p is an acceptable API-key application prefix:
// empty (-> bare st_) or 1-16 lowercase alphanumeric characters.
func validAPIKeyPrefix(p string) bool {
	if p == "" {
		return true
	}
	if len(p) > 16 {
		return false
	}
	for _, r := range p {
		if !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')) {
			return false
		}
	}
	return true
}

func normalizeRegistrationVerification(v RegistrationVerificationPolicy) (RegistrationVerificationPolicy, error) {
	value := RegistrationVerificationPolicy(strings.ToLower(strings.TrimSpace(string(v))))
	if value == "" {
		return RegistrationVerificationRequired, nil
	}
	switch value {
	case RegistrationVerificationNone, RegistrationVerificationOptional, RegistrationVerificationRequired:
		return value, nil
	default:
		return "", fmt.Errorf("authkit: invalid RegistrationVerification %q (want \"none\", \"optional\", or \"required\")", v)
	}
}

func normalizeRegistrationMode(v RegistrationMode) (RegistrationMode, error) {
	value := RegistrationMode(strings.ToLower(strings.TrimSpace(string(v))))
	if value == "" {
		return RegistrationModeOpen, nil
	}
	switch value {
	case RegistrationModeOpen,
		RegistrationModeInviteOnly,
		RegistrationModeAdminOnly,
		RegistrationModeAdminBootstrapOnly,
		RegistrationModeManifestOnly,
		RegistrationModeClosed:
		return value, nil
	default:
		return "", fmt.Errorf("invalid_registration_mode")
	}
}

func normalizeFrontendCallbackPath(raw string) (string, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return defaultFrontendCallbackPath, nil
	}
	if strings.Contains(value, "#") {
		return "", fmt.Errorf("authkit: FrontendCallbackPath must not contain a fragment")
	}
	u, err := url.Parse(value)
	if err != nil {
		return "", fmt.Errorf("authkit: invalid FrontendCallbackPath %q: %w", raw, err)
	}
	if u.IsAbs() || u.Host != "" || strings.HasPrefix(value, "//") {
		return "", fmt.Errorf("authkit: FrontendCallbackPath must be a relative absolute-path, got %q", raw)
	}
	if u.Path == "" || !strings.HasPrefix(u.Path, "/") {
		return "", fmt.Errorf("authkit: FrontendCallbackPath must start with '/', got %q", raw)
	}
	if u.Fragment != "" {
		return "", fmt.Errorf("authkit: FrontendCallbackPath must not contain a fragment")
	}
	return u.RequestURI(), nil
}

func (o Options) RegistrationVerificationPolicy() RegistrationVerificationPolicy {
	v, err := normalizeRegistrationVerification(o.RegistrationVerification)
	if err != nil {
		return RegistrationVerificationNone
	}
	return v
}

func (o Options) RegistrationVerificationRequired() bool {
	return o.RegistrationVerificationPolicy() == RegistrationVerificationRequired
}

func (o Options) RegistrationVerificationEnabled() bool {
	return o.RegistrationVerificationPolicy() != RegistrationVerificationNone
}

func (o Options) AutoCreatePersonalOrgsEnabled() bool {
	return o.AutoCreatePersonalOrgs
}

// PublicNativeUserRegistrationEnabled reports whether public native-user
// self-registration / auto-registration is allowed.
func (o Options) PublicNativeUserRegistrationEnabled() bool {
	mode, err := normalizeRegistrationMode(o.NativeUserRegistrationMode)
	return err == nil && mode == RegistrationModeOpen
}

// PublicOrgRegistrationEnabled reports whether public org onboarding /
// management HTTP routes are allowed.
func (o Options) PublicOrgRegistrationEnabled() bool {
	mode, err := normalizeRegistrationMode(o.OrgRegistrationMode)
	return err == nil && mode == RegistrationModeOpen
}

func isWellFormattedURL(raw string) bool {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	if strings.TrimSpace(u.Scheme) == "" || strings.TrimSpace(u.Host) == "" {
		return false
	}
	return true
}

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

// IssueAccessToken builds and signs an access token (JWT) for the given user.
// Includes core registered claims plus:
// - entitlements (authoritative short-lived snapshot)
// Extra claims in `extra` are merged into the token body (e.g., sid).
func (s *Service) IssueAccessToken(ctx context.Context, userID, email string, extra map[string]any) (token string, expiresAt time.Time, err error) {
	_ = email // kept for API compatibility; profile claims no longer ride in access tokens.
	base := jwtkit.BaseRegisteredClaims(userID, s.opts.IssuedAudiences, s.opts.AccessTokenDuration)
	expiresAt = base.ExpiresAt.Time
	// Platform/org authority is no longer carried as a token claim: the legacy
	// `global_roles`/`roles` plane was hard-cut in favor of Layer-2 platform RBAC
	// (profiles.platform_roles + platform:* perms), which is resolved at request
	// time from the DB, not snapshotted into the access token.
	var ents []string
	if s.entitlements != nil {
		var entErr error
		ents, entErr = s.entitlements.ListEntitlements(ctx, userID)
		if entErr != nil {
			// Deliberate availability-over-consistency: a failing entitlements
			// provider must not block login, but it must be LOUD — the user is
			// getting a token without entitlement claims (no premium access)
			// until the next refresh.
			stdlog.Printf("authkit: error: entitlements provider failed during access-token issuance for user %s; token issued WITHOUT entitlement claims: %v", userID, entErr)
			ents = nil
		}
	}
	// Keep the live-user gate even though profile fields no longer ride in the
	// token: banned/deleted users must not receive fresh access tokens.
	if s.pg != nil {
		u, uErr := s.getUserByID(ctx, userID)
		if uErr != nil {
			return "", time.Time{}, uErr
		}
		if u == nil {
			return "", time.Time{}, jwt.ErrTokenInvalidClaims
		}
		if err := s.ensureUserAccess(ctx, u); err != nil {
			return "", time.Time{}, err
		}
	}

	claims := map[string]any{
		"iss":          s.opts.Issuer,
		"sub":          base.Subject,
		"aud":          base.Audience,
		"iat":          base.IssuedAt.Time.Unix(),
		"exp":          base.ExpiresAt.Time.Unix(),
		"entitlements": ents,
	}
	for k, v := range extra {
		claims[k] = v
	}
	if s.keys.Active == nil {
		return "", time.Time{}, ErrMissingSigner // #87: verify-only Service cannot mint
	}
	hs, ok := s.keys.Active.(jwtkit.HeaderSigner)
	if !ok {
		return "", time.Time{}, errors.New("header signer required")
	}
	tok, err := hs.SignWithHeaders(ctx, claims, map[string]any{"typ": jwtkit.AccessTokenType})
	return tok, expiresAt, err
}

// --- Refresh tokens are implemented via server-side sessions in service_sessions.go ---

// Options exposes immutable configuration for callers that need to validate claims.
func (s *Service) Options() Options {
	return s.opts
}

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

// WithPostgres attaches a pgx pool to the service. The pool is shared with the
// host; AuthKit never mutates it (in particular it never sets search_path —
// queries stay schema-qualified, rewritten to s.Schema() when non-default).
func (s *Service) WithPostgres(pool *pgxpool.Pool) *Service {
	s.pg = pool
	s.q = db.New(db.ForSchema(pool, s.dbSchema()))
	// (issue 60) No org-mode downgrade safeguard: orgs are always supported,
	// so there is no single/multi mode to refuse a downgrade into.
	return s
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

// WithEntitlements sets the entitlements provider.
func (s *Service) WithEntitlements(p EntitlementsProvider) *Service { s.entitlements = p; return s }

// WithAuthLogger sets the authentication event logger (e.g., ClickHouse sink).
func (s *Service) WithAuthLogger(l AuthEventLogger) *Service { s.authlog = l; return s }

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

// RequestPhoneChange initiates a phone number change by sending a verification code to the new phone.
// The current phone is NOT changed until the user confirms via ConfirmPhoneChange.
func (s *Service) RequestPhoneChange(ctx context.Context, userID, newPhone string) error {
	if s.pg == nil {
		return fmt.Errorf("postgres not configured")
	}

	if err := ValidatePhone(newPhone); err != nil {
		return err
	}
	trimmed := NormalizePhone(newPhone)

	// Get user
	u, err := s.getUserByID(ctx, userID)
	if err != nil {
		return err
	}
	if u == nil {
		return fmt.Errorf("user not found")
	}

	// Check if trying to change to the same phone
	if u.PhoneNumber != nil && strings.EqualFold(*u.PhoneNumber, trimmed) {
		return fmt.Errorf("new phone is the same as current phone")
	}

	// Check if new phone is already in use by another user
	existing, _ := s.getUserByPhone(ctx, trimmed)
	if existing != nil && existing.ID != userID {
		return fmt.Errorf("phone already in use")
	}

	// Generate manual code + link token.
	code := randAlphanumeric(6)
	codeHash := sha256Hex(code)
	linkToken := randB64(32)
	linkHash := sha256Hex(linkToken)

	// Hold the new phone in the unified pending-change store with split TTLs. The
	// new phone is applied to the profile only on confirmation — we do not
	// optimistically pre-apply it. That keeps the user's current phone intact if
	// the change is never confirmed (or is cancelled), so cancellation is a clean
	// delete of this record with nothing to roll back.
	if err := s.storePendingChange(ctx, pendingChange{
		Kind:   KindChangePhone,
		Target: trimmed,
		UserID: userID,
	}, map[string]time.Duration{
		codeHash: defaultPhoneVerificationTTL,
		linkHash: defaultPhoneVerificationTTL,
	}); err != nil {
		return err
	}

	msg := VerificationMessage{Code: code, LinkToken: linkToken}

	// Send verification message to new phone
	if s.sms != nil {
		sendCtx := s.contextWithUserPreferredLocale(ctx, userID)
		if err := s.withSendTimeout(sendCtx, func(sendCtx context.Context) error { return s.sms.SendVerification(sendCtx, trimmed, msg) }); err != nil {
			return smsDeliveryError(err)
		}
	} else if !s.isDevEnvironment() {
		return fmt.Errorf("phone change verification unavailable: SMS sender not configured")
	}

	// Optionally: notify old phone (not implemented)

	return nil
}

// ConfirmPhoneChange verifies the code and updates the user's phone number.
// This is called when the user enters the verification code sent to their new phone.
func (s *Service) ConfirmPhoneChange(ctx context.Context, userID, phone, code string) error {
	if s.pg == nil || !s.useEphemeralStore() {
		return jwt.ErrTokenUnverifiable
	}

	// Load the pending change by the code's hash; validate kind, owner, and (when
	// the caller supplied a phone) that it matches the pending target.
	hash := sha256Hex(code)
	rec, ok, err := s.loadPendingChangeByToken(ctx, hash)
	if err != nil || !ok || rec.Kind != KindChangePhone {
		return jwt.ErrTokenUnverifiable
	}
	if rec.UserID != userID {
		return jwt.ErrTokenInvalidClaims
	}
	if strings.TrimSpace(phone) != "" && !strings.EqualFold(NormalizePhone(phone), rec.Target) {
		return jwt.ErrTokenUnverifiable
	}

	if _, err := s.finalizeChangePhone(ctx, rec); err != nil {
		return err
	}
	s.deletePendingChangeByToken(ctx, hash)
	return nil
}

// ResendPhoneChangeCode resends the verification code for a pending phone change.
func (s *Service) ResendPhoneChangeCode(ctx context.Context, userID, phone string) error {
	// Get current user
	u, err := s.getUserByID(ctx, userID)
	if err != nil {
		return err
	}
	if u == nil {
		return fmt.Errorf("user not found")
	}

	// The unified pending-change record (keyed by user) is the source of truth for
	// whether a phone change is pending for this user.
	rec, ok := s.findPendingChangeByUser(ctx, KindChangePhone, userID)
	if !ok {
		return fmt.Errorf("no pending phone change found")
	}
	pendingPhone := rec.Target

	// Generate new verification credentials; storePendingChange supersedes the old record.
	code := randAlphanumeric(6)
	codeHash := sha256Hex(code)
	linkToken := randB64(32)
	linkHash := sha256Hex(linkToken)
	if err := s.storePendingChange(ctx, pendingChange{
		Kind:   KindChangePhone,
		Target: pendingPhone,
		UserID: userID,
	}, map[string]time.Duration{
		codeHash: defaultPhoneVerificationTTL,
		linkHash: defaultPhoneVerificationTTL,
	}); err != nil {
		return err
	}

	msg := VerificationMessage{Code: code, LinkToken: linkToken}
	// Send new credentials.
	if s.sms != nil {
		sendCtx := s.contextWithUserPreferredLocale(ctx, userID)
		if err := s.withSendTimeout(sendCtx, func(sendCtx context.Context) error { return s.sms.SendVerification(sendCtx, pendingPhone, msg) }); err != nil {
			return smsDeliveryError(err)
		}
	} else if !s.isDevEnvironment() {
		return fmt.Errorf("phone change verification unavailable: SMS sender not configured")
	}

	return nil
}

// CancelPhoneChange aborts a pending phone-change for the user, clearing the
// unified pending-change record. Because the new phone is held only in the
// pending record and never optimistically applied to the profile, there is
// nothing to roll back. Idempotent: a no-op when no pending change exists.
func (s *Service) CancelPhoneChange(ctx context.Context, userID, phone string) error {
	if !s.useEphemeralStore() {
		return nil
	}
	s.deletePendingChangeByUser(ctx, KindChangePhone, userID)
	return nil
}

// getUserByPhone returns a user by phone number (if any)
func (s *Service) getUserByPhone(ctx context.Context, phone string) (*User, error) {
	if s.pg == nil {
		return nil, nil
	}
	r, err := s.q.UserByPhone(ctx, &phone)
	if err != nil {
		return nil, err
	}
	return userFromByPhoneRow(r), nil
}

// setPhoneVerified sets the phone_verified flag for a user.
func (s *Service) setPhoneVerified(ctx context.Context, id string, v bool) error {
	if s.pg == nil {
		return nil
	}
	return s.q.UserSetPhoneVerifiedByID(ctx, db.UserSetPhoneVerifiedByIDParams{ID: id, PhoneVerified: &v})
}

// SendPhone2FASetupCode generates and sends a 6-digit code for 2FA setup to the user's phone.
func (s *Service) SendPhone2FASetupCode(ctx context.Context, userID, phone, code string) error {
	hash := sha256Hex(code)
	// Store code in ephemeral store for 10 minutes, purpose: "2fa_setup"
	if s.useEphemeralStore() {
		if err := s.storePhoneVerification(ctx, "2fa_setup", phone, userID, hash, 10*time.Minute); err != nil {
			return err
		}
	} else {
		return fmt.Errorf("ephemeral store not configured")
	}

	if s.sms != nil {
		msg := VerificationMessage{Code: code}
		sendCtx := s.contextWithUserPreferredLocale(ctx, userID)
		return smsDeliveryError(s.withSendTimeout(sendCtx, func(sendCtx context.Context) error { return s.sms.SendVerification(sendCtx, phone, msg) }))
	}
	// In production, require SMS to be configured
	if !s.isDevEnvironment() {
		return fmt.Errorf("SMS sender not configured")
	}
	return nil
}

// VerifyPhone2FASetupCode checks the code for 2FA phone setup.
func (s *Service) VerifyPhone2FASetupCode(ctx context.Context, userID, phone, code string) (bool, error) {
	hash := sha256Hex(code)
	if s.useEphemeralStore() {
		uid, err := s.consumePhoneVerification(ctx, "2fa_setup", phone, hash)
		if err != nil {
			return false, err
		}
		if uid != userID {
			return false, fmt.Errorf("user_id mismatch")
		}
		return true, nil
	}
	return false, fmt.Errorf("ephemeral store not configured")
}

// PasswordLogin verifies credentials and issues an ID token.
func (s *Service) PasswordLogin(ctx context.Context, email, pass string, extra map[string]any) (string, time.Time, error) {
	if s.pg == nil {
		return "", time.Time{}, jwt.ErrTokenUnverifiable
	}
	u, err := s.getUserByEmail(ctx, email)
	if err != nil || u == nil {
		return "", time.Time{}, errOrUnauthorized(err)
	}
	if err := s.ensureUserAccess(ctx, u); err != nil {
		return "", time.Time{}, err
	}
	hash, algo, _, err := s.getPasswordHash(ctx, u.ID)
	if err != nil {
		return "", time.Time{}, errOrUnauthorized(err)
	}
	// Support legacy bcrypt with lazy rehash to Argon2id on successful login.
	switch algo {
	case HashAlgoLegacyResetRequired:
		return "", time.Time{}, ErrPasswordResetRequired
	case "argon2id":
		ok, err := password.VerifyArgon2id(hash, pass)
		if err != nil || !ok {
			return "", time.Time{}, errOrUnauthorized(err)
		}
	case "bcrypt", "":
		// Some legacy rows may have empty algo but bcrypt formatted hash ($2b$...) — accept those too.
		if !password.IsBcryptHash(hash) && algo == "" {
			return "", time.Time{}, errOrUnauthorized(nil)
		}
		ok, err := password.VerifyBcrypt(hash, pass)
		if err != nil || !ok {
			return "", time.Time{}, errOrUnauthorized(err)
		}
		// Rehash to Argon2id and upsert
		phc, err := password.HashArgon2id(pass)
		if err == nil {
			_ = s.upsertPasswordHash(ctx, u.ID, phc, "argon2id", nil)
		}
	default:
		return "", time.Time{}, errOrUnauthorized(nil)
	}
	_ = s.setLastLogin(ctx, u.ID, time.Now())
	emailStr := ""
	if u.Email != nil {
		emailStr = *u.Email
	}
	return s.IssueAccessToken(ctx, u.ID, emailStr, extra)
}

// PasswordLoginByUserID verifies credentials for a specific user ID and issues an ID token.
// This supports login flows where the identifier is a phone number or username and email may be NULL.
func (s *Service) PasswordLoginByUserID(ctx context.Context, userID, pass string, extra map[string]any) (string, time.Time, error) {
	if s.pg == nil {
		return "", time.Time{}, jwt.ErrTokenUnverifiable
	}
	if strings.TrimSpace(userID) == "" {
		return "", time.Time{}, jwt.ErrTokenInvalidClaims
	}
	u, err := s.getUserByID(ctx, userID)
	if err != nil || u == nil {
		return "", time.Time{}, errOrUnauthorized(err)
	}
	if err := s.ensureUserAccess(ctx, u); err != nil {
		return "", time.Time{}, err
	}
	hash, algo, _, err := s.getPasswordHash(ctx, u.ID)
	if err != nil {
		return "", time.Time{}, errOrUnauthorized(err)
	}
	switch algo {
	case HashAlgoLegacyResetRequired:
		return "", time.Time{}, ErrPasswordResetRequired
	case "argon2id":
		ok, err := password.VerifyArgon2id(hash, pass)
		if err != nil || !ok {
			return "", time.Time{}, errOrUnauthorized(err)
		}
	case "bcrypt", "":
		if !password.IsBcryptHash(hash) && algo == "" {
			return "", time.Time{}, errOrUnauthorized(nil)
		}
		ok, err := password.VerifyBcrypt(hash, pass)
		if err != nil || !ok {
			return "", time.Time{}, errOrUnauthorized(err)
		}
		// Rehash to Argon2id and upsert
		phc, err := password.HashArgon2id(pass)
		if err == nil {
			_ = s.upsertPasswordHash(ctx, u.ID, phc, "argon2id", nil)
		}
	default:
		return "", time.Time{}, errOrUnauthorized(nil)
	}
	_ = s.setLastLogin(ctx, u.ID, time.Now())
	emailStr := ""
	if u.Email != nil {
		emailStr = *u.Email
	}
	return s.IssueAccessToken(ctx, u.ID, emailStr, extra)
}

func errOrUnauthorized(err error) error {
	if err != nil {
		return err
	}
	return jwt.ErrTokenInvalidClaims
}

// VerifyUserPassword checks a user's password without issuing tokens or updating last-login.
// Returns true if the password is correct, false otherwise.
func (s *Service) VerifyUserPassword(ctx context.Context, userID, pass string) bool {
	return s.CheckUserPassword(ctx, userID, pass) == nil
}

// CheckUserPassword is the error-returning form of VerifyUserPassword: nil on
// success, ErrPasswordResetRequired when the stored hash is flagged
// HashAlgoLegacyResetRequired (no plaintext can verify; the user must reset),
// and a generic unauthorized error otherwise. Callers that need to route
// reset-required users (reauth, change-password) should use this form.
func (s *Service) CheckUserPassword(ctx context.Context, userID, pass string) error {
	if s.pg == nil || strings.TrimSpace(userID) == "" {
		return errOrUnauthorized(nil)
	}
	hash, algo, _, err := s.getPasswordHash(ctx, userID)
	if err != nil {
		return errOrUnauthorized(err)
	}
	switch algo {
	case HashAlgoLegacyResetRequired:
		return ErrPasswordResetRequired
	case "argon2id":
		ok, err := password.VerifyArgon2id(hash, pass)
		if err != nil || !ok {
			return errOrUnauthorized(err)
		}
		return nil
	case "bcrypt", "":
		if !password.IsBcryptHash(hash) && algo == "" {
			return errOrUnauthorized(nil)
		}
		ok, err := password.VerifyBcrypt(hash, pass)
		if err == nil && ok {
			// Rehash to Argon2id opportunistically
			if phc, hErr := password.HashArgon2id(pass); hErr == nil {
				_ = s.upsertPasswordHash(ctx, userID, phc, "argon2id", nil)
			}
			return nil
		}
		return errOrUnauthorized(err)
	default:
		return errOrUnauthorized(nil)
	}
}

// ChangePassword sets or changes a user's password.
// If the user already has a password, current must verify; otherwise current is ignored.
// Always Argon2id-hashes the new password and upserts it, then revokes all
// other sessions for the user; caller may keep one active session via keepSessionID.
func (s *Service) ChangePassword(ctx context.Context, userID, current, new string, keepSessionID *string) error {
	if s.pg == nil {
		return jwt.ErrTokenUnverifiable
	}
	if strings.TrimSpace(userID) == "" {
		return fmt.Errorf("invalid_user")
	}
	if err := ValidatePassword(new); err != nil {
		return err
	}
	// If a password exists, verify current
	hadPassword := s.hasPassword(ctx, userID)
	if hadPassword {
		hash, algo, _, err := s.getPasswordHash(ctx, userID)
		if err != nil {
			return err
		}
		switch algo {
		case HashAlgoLegacyResetRequired:
			// The current password can never verify against a reset-required
			// hash; the user must go through the password-reset flow instead.
			return ErrPasswordResetRequired
		case "argon2id":
			ok, err := password.VerifyArgon2id(hash, current)
			if err != nil || !ok {
				return jwt.ErrTokenInvalidClaims
			}
		case "bcrypt", "":
			if !password.IsBcryptHash(hash) && algo == "" {
				return jwt.ErrTokenInvalidClaims
			}
			ok, err := password.VerifyBcrypt(hash, current)
			if err != nil || !ok {
				return jwt.ErrTokenInvalidClaims
			}
		default:
			return jwt.ErrTokenInvalidClaims
		}
	}
	// Hash and store new password
	phc, err := password.HashArgon2id(new)
	if err != nil {
		return err
	}
	if err := s.upsertPasswordHash(ctx, userID, phc, "argon2id", nil); err != nil {
		return err
	}
	// Revoke all other sessions after a successful password change to ensure that
	// any previously compromised refresh tokens are invalidated. The current
	// session can be preserved via keepSessionID if provided.
	ctx = WithSessionRevokeReason(ctx, SessionRevokeReasonPasswordChange)
	if err := s.RevokeAllSessions(ctx, userID, keepSessionID); err != nil {
		return err
	}
	sessionID := ""
	if keepSessionID != nil {
		sessionID = *keepSessionID
	}
	s.LogPasswordChanged(ctx, userID, sessionID, nil, nil)
	return nil
}

func (s *Service) SetPasswordAfterFreshAuth(ctx context.Context, userID, new string, keepSessionID *string) error {
	if s.pg == nil {
		return jwt.ErrTokenUnverifiable
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
	ctx = WithSessionRevokeReason(ctx, SessionRevokeReasonPasswordChange)
	if err := s.RevokeAllSessions(ctx, userID, keepSessionID); err != nil {
		return err
	}
	sessionID := ""
	if keepSessionID != nil {
		sessionID = *keepSessionID
	}
	s.LogPasswordChanged(ctx, userID, sessionID, nil, nil)
	return nil
}

type VerificationMessage struct {
	// Fixed-length numeric code for manual entry (optional).
	Code string
	// High-entropy token for one-click verification link flow (optional).
	LinkToken string
}

func (m VerificationMessage) Validate() error {
	if strings.TrimSpace(m.Code) == "" && strings.TrimSpace(m.LinkToken) == "" {
		return fmt.Errorf("verification message must contain at least one of code or link token")
	}
	return nil
}

var (
	ErrEmailDeliveryFailed = errors.New("email_delivery_failed")
	ErrSMSDeliveryFailed   = errors.New("sms_delivery_failed")
)

// EmailSender sends verification/login/reset emails.
type EmailSender interface {
	SendVerification(ctx context.Context, email, username string, msg VerificationMessage) error
	SendPasswordResetLink(ctx context.Context, email, username, token string) error
	SendLoginCode(ctx context.Context, email, username, code string) error
	SendWelcome(ctx context.Context, email, username string) error
}

// SMSSender sends verification/login/reset SMS messages.
type SMSSender interface {
	SendVerification(ctx context.Context, phone string, msg VerificationMessage) error
	SendPasswordResetLink(ctx context.Context, phone, token string) error
	SendLoginCode(ctx context.Context, phone, code string) error
}

// SMSHealthChecker is an optional capability for SMS senders that can verify,
// without sending a message, that they are configured to actually deliver
// (valid credentials, an attached sender, and a verified/registered number).
// CheckHealth returns nil when delivery is expected to succeed, or a
// descriptive error explaining why it will not (e.g. an unverified toll-free
// sender that would otherwise fail silently with Twilio error 30032).
type SMSHealthChecker interface {
	CheckHealth(ctx context.Context) error
}

// WithEmailSender sets the email sender dependency.
func (s *Service) WithEmailSender(sender EmailSender) *Service { s.email = sender; return s }

// WithSMSSender sets the SMS sender dependency.
func (s *Service) WithSMSSender(sender SMSSender) *Service { s.sms = sender; return s }

// HasEmailSender returns true if an email sender is configured.
func (s *Service) HasEmailSender() bool { return s.email != nil }

// HasSMSSender returns true if an SMS sender is configured.
func (s *Service) HasSMSSender() bool { return s.sms != nil }

// CheckSMSHealth probes whether the configured SMS sender can actually deliver,
// without sending a message, when the sender implements SMSHealthChecker. The
// result is cached and gates phone-based flows via SMSAvailable. It returns the
// probe error (nil = healthy) so callers can log it. When no sender is
// configured or the sender cannot self-check, it records healthy=true (delivery
// readiness is then governed solely by sender presence, as before).
func (s *Service) CheckSMSHealth(ctx context.Context) error {
	if s == nil {
		return nil
	}
	checker, ok := s.sms.(SMSHealthChecker)
	if s.sms == nil || !ok {
		s.smsHealthy.Store(true)
		s.smsHealthReason.Store("")
		s.smsHealthChecked.Store(true)
		return nil
	}
	err := checker.CheckHealth(ctx)
	if err != nil {
		s.smsHealthy.Store(false)
		s.smsHealthReason.Store(err.Error())
	} else {
		s.smsHealthy.Store(true)
		s.smsHealthReason.Store("")
	}
	s.smsHealthChecked.Store(true)
	return err
}

// SMSHealthy reports the last CheckSMSHealth result. It is true until a check
// has run (legacy behavior: assume healthy when a sender is present).
func (s *Service) SMSHealthy() bool {
	if s == nil {
		return false
	}
	if !s.smsHealthChecked.Load() {
		return true
	}
	return s.smsHealthy.Load()
}

// SMSHealthReason returns the reason SMS was last found unhealthy, if any.
func (s *Service) SMSHealthReason() string {
	if s == nil {
		return ""
	}
	if r, ok := s.smsHealthReason.Load().(string); ok {
		return r
	}
	return ""
}

// SMSAvailable reports whether phone-based flows should be offered: a sender is
// configured and (if a health check has run) it was found able to deliver.
func (s *Service) SMSAvailable() bool {
	return s.HasSMSSender() && s.SMSHealthy()
}

func emailDeliveryError(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%w: %w", ErrEmailDeliveryFailed, err)
}

func smsDeliveryError(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%w: %w", ErrSMSDeliveryFailed, err)
}

// ValidateVerificationConfiguration ensures registration verification policy
// can be satisfied by currently configured delivery senders.
func (s *Service) ValidateVerificationConfiguration() error {
	if s == nil {
		return nil
	}
	policy := s.opts.RegistrationVerificationPolicy()
	hasVerificationSender := s.email != nil || s.sms != nil

	if policy == RegistrationVerificationRequired && !hasVerificationSender {
		return fmt.Errorf("authkit: registration verification policy is %q but no email or SMS sender is configured", RegistrationVerificationRequired)
	}

	if !hasVerificationSender {
		s.verifyWarnOnce.Do(func() {
			stdlog.Printf("authkit: warning: no email or SMS sender configured; verification delivery is disabled")
		})
	}
	return nil
}

// RequestPasswordReset creates a password reset token and dispatches a reset link via email.
// Returns nil for unknown emails to prevent user enumeration (202-like behavior).
func (s *Service) RequestPasswordReset(ctx context.Context, email string, ttl time.Duration, ip *string, ua *string) error {
	if s.pg == nil {
		return nil
	}
	u, err := s.getUserByEmail(ctx, email)
	if err != nil || u == nil {
		return nil
	}
	if ttl <= 0 {
		ttl = time.Hour
	}

	token := randB64(32)
	hash := sha256Hex(token)
	if err := s.createResetToken(ctx, u.ID, hash, time.Now().Add(ttl)); err != nil {
		// Internal error, but do not reveal anything about whether user exists.
		return err
	}

	if u.Email == nil {
		return nil
	}
	username := ""
	if u.Username != nil {
		username = *u.Username
	}

	if s.email == nil {
		if !s.isDevEnvironment() {
			return fmt.Errorf("email password reset unavailable: email sender not configured")
		}
		return nil
	}

	sendCtx := s.contextWithUserPreferredLocale(ctx, u.ID)
	if err := s.withSendTimeout(sendCtx, func(sendCtx context.Context) error {
		return s.email.SendPasswordResetLink(sendCtx, *u.Email, username, token)
	}); err != nil {
		return emailDeliveryError(err)
	}

	s.LogPasswordRecovery(ctx, u.ID, "email", "", ip, ua)

	return nil
}

// BeginPasswordReset validates and consumes a password reset token, then issues a
// short-lived one-time reset session for browser handoff.
func (s *Service) BeginPasswordReset(ctx context.Context, token string, sessionTTL time.Duration) (string, error) {
	if s.pg == nil {
		return "", jwt.ErrTokenUnverifiable
	}
	rt, err := s.useResetToken(ctx, sha256Hex(token))
	if err != nil {
		return "", err
	}
	if sessionTTL <= 0 {
		sessionTTL = 15 * time.Minute
	}
	resetSession := randB64(32)
	if err := s.storePasswordResetSession(ctx, sha256Hex(resetSession), rt.UserID, sessionTTL); err != nil {
		return "", err
	}
	return resetSession, nil
}

// ConfirmPasswordResetWithSession consumes a reset session and sets the new password.
func (s *Service) ConfirmPasswordResetWithSession(ctx context.Context, resetSession, newPassword string) (string, error) {
	if s.pg == nil {
		return "", jwt.ErrTokenUnverifiable
	}
	userID, err := s.consumePasswordResetSession(ctx, sha256Hex(resetSession))
	if err != nil {
		return "", err
	}
	phc, err := password.HashArgon2id(newPassword)
	if err != nil {
		return "", err
	}
	if err := s.upsertPasswordHash(ctx, userID, phc, "argon2id", nil); err != nil {
		return "", err
	}
	// Revoke all sessions to invalidate any potentially compromised refresh tokens.
	_ = s.RevokeAllSessions(ctx, userID, nil)
	s.LogPasswordChanged(ctx, userID, "", nil, nil)

	return userID, nil
}

// ConfirmPasswordReset verifies token and sets a new password.
func (s *Service) ConfirmPasswordReset(ctx context.Context, token, newPassword string) (string, error) {
	resetSession, err := s.BeginPasswordReset(ctx, token, 15*time.Minute)
	if err != nil {
		return "", err
	}
	return s.ConfirmPasswordResetWithSession(ctx, resetSession, newPassword)
}

// RequestEmailVerification creates a verification code and dispatches an email.
func (s *Service) RequestEmailVerification(ctx context.Context, email string, ttl time.Duration) error {
	email = NormalizeEmail(email)
	if err := ValidateEmail(email); err != nil {
		return err
	}
	if s.pg != nil {
		u, err := s.getUserByEmail(ctx, email)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if u != nil {
			return s.sendEmailVerificationToUser(ctx, u, ttl)
		}
	}

	if pending, err := s.GetPendingRegistrationByEmail(ctx, email); err == nil && pending != nil {
		_, err := s.CreatePendingRegistrationWithLocale(ctx, email, pending.Username, pending.PasswordHash, ttl, pending.PreferredLocale)
		return err
	}
	if s.pg == nil {
		return s.requirePG()
	}
	return ErrUserNotFound
}

func (s *Service) sendEmailVerificationToUser(ctx context.Context, u *User, ttl time.Duration) error {
	if u == nil {
		return ErrUserNotFound
	}
	if u.EmailVerified {
		return ErrEmailAlreadyVerified
	}
	if ttl <= 0 {
		ttl = defaultEmailVerificationTTL
	}
	if u.Email == nil {
		return ErrUserNotFound
	}
	code := randAlphanumeric(6)
	codeHash := sha256Hex(code)
	linkToken := randB64(32)
	linkTokenHash := sha256Hex(linkToken)
	if err := s.storeEmailVerificationTokens(ctx, u.ID, u.Email, map[string]time.Duration{
		codeHash:      ttl,
		linkTokenHash: defaultEmailVerificationTTL,
	}); err != nil {
		return nil
	}
	username := ""
	if u.Username != nil {
		username = *u.Username
	}
	msg := VerificationMessage{Code: code, LinkToken: linkToken}
	if err := msg.Validate(); err != nil {
		return nil
	}
	if s.email != nil {
		sendCtx := s.contextWithUserPreferredLocale(ctx, u.ID)
		if err := s.withSendTimeout(sendCtx, func(sendCtx context.Context) error { return s.email.SendVerification(sendCtx, *u.Email, username, msg) }); err != nil {
			return emailDeliveryError(err)
		}
	} else if !s.isDevEnvironment() {
		return fmt.Errorf("email verification unavailable: email sender not configured")
	}
	return nil
}

// ConfirmEmailVerification verifies a token and marks email_verified = true.
// Returns the userID of the verified user.
func (s *Service) ConfirmEmailVerification(ctx context.Context, token string) (userID string, err error) {
	if s.pg == nil {
		return "", jwt.ErrTokenUnverifiable
	}
	rec, err := s.useEmailVerifyToken(ctx, sha256Hex(token))
	if err != nil {
		return "", err
	}
	// Ensure the token verifies the same email currently on the account.
	// Backward-compat: if the stored email is NULL (old tokens), accept as account-level verify.
	u, err := s.getUserByID(ctx, rec.UserID)
	if err != nil || u == nil {
		return "", errOrUnauthorized(err)
	}
	if rec.Email != nil && u.Email != nil && !strings.EqualFold(*u.Email, *rec.Email) {
		// Email changed since request; treat token as consumed but invalid for current address
		return "", jwt.ErrTokenInvalidClaims
	}
	err = s.setEmailVerified(ctx, rec.UserID, true)
	if err != nil {
		return "", err
	}
	return rec.UserID, nil
}

// --- Pending Registration (for email/password signups) ---

// CreatePendingRegistration creates a pending registration and sends verification email.
// Returns token for verification. Allows duplicate pending registrations (last one wins).
func (s *Service) CreatePendingRegistration(ctx context.Context, email, username, passwordHash string, ttl time.Duration) (string, error) {
	return s.CreatePendingRegistrationWithLocale(ctx, email, username, passwordHash, ttl, "")
}

func (s *Service) CreatePendingRegistrationWithLocale(ctx context.Context, email, username, passwordHash string, ttl time.Duration, preferredLocale string) (string, error) {
	if !s.opts.PublicNativeUserRegistrationEnabled() {
		return "", ErrRegistrationDisabled
	}
	locale, err := NormalizePreferredLocale(preferredLocale)
	if err != nil {
		return "", err
	}
	sendCtx := contextWithPreferredLocale(ctx, locale)
	switch s.opts.RegistrationVerificationPolicy() {
	case RegistrationVerificationNone:
		userID, err := s.createEmailRegistrationUser(ctx, email, username, passwordHash, true)
		if err != nil {
			return "", err
		}
		if locale != "" {
			if err := s.SetPreferredLocale(ctx, userID, locale, "registration"); err != nil {
				return "", err
			}
		}
		return "", nil
	case RegistrationVerificationOptional:
		verified := s.email == nil
		userID, err := s.createEmailRegistrationUser(ctx, email, username, passwordHash, verified)
		if err != nil {
			return "", err
		}
		if locale != "" {
			if err := s.SetPreferredLocale(ctx, userID, locale, "registration"); err != nil {
				return "", err
			}
		}
		if verified {
			return "", nil
		}
		if ttl <= 0 {
			ttl = defaultEmailVerificationTTL
		}
		code := randAlphanumeric(6)
		codeHash := sha256Hex(code)
		linkToken := randB64(32)
		linkHash := sha256Hex(linkToken)
		normEmail := normalizeEmail(email)
		if err := s.storeEmailVerificationTokens(ctx, userID, &normEmail, map[string]time.Duration{
			codeHash: ttl,
			linkHash: defaultEmailVerificationTTL,
		}); err != nil {
			return "", err
		}
		msg := VerificationMessage{Code: code, LinkToken: linkToken}
		if err := msg.Validate(); err == nil {
			if err := s.withSendTimeout(sendCtx, func(sendCtx context.Context) error {
				return s.email.SendVerification(sendCtx, normEmail, username, msg)
			}); err != nil {
				return "", emailDeliveryError(err)
			}
		}
		return code, nil
	default:
		if ttl <= 0 {
			ttl = defaultEmailVerificationTTL
		}
		code := randAlphanumeric(6)
		codeHash := sha256Hex(code)
		linkToken := randB64(32)
		linkHash := sha256Hex(linkToken)

		if s.useEphemeralStore() {
			if err := s.storePendingChange(ctx, pendingChange{
				Kind:            KindRegisterEmail,
				Target:          email,
				Username:        username,
				PasswordHash:    passwordHash,
				PreferredLocale: locale,
			}, map[string]time.Duration{
				codeHash: ttl,
				linkHash: defaultEmailVerificationTTL,
			}); err != nil {
				return "", err
			}
		} else {
			return "", fmt.Errorf("ephemeral store not configured")
		}

		msg := VerificationMessage{Code: code, LinkToken: linkToken}
		if err := msg.Validate(); err == nil {
			if s.email != nil {
				if err := s.withSendTimeout(sendCtx, func(sendCtx context.Context) error { return s.email.SendVerification(sendCtx, email, username, msg) }); err != nil {
					return "", emailDeliveryError(err)
				}
			} else if !s.isDevEnvironment() {
				return "", fmt.Errorf("registration verification unavailable: email sender not configured")
			}
		}

		return code, nil
	}
}

// ConfirmPendingRegistration verifies token and creates the actual user account.
// This implements "first to verify wins" - whoever verifies first gets the username/email.
func (s *Service) ConfirmPendingRegistration(ctx context.Context, token string) (userID string, err error) {
	if !s.opts.PublicNativeUserRegistrationEnabled() {
		return "", ErrRegistrationDisabled
	}
	if !s.useEphemeralStore() {
		return "", jwt.ErrTokenUnverifiable
	}
	// The register_email finalizer enforces "first to verify wins", creates the
	// verified user, and applies locale + personal org; consume deletes the
	// pending record on success.
	return s.consumePendingChangeByToken(ctx, sha256Hex(token), KindRegisterEmail)
}

// CheckPendingRegistrationConflict checks if email or username exists in users or pending registration cache.
// Returns (emailTaken, usernameTaken, error)
func (s *Service) CheckPendingRegistrationConflict(ctx context.Context, email, username string) (bool, bool, error) {
	var emailTaken, usernameTaken bool
	email = NormalizeEmail(email)
	username = strings.TrimSpace(username)
	if s.pg != nil {
		taken, err := s.q.UserEmailOrUsernameTaken(ctx, db.UserEmailOrUsernameTakenParams{Email: email, Username: username})
		if err != nil {
			return false, false, err
		}
		emailTaken, usernameTaken = taken.EmailTaken, taken.UsernameTaken
	}

	if emailTaken || usernameTaken {
		return emailTaken, usernameTaken, nil
	}

	if s.useEphemeralStore() {
		if s.pendingChangeTargetTaken(ctx, KindRegisterEmail, email) {
			emailTaken = true
		}
		if s.pendingChangeUsernameTaken(ctx, username) {
			usernameTaken = true
		}
	}
	return emailTaken, usernameTaken, nil
}

// --- Phone Registration (for phone+password signups) ---

// CreatePendingPhoneRegistration creates a pending phone registration and sends SMS verification code.
// Returns 6-digit code for verification. Code expires in 10 minutes (shorter than email).
func (s *Service) CreatePendingPhoneRegistration(ctx context.Context, phone, username, passwordHash string) (string, error) {
	return s.CreatePendingPhoneRegistrationWithLocale(ctx, phone, username, passwordHash, "")
}

func (s *Service) CreatePendingPhoneRegistrationWithLocale(ctx context.Context, phone, username, passwordHash, preferredLocale string) (string, error) {
	if !s.opts.PublicNativeUserRegistrationEnabled() {
		return "", ErrRegistrationDisabled
	}
	locale, err := NormalizePreferredLocale(preferredLocale)
	if err != nil {
		return "", err
	}
	sendCtx := contextWithPreferredLocale(ctx, locale)
	switch s.opts.RegistrationVerificationPolicy() {
	case RegistrationVerificationNone:
		userID, err := s.createPhoneRegistrationUser(ctx, phone, username, passwordHash, true)
		if err != nil {
			return "", err
		}
		if locale != "" {
			if err := s.SetPreferredLocale(ctx, userID, locale, "registration"); err != nil {
				return "", err
			}
		}
		return "", nil
	case RegistrationVerificationOptional:
		verified := s.sms == nil
		userID, err := s.createPhoneRegistrationUser(ctx, phone, username, passwordHash, verified)
		if err != nil {
			return "", err
		}
		if locale != "" {
			if err := s.SetPreferredLocale(ctx, userID, locale, "registration"); err != nil {
				return "", err
			}
		}
		if verified {
			return "", nil
		}
		code := randAlphanumeric(6)
		codeHash := sha256Hex(code)
		linkToken := randB64(32)
		linkHash := sha256Hex(linkToken)
		if err := s.storePhoneVerificationTokens(ctx, "verify_phone", phone, userID, map[string]time.Duration{
			codeHash: defaultPhoneVerificationTTL,
			linkHash: defaultPhoneVerificationTTL,
		}); err != nil {
			return "", err
		}
		msg := VerificationMessage{Code: code, LinkToken: linkToken}
		if err := msg.Validate(); err == nil {
			if err := s.withSendTimeout(sendCtx, func(sendCtx context.Context) error { return s.sms.SendVerification(sendCtx, phone, msg) }); err != nil {
				return "", smsDeliveryError(err)
			}
		}
		return code, nil
	default:
		code := randAlphanumeric(6)
		codeHash := sha256Hex(code)
		linkToken := randB64(32)
		linkHash := sha256Hex(linkToken)
		if s.useEphemeralStore() {
			if err := s.storePendingChange(ctx, pendingChange{
				Kind:            KindRegisterPhone,
				Target:          phone,
				Username:        username,
				PasswordHash:    passwordHash,
				PreferredLocale: locale,
			}, map[string]time.Duration{
				codeHash: defaultPhoneVerificationTTL,
				linkHash: defaultPhoneVerificationTTL,
			}); err != nil {
				return "", err
			}
		} else {
			return "", fmt.Errorf("ephemeral store not configured")
		}

		msg := VerificationMessage{Code: code, LinkToken: linkToken}
		if err := msg.Validate(); err == nil {
			if s.sms != nil {
				if err := s.withSendTimeout(sendCtx, func(sendCtx context.Context) error { return s.sms.SendVerification(sendCtx, phone, msg) }); err != nil {
					return "", smsDeliveryError(err)
				}
			} else {
				if !s.isDevEnvironment() {
					return "", fmt.Errorf("SMS verification unavailable: SMS sender not configured (phone registration requires SMS in production)")
				}
			}
		}

		return code, nil
	}
}

// ConfirmPendingPhoneRegistration verifies code and creates the actual user account.
// Implements "first to verify wins" - whoever verifies first gets the username/phone.
func (s *Service) ConfirmPendingPhoneRegistration(ctx context.Context, phone, code string) (userID string, err error) {
	if !s.opts.PublicNativeUserRegistrationEnabled() {
		return "", ErrRegistrationDisabled
	}
	if !s.useEphemeralStore() {
		return "", jwt.ErrTokenUnverifiable
	}
	hash := sha256Hex(code)

	// If a phone was supplied (manual-code path), ensure it matches the pending
	// target before finalizing. The link-token path passes an empty phone.
	if strings.TrimSpace(phone) != "" {
		rec, ok, err := s.loadPendingChangeByToken(ctx, hash)
		if err != nil || !ok || rec.Kind != KindRegisterPhone {
			return "", jwt.ErrTokenUnverifiable
		}
		if !strings.EqualFold(NormalizePhone(strings.TrimSpace(phone)), rec.Target) {
			return "", jwt.ErrTokenUnverifiable
		}
	}

	// The register_phone finalizer enforces "first to verify wins", creates the
	// verified user, and applies locale; consume deletes on success.
	return s.consumePendingChangeByToken(ctx, hash, KindRegisterPhone)
}

// ConfirmPendingPhoneRegistrationByToken verifies a pending phone registration
// using either a manual code or a high-entropy link token.
func (s *Service) ConfirmPendingPhoneRegistrationByToken(ctx context.Context, token string) (string, error) {
	return s.ConfirmPendingPhoneRegistration(ctx, "", token)
}

// CheckPhoneRegistrationConflict checks if phone or username exists in users OR pending tables.
// Returns (phoneTaken, usernameTaken, error)
func (s *Service) CheckPhoneRegistrationConflict(ctx context.Context, phone, username string) (bool, bool, error) {
	var phoneTaken, usernameTaken bool
	phone = NormalizePhone(phone)
	username = strings.TrimSpace(username)

	if s.pg != nil {
		taken, err := s.q.UserPhoneOrUsernameTaken(ctx, db.UserPhoneOrUsernameTakenParams{Phone: phone, Username: username})
		if err != nil {
			return false, false, err
		}
		phoneTaken, usernameTaken = taken.PhoneTaken, taken.UsernameTaken
	}

	if phoneTaken || usernameTaken {
		return phoneTaken, usernameTaken, nil
	}

	if s.useEphemeralStore() {
		if s.pendingChangeTargetTaken(ctx, KindRegisterPhone, phone) {
			phoneTaken = true
		}
		if s.pendingChangeUsernameTaken(ctx, username) {
			usernameTaken = true
		}
		return phoneTaken, usernameTaken, nil
	}
	return phoneTaken, usernameTaken, nil
}

// GetUserByPhone looks up a user by phone number.
func (s *Service) GetUserByPhone(ctx context.Context, phone string) (*User, error) {
	if s.pg == nil {
		return nil, nil
	}
	r, err := s.q.UserByPhone(ctx, &phone)
	if err != nil {
		return nil, err
	}
	u := userFromByPhoneRow(r)
	// Match the historical narrow projection of this lookup: banned_until,
	// ban_reason, and banned_by were not selected here.
	u.BannedUntil, u.BanReason, u.BannedBy = nil, nil, nil
	return u, nil
}

// --- Phone Verification (for existing users with unverified phones) ---

// RequestPhoneVerification looks up the user by phone number and sends a verification code.
// This mirrors the RequestEmailVerification pattern - caller only needs to provide the phone number.
func (s *Service) RequestPhoneVerification(ctx context.Context, phone string, ttl time.Duration) error {
	phone = NormalizePhone(phone)
	if err := ValidatePhone(phone); err != nil {
		return err
	}
	if s.pg != nil {
		u, err := s.GetUserByPhone(ctx, phone)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if u != nil {
			if u.PhoneVerified {
				return ErrPhoneAlreadyVerified
			}
			if u.PhoneNumber == nil {
				return ErrUserNotFound
			}
			return s.SendPhoneVerificationToUser(ctx, *u.PhoneNumber, u.ID, ttl)
		}
	}

	if pending, err := s.GetPendingPhoneRegistrationByPhone(ctx, phone); err == nil && pending != nil {
		_, err := s.CreatePendingPhoneRegistrationWithLocale(ctx, phone, pending.Username, pending.PasswordHash, pending.PreferredLocale)
		return err
	}
	if s.pg == nil {
		return s.requirePG()
	}
	return ErrUserNotFound
}

// SendPhoneVerificationToUser creates a verification code and sends it via SMS to a known user.
// Use RequestPhoneVerification if you only have a phone number and need to look up the user.
// Always returns nil for security.
func (s *Service) SendPhoneVerificationToUser(ctx context.Context, phone, userID string, ttl time.Duration) error {
	if ttl <= 0 {
		ttl = defaultPhoneVerificationTTL
	}

	// Generate a numeric code for manual entry + a high-entropy link token.
	code := randAlphanumeric(6)
	codeHash := sha256Hex(code)
	linkToken := randB64(32)
	linkHash := sha256Hex(linkToken)
	if s.useEphemeralStore() {
		if err := s.storePhoneVerificationTokens(ctx, "verify_phone", phone, userID, map[string]time.Duration{
			codeHash: ttl,
			linkHash: defaultPhoneVerificationTTL,
		}); err != nil {
			return nil
		}
	} else {
		return nil
	}

	msg := VerificationMessage{Code: code, LinkToken: linkToken}
	if err := msg.Validate(); err != nil {
		return nil
	}

	// Send SMS
	if s.sms != nil {
		sendCtx := s.contextWithUserPreferredLocale(ctx, userID)
		if err := s.withSendTimeout(sendCtx, func(sendCtx context.Context) error { return s.sms.SendVerification(sendCtx, phone, msg) }); err != nil {
			return smsDeliveryError(err)
		}
	} else {
		// In production, require SMS to be configured
		if !s.isDevEnvironment() {
			return fmt.Errorf("SMS verification unavailable: SMS sender not configured (phone verification requires SMS in production)")
		}
	}

	return nil
}

// ConfirmPhoneVerification verifies a token and marks phone_verified = true.
func (s *Service) ConfirmPhoneVerification(ctx context.Context, phone, code string) error {
	_, err := s.ConfirmPhoneVerificationUserID(ctx, phone, code)
	return err
}

// ConfirmPhoneVerificationUserID verifies a token, marks phone_verified = true, and returns the user ID.
func (s *Service) ConfirmPhoneVerificationUserID(ctx context.Context, phone, code string) (string, error) {
	hash := sha256Hex(code)

	var userID string
	if s.useEphemeralStore() {
		uid, err := s.consumePhoneVerification(ctx, "verify_phone", phone, hash)
		if err != nil {
			return "", err
		}
		userID = uid
	} else {
		return "", jwt.ErrTokenUnverifiable
	}

	// Mark phone as verified
	if err := s.q.UserSetPhoneVerifiedByIDAndPhone(ctx, db.UserSetPhoneVerifiedByIDAndPhoneParams{ID: userID, PhoneNumber: &phone}); err != nil {
		return "", err
	}
	return userID, nil
}

// ConfirmPhoneVerificationByToken verifies phone ownership using a one-click token.
func (s *Service) ConfirmPhoneVerificationByToken(ctx context.Context, token string) error {
	_, err := s.ConfirmPhoneVerificationByTokenUserID(ctx, token)
	return err
}

// ConfirmPhoneVerificationByTokenUserID verifies phone ownership using a one-click token and returns the user ID.
func (s *Service) ConfirmPhoneVerificationByTokenUserID(ctx context.Context, token string) (string, error) {
	hash := sha256Hex(token)
	userID, phone, err := s.consumePhoneVerificationByToken(ctx, "verify_phone", hash)
	if err != nil {
		return "", err
	}

	if err := s.q.UserSetPhoneVerifiedByIDAndPhone(ctx, db.UserSetPhoneVerifiedByIDAndPhoneParams{ID: userID, PhoneNumber: &phone}); err != nil {
		return "", err
	}
	return userID, nil
}

// --- Phone Password Reset (for phone+password users) ---

// RequestPhonePasswordReset creates a password reset token and sends a reset link via SMS.
// Always returns nil for unknown phone numbers to prevent user enumeration (202-like behavior).
func (s *Service) RequestPhonePasswordReset(ctx context.Context, phone string, ttl time.Duration, ip *string, ua *string) error {
	// Look up user by phone
	u, err := s.GetUserByPhone(ctx, phone)
	if err != nil || u == nil {
		return nil // Don't reveal if phone exists
	}

	if ttl <= 0 {
		ttl = time.Hour
	}

	token := randB64(32)
	hash := sha256Hex(token)
	if err := s.createResetToken(ctx, u.ID, hash, time.Now().Add(ttl)); err != nil {
		return err
	}

	if s.sms == nil {
		if !s.isDevEnvironment() {
			return fmt.Errorf("SMS password reset unavailable: sms sender not configured")
		}
		return nil
	}

	sendCtx := s.contextWithUserPreferredLocale(ctx, u.ID)
	if err := s.withSendTimeout(sendCtx, func(sendCtx context.Context) error { return s.sms.SendPasswordResetLink(sendCtx, phone, token) }); err != nil {
		return smsDeliveryError(err)
	}

	s.LogPasswordRecovery(ctx, u.ID, "sms", "", ip, ua)

	return nil
}

// helpers
func randB64(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func randInt(max int) int {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	n := int(b[0]) | int(b[1])<<8 | int(b[2])<<16 | int(b[3])<<24
	if n < 0 {
		n = -n
	}
	return n % max
}

// randAlphanumeric generates a random numeric code of length n.
// It returns a string to preserve leading zeros.
func randAlphanumeric(n int) string {
	// Generate n-digit numeric code (e.g., 6 digits = 000000-999999)
	code := ""
	for i := 0; i < n; i++ {
		code += string('0' + byte(randInt(10)))
	}
	return code
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// --- Direct Postgres helpers (profiles schema) ---

type User struct {
	ID              string
	Email           *string // Nullable - phone-only users have NULL email
	PhoneNumber     *string
	Username        *string
	DiscordUsername *string
	EmailVerified   bool
	PhoneVerified   bool
	BannedAt        *time.Time
	BannedUntil     *time.Time
	BanReason       *string
	BannedBy        *string
	DeletedAt       *time.Time
	Biography       *string
	CreatedAt       time.Time
	UpdatedAt       time.Time
	LastLogin       *time.Time
}

func userFromByIDRow(r db.UserByIDRow) *User {
	return &User{ID: r.ID, Email: r.Email, PhoneNumber: r.PhoneNumber, Username: r.Username, DiscordUsername: r.DiscordUsername, EmailVerified: r.EmailVerified, PhoneVerified: r.PhoneVerified, BannedAt: r.BannedAt, BannedUntil: r.BannedUntil, BanReason: r.BanReason, BannedBy: r.BannedBy, DeletedAt: r.DeletedAt, Biography: r.Biography, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt, LastLogin: r.LastLogin}
}

func userFromByEmailRow(r db.UserByEmailRow) *User {
	return &User{ID: r.ID, Email: r.Email, PhoneNumber: r.PhoneNumber, Username: r.Username, DiscordUsername: r.DiscordUsername, EmailVerified: r.EmailVerified, PhoneVerified: r.PhoneVerified, BannedAt: r.BannedAt, BannedUntil: r.BannedUntil, BanReason: r.BanReason, BannedBy: r.BannedBy, DeletedAt: r.DeletedAt, Biography: r.Biography, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt, LastLogin: r.LastLogin}
}

func userFromByUsernameRow(r db.UserByUsernameRow) *User {
	return &User{ID: r.ID, Email: r.Email, PhoneNumber: r.PhoneNumber, Username: r.Username, DiscordUsername: r.DiscordUsername, EmailVerified: r.EmailVerified, PhoneVerified: r.PhoneVerified, BannedAt: r.BannedAt, BannedUntil: r.BannedUntil, BanReason: r.BanReason, BannedBy: r.BannedBy, DeletedAt: r.DeletedAt, Biography: r.Biography, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt, LastLogin: r.LastLogin}
}

func userFromByPhoneRow(r db.UserByPhoneRow) *User {
	return &User{ID: r.ID, Email: r.Email, PhoneNumber: r.PhoneNumber, Username: r.Username, DiscordUsername: r.DiscordUsername, EmailVerified: r.EmailVerified, PhoneVerified: r.PhoneVerified, BannedAt: r.BannedAt, BannedUntil: r.BannedUntil, BanReason: r.BanReason, BannedBy: r.BannedBy, DeletedAt: r.DeletedAt, Biography: r.Biography, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt, LastLogin: r.LastLogin}
}

var preferredLocaleRe = regexp.MustCompile(`^[A-Za-z]{2,3}(-([A-Za-z]{2}|[0-9]{3}))?$`)

func NormalizePreferredLocale(locale string) (string, error) {
	locale = strings.TrimSpace(strings.ReplaceAll(locale, "_", "-"))
	if locale == "" {
		return "", nil
	}
	if !preferredLocaleRe.MatchString(locale) {
		return "", fmt.Errorf("invalid_preferred_locale")
	}
	parts := strings.Split(locale, "-")
	parts[0] = strings.ToLower(parts[0])
	if len(parts) == 2 {
		if len(parts[1]) == 2 {
			parts[1] = strings.ToUpper(parts[1])
		}
	}
	return strings.Join(parts, "-"), nil
}

func normalizePreferredLocaleSource(source string) string {
	source = strings.TrimSpace(strings.ToLower(source))
	switch source {
	case "registration", "explicit", "migration", "import":
		return source
	default:
		return "explicit"
	}
}

type PreferredLocale struct {
	Locale    string
	Source    string
	UpdatedAt *time.Time
}

func (s *Service) SetPreferredLocale(ctx context.Context, userID, locale, source string) error {
	if s.pg == nil {
		return fmt.Errorf("postgres not configured")
	}
	userID = strings.TrimSpace(userID)
	normalized, err := NormalizePreferredLocale(locale)
	if err != nil {
		return err
	}
	if userID == "" || normalized == "" {
		return fmt.Errorf("invalid_request")
	}
	src := normalizePreferredLocaleSource(source)
	return s.q.UserSetPreferredLocale(ctx, db.UserSetPreferredLocaleParams{ID: userID, PreferredLocale: &normalized, PreferredLocaleSource: &src})
}

func (s *Service) GetPreferredLocale(ctx context.Context, userID string) (PreferredLocale, error) {
	if s.pg == nil {
		return PreferredLocale{}, nil
	}
	row, err := s.q.UserPreferredLocale(ctx, strings.TrimSpace(userID))
	return PreferredLocale{Locale: row.Locale, Source: row.Source, UpdatedAt: row.PreferredLocaleUpdatedAt}, err
}

func contextWithPreferredLocale(ctx context.Context, locale string) context.Context {
	if strings.TrimSpace(locale) == "" {
		return ctx
	}
	return authlang.WithLanguage(ctx, locale)
}

func (s *Service) contextWithUserPreferredLocale(ctx context.Context, userID string) context.Context {
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return ctx
	}
	preferred, err := s.GetPreferredLocale(ctx, userID)
	if err != nil || strings.TrimSpace(preferred.Locale) == "" {
		return ctx
	}
	return contextWithPreferredLocale(ctx, preferred.Locale)
}

// verificationSendTimeout is the per-send deadline for in-line email/SMS
// provider calls. Configurable via Options.VerificationSendTimeout; defaults to
// 15s when unset.
func (s *Service) verificationSendTimeout() time.Duration {
	if s != nil && s.opts.VerificationSendTimeout > 0 {
		return s.opts.VerificationSendTimeout
	}
	return 15 * time.Second
}

// withSendTimeout runs a single email/SMS provider send under a bounded context
// so a configured-but-misconfigured/unreachable provider cannot hang the
// request that triggered it (e.g. registration verification). It is loop-safe:
// the deadline is cancelled as soon as the send returns, not at the end of the
// calling function.
func (s *Service) withSendTimeout(ctx context.Context, send func(context.Context) error) error {
	ctx, cancel := context.WithTimeout(ctx, s.verificationSendTimeout())
	defer cancel()
	return send(ctx)
}

type ImportUserInput struct {
	Email         string
	PhoneNumber   string
	Username      string
	EmailVerified bool
	PhoneVerified bool
	BannedAt      *time.Time
	BannedUntil   *time.Time
	BanReason     *string
	BannedBy      *string
	Metadata      map[string]any
	CreatedAt     *time.Time
	UpdatedAt     *time.Time
}

func (s *Service) getUserByEmail(ctx context.Context, email string) (*User, error) {
	if s.pg == nil {
		return nil, nil
	}
	r, err := s.q.UserByEmail(ctx, email)
	if err != nil {
		return nil, err
	}
	return userFromByEmailRow(r), nil
}

func (s *Service) getUserByUsername(ctx context.Context, username string) (*User, error) {
	if s.pg == nil {
		return nil, nil
	}
	r, err := s.q.UserByUsername(ctx, &username)
	if err != nil {
		return nil, err
	}
	return userFromByUsernameRow(r), nil
}

func (s *Service) getUserByID(ctx context.Context, id string) (*User, error) {
	if s.pg == nil {
		return nil, nil
	}
	r, err := s.q.UserByID(ctx, id)
	if err != nil {
		return nil, err
	}
	return userFromByIDRow(r), nil
}

func (s *Service) ensureUserAccess(ctx context.Context, u *User) error {
	if u == nil {
		return jwt.ErrTokenInvalidClaims
	}
	if u.DeletedAt != nil {
		return ErrUserBanned
	}
	if reserved, err := s.IsUserReserved(ctx, strings.TrimSpace(u.ID)); err == nil && reserved {
		return ErrUserBanned
	}
	if err := s.autoUnbanIfExpired(ctx, u); err != nil {
		return err
	}
	if isUserBanned(u) {
		return ErrUserBanned
	}
	return nil
}

func (s *Service) ensureUserAccessByID(ctx context.Context, userID string) error {
	if strings.TrimSpace(userID) == "" {
		return jwt.ErrTokenInvalidClaims
	}
	u, err := s.getUserByID(ctx, userID)
	if err != nil || u == nil {
		return errOrUnauthorized(err)
	}
	return s.ensureUserAccess(ctx, u)
}

func (s *Service) autoUnbanIfExpired(ctx context.Context, u *User) error {
	if u == nil || u.BannedUntil == nil {
		return nil
	}
	now := time.Now().UTC()
	if !u.BannedUntil.After(now) {
		if err := s.clearUserBan(ctx, u.ID); err != nil {
			return err
		}
		u.BannedAt = nil
		u.BannedUntil = nil
		u.BanReason = nil
		u.BannedBy = nil
	}
	return nil
}

func isUserBanned(u *User) bool {
	if u == nil {
		return false
	}
	return u.BannedAt != nil || u.BannedUntil != nil || u.BanReason != nil || u.BannedBy != nil
}

func (s *Service) createUser(ctx context.Context, email, username string) (*User, error) {
	if s.pg == nil {
		return nil, nil
	}
	slug := ownerSlugFromUsername(username)
	if slug == "" || validateOrgSlug(slug) != nil {
		return nil, fmt.Errorf("invalid_username_for_owner_namespace")
	}
	if err := s.ensureOwnerSlugAvailable(ctx, slug, "", ""); err != nil {
		return nil, err
	}
	userID, err := newUUIDV7String()
	if err != nil {
		return nil, err
	}
	ins, err := s.q.UserInsert(ctx, db.UserInsertParams{ID: userID, Email: email, Username: &username})
	if err != nil {
		return nil, err
	}
	u := User{ID: ins.ID, Email: ins.Email, Username: ins.Username, EmailVerified: ins.EmailVerified, BannedAt: ins.BannedAt, DeletedAt: ins.DeletedAt}

	if s.opts.AutoCreatePersonalOrgsEnabled() {
		if err := s.ensurePersonalOrgForUser(ctx, u.ID, username); err != nil {
			return nil, err
		}
	}
	return &u, nil
}

func normalizeImportUserInput(input ImportUserInput) (email *string, phone *string, username string, bannedBy *string, metadata string, createdAt time.Time, updatedAt time.Time, err error) {
	if trimmed := strings.TrimSpace(input.Email); trimmed != "" {
		if err := ValidateEmail(trimmed); err != nil {
			return nil, nil, "", nil, "", time.Time{}, time.Time{}, err
		}
		v := NormalizeEmail(trimmed)
		email = &v
	}
	if trimmed := strings.TrimSpace(input.PhoneNumber); trimmed != "" {
		if err := ValidatePhone(trimmed); err != nil {
			return nil, nil, "", nil, "", time.Time{}, time.Time{}, err
		}
		v := NormalizePhone(trimmed)
		phone = &v
	}
	username = strings.TrimSpace(input.Username)
	slug := ownerSlugFromUsername(username)
	if slug == "" || validateOrgSlug(slug) != nil {
		return nil, nil, "", nil, "", time.Time{}, time.Time{}, fmt.Errorf("invalid_username_for_owner_namespace")
	}
	if input.BannedBy != nil && strings.TrimSpace(*input.BannedBy) != "" {
		v := strings.TrimSpace(*input.BannedBy)
		bannedBy = &v
	}
	rawMetadata := input.Metadata
	if rawMetadata == nil {
		rawMetadata = map[string]any{}
	}
	metadataJSON, err := json.Marshal(rawMetadata)
	if err != nil {
		return nil, nil, "", nil, "", time.Time{}, time.Time{}, err
	}
	now := time.Now().UTC()
	createdAt = now
	if input.CreatedAt != nil {
		createdAt = input.CreatedAt.UTC()
	}
	updatedAt = now
	if input.UpdatedAt != nil {
		updatedAt = input.UpdatedAt.UTC()
	}
	return email, phone, username, bannedBy, string(metadataJSON), createdAt, updatedAt, nil
}

func (s *Service) ImportUser(ctx context.Context, input ImportUserInput) (*User, error) {
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	email, phone, username, bannedBy, metadata, createdAt, updatedAt, err := normalizeImportUserInput(input)
	if err != nil {
		return nil, err
	}
	slug := ownerSlugFromUsername(username)
	if err := s.ensureOwnerSlugAvailable(ctx, slug, "", ""); err != nil {
		return nil, err
	}
	userID, err := newUUIDV7String()
	if err != nil {
		return nil, err
	}
	err = s.q.UserImportInsert(ctx, db.UserImportInsertParams{
		ID:            userID,
		Email:         email,
		PhoneNumber:   phone,
		Username:      &username,
		EmailVerified: input.EmailVerified,
		PhoneVerified: &input.PhoneVerified,
		BannedAt:      input.BannedAt,
		BannedUntil:   input.BannedUntil,
		BanReason:     input.BanReason,
		BannedBy:      bannedBy,
		Metadata:      []byte(metadata),
		CreatedAt:     createdAt,
		UpdatedAt:     updatedAt,
	})
	if err != nil {
		return nil, err
	}
	if s.opts.AutoCreatePersonalOrgsEnabled() {
		if err := s.ensurePersonalOrgForUser(ctx, userID, username); err != nil {
			return nil, err
		}
	}
	return s.getUserByID(ctx, userID)
}

func (s *Service) UpdateImportedUser(ctx context.Context, userID string, input ImportUserInput) (*User, error) {
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return nil, ErrUserNotFound
	}
	email, phone, username, bannedBy, metadata, createdAt, updatedAt, err := normalizeImportUserInput(input)
	if err != nil {
		return nil, err
	}
	if _, err := s.ensureUserOwnerSlugAvailable(ctx, userID, username); err != nil {
		return nil, err
	}
	updatedID, err := s.q.UserImportUpdate(ctx, db.UserImportUpdateParams{
		ID:            userID,
		Email:         email,
		PhoneNumber:   phone,
		Username:      &username,
		EmailVerified: input.EmailVerified,
		PhoneVerified: &input.PhoneVerified,
		BannedAt:      input.BannedAt,
		BannedUntil:   input.BannedUntil,
		BanReason:     input.BanReason,
		BannedBy:      bannedBy,
		Metadata:      []byte(metadata),
		CreatedAt:     createdAt,
		UpdatedAt:     updatedAt,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrUserNotFound
	}
	if err != nil {
		return nil, err
	}
	if s.opts.AutoCreatePersonalOrgsEnabled() {
		if err := s.ensurePersonalOrgForUser(ctx, userID, username); err != nil {
			return nil, err
		}
	}
	return s.getUserByID(ctx, updatedID)
}

func (s *Service) setEmailVerified(ctx context.Context, id string, v bool) error {
	if s.pg == nil {
		return nil
	}
	return s.q.UserSetEmailVerified(ctx, db.UserSetEmailVerifiedParams{ID: id, EmailVerified: v})
}

func (s *Service) createVerifiedRegistrationUser(ctx context.Context, email, username, passwordHash string) (string, error) {
	return s.createEmailRegistrationUser(ctx, email, username, passwordHash, true)
}

func (s *Service) createEmailRegistrationUser(ctx context.Context, email, username, passwordHash string, emailVerified bool) (string, error) {
	if s.pg == nil {
		return "", fmt.Errorf("postgres not configured")
	}
	if err := ValidateEmail(email); err != nil {
		return "", err
	}
	if _, err := s.ValidateUsernameForRegistration(ctx, username); err != nil {
		return "", err
	}
	email = NormalizeEmail(email)
	username = strings.TrimSpace(username)

	u, err := s.createUser(ctx, email, username)
	if err != nil {
		return "", err
	}
	if u == nil {
		return "", fmt.Errorf("failed to create user")
	}

	if err := s.q.UserPasswordInsert(ctx, db.UserPasswordInsertParams{UserID: u.ID, PasswordHash: passwordHash}); err != nil {
		return "", err
	}

	if err := s.setEmailVerified(ctx, u.ID, emailVerified); err != nil {
		return "", err
	}

	return u.ID, nil
}

func (s *Service) createPhoneRegistrationUser(ctx context.Context, phone, username, passwordHash string, phoneVerified bool) (string, error) {
	if s.pg == nil {
		return "", fmt.Errorf("postgres not configured")
	}
	if err := ValidatePhone(phone); err != nil {
		return "", err
	}
	if _, err := s.ValidateUsernameForRegistration(ctx, username); err != nil {
		return "", err
	}
	phone = NormalizePhone(phone)
	username = strings.TrimSpace(username)

	u, err := s.createUser(ctx, "", username)
	if err != nil {
		return "", err
	}
	if u == nil {
		return "", fmt.Errorf("failed to create user")
	}

	if err := s.q.UserPasswordInsert(ctx, db.UserPasswordInsertParams{UserID: u.ID, PasswordHash: passwordHash}); err != nil {
		return "", err
	}

	if err := s.q.UserSetPhoneAndVerified(ctx, db.UserSetPhoneAndVerifiedParams{ID: u.ID, PhoneNumber: &phone, PhoneVerified: &phoneVerified}); err != nil {
		return "", err
	}

	return u.ID, nil
}

func (s *Service) setLastLogin(ctx context.Context, id string, t time.Time) error {
	if s.pg == nil {
		return nil
	}
	return s.q.UserSetLastLogin(ctx, db.UserSetLastLoginParams{ID: id, LastLogin: &t})
}

func (s *Service) clearUserBan(ctx context.Context, userID string) error {
	if s.pg == nil {
		return fmt.Errorf("postgres not configured")
	}
	if strings.TrimSpace(userID) == "" {
		return fmt.Errorf("invalid_user")
	}
	return s.q.UserClearBan(ctx, userID)
}

// BanUser disables a user account and stores ban metadata.
func (s *Service) BanUser(ctx context.Context, userID string, reason *string, until *time.Time, bannedBy string) error {
	if s.pg == nil {
		return fmt.Errorf("postgres not configured")
	}
	if strings.TrimSpace(userID) == "" {
		return fmt.Errorf("invalid_user")
	}
	now := time.Now().UTC()
	var reasonPtr *string
	if reason != nil {
		trimmed := strings.TrimSpace(*reason)
		if trimmed != "" {
			reasonPtr = &trimmed
		}
	}
	var bannedByPtr *string
	if trimmed := strings.TrimSpace(bannedBy); trimmed != "" {
		bannedByPtr = &trimmed
	}
	var untilPtr *time.Time
	if until != nil {
		t := until.UTC()
		untilPtr = &t
	}
	if err := s.q.UserBan(ctx, db.UserBanParams{ID: userID, BannedAt: &now, BannedUntil: untilPtr, BanReason: reasonPtr, BannedBy: bannedByPtr}); err != nil {
		return err
	}
	_ = s.RevokeAllSessions(WithSessionRevokeReason(ctx, SessionRevokeReasonBanned), userID, nil)
	return nil
}

// UnbanUser clears ban metadata and re-enables the account.
func (s *Service) UnbanUser(ctx context.Context, userID string) error {
	return s.clearUserBan(ctx, userID)
}

// SoftDeleteUser marks the user deleted and sets deleted_at without dropping rows.
// Also revokes all refresh sessions for this issuer.
func (s *Service) SoftDeleteUser(ctx context.Context, id string) error {
	if s.pg == nil {
		return nil
	}
	// Revoke sessions first
	_ = s.RevokeAllSessions(WithSessionRevokeReason(ctx, SessionRevokeReasonSoftDeleted), id, nil)
	// Soft-delete user
	return s.q.UserSoftDelete(ctx, id)
}

// RestoreUser clears deleted_at and re-enables the account.
func (s *Service) RestoreUser(ctx context.Context, id string) error {
	if s.pg == nil {
		return nil
	}
	return s.q.UserRestore(ctx, id)
}

// HostDeleteUser performs deletion on behalf of the host application.
// If soft is true, it performs a soft delete (see SoftDeleteUser). If false, it hard-deletes the user
// and all dependent rows via ON DELETE CASCADE.
func (s *Service) HostDeleteUser(ctx context.Context, id string, soft bool) error {
	if soft {
		return s.SoftDeleteUser(ctx, id)
	}
	return s.AdminDeleteUser(ctx, id)
}

func (s *Service) updateUsername(ctx context.Context, id, username string) error {
	return s.updateUsernameImpl(ctx, id, username, false)
}

// UpdateUsernameForce is the admin override that skips the 72h cooldown
// check. Otherwise identical to UpdateUsername. Caller is responsible
// for gating this behind admin scope upstream.
func (s *Service) UpdateUsernameForce(ctx context.Context, id, username string) error {
	return s.updateUsernameImpl(ctx, id, username, true)
}

func (s *Service) updateUsernameImpl(ctx context.Context, id, username string, bypassCooldown bool) error {
	if s.pg == nil {
		return nil
	}
	newUsername := strings.TrimSpace(username)
	newSlug, excludeOrgID, err := s.ValidateUsernameForUser(ctx, newUsername, id)
	if err != nil {
		return err
	}
	tx, err := s.pg.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	qtx := s.qtx(tx)

	oldUsername, err := qtx.UserUsernameByID(ctx, id)
	if err != nil {
		return err
	}
	if strings.EqualFold(strings.TrimSpace(oldUsername), newUsername) {
		return nil
	}
	if err := s.ensureOwnerSlugAvailable(ctx, newSlug, id, excludeOrgID); err != nil {
		return err
	}

	// Cooldown check (issue #58). The cooldown applies to the user's
	// rename intent only — the personal-org rename below is a
	// by-product, not separately rate-limited. Walks the
	// `(user_id, renamed_at DESC)` index to grab the most recent rename.
	if !bypassCooldown {
		lastRenamedAt, err := qtx.UserLastRenamedAt(ctx, id)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if err == nil && time.Since(lastRenamedAt) < renameCooldown {
			return ErrRenameRateLimited
		}
	}

	if err := qtx.UserSetUsername(ctx, db.UserSetUsernameParams{ID: id, Username: &newUsername}); err != nil {
		return err
	}
	// Audit row for the user rename.
	if err := qtx.UserRenameInsert(ctx, db.UserRenameInsertParams{UserID: id, FromSlug: strings.ToLower(strings.TrimSpace(oldUsername))}); err != nil {
		return err
	}

	if s.opts.AutoCreatePersonalOrgsEnabled() {
		var orgID, oldOrgSlug string
		pt, err := qtx.PersonalOrgIDSlugByOwner(ctx, id)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if err == nil {
			orgID, oldOrgSlug = pt.ID, pt.Slug
		}
		if strings.TrimSpace(orgID) == "" {
			derivedOrgID, err := newUUIDV7String()
			if err != nil {
				return err
			}
			if err := qtx.PersonalOrgInsertBasic(ctx, db.PersonalOrgInsertBasicParams{ID: derivedOrgID, Slug: newSlug, OwnerUserID: id}); err != nil {
				return err
			}
			pt, err := qtx.PersonalOrgIDSlugByOwner(ctx, id)
			if err != nil {
				return err
			}
			orgID = pt.ID
		} else if !strings.EqualFold(oldOrgSlug, newSlug) {
			// Personal-org rename rides the user-rename intent — write
			// the org_renames audit row in the same tx. Cooldown was
			// already checked against user_renames above; we don't
			// re-gate here.
			if err := qtx.OrgRenameInsert(ctx, db.OrgRenameInsertParams{OrgID: orgID, FromSlug: strings.ToLower(strings.TrimSpace(oldOrgSlug))}); err != nil {
				return err
			}
			if err := qtx.OrgUpdateSlugUnconditional(ctx, db.OrgUpdateSlugUnconditionalParams{Slug: newSlug, ID: orgID}); err != nil {
				return err
			}
		}
		if strings.TrimSpace(orgID) != "" {
			if err := qtx.OrgRolesSeedOwnerMember(ctx, db.OrgRolesSeedOwnerMemberParams{OrgID: orgID, OwnerRole: orgOwnerRole, MemberRole: orgMemberRole}); err != nil {
				return err
			}
			if err := qtx.OrgMembershipUpsertRole(ctx, db.OrgMembershipUpsertRoleParams{OrgID: orgID, UserID: id, Role: orgOwnerRole}); err != nil {
				return err
			}
		}
	}
	return tx.Commit(ctx)
}

func (s *Service) updateEmail(ctx context.Context, id, email string) error {
	if s.pg == nil {
		return nil
	}
	if err := ValidateEmail(email); err != nil {
		return err
	}
	trimmed := NormalizeEmail(email)
	u, err := s.getUserByID(ctx, id)
	if err != nil {
		return err
	}

	if u == nil {
		return fmt.Errorf("user not found")
	}

	if u.Email != nil && strings.EqualFold(*u.Email, trimmed) {
		return nil
	}

	if err := s.q.UserSetEmailAndUnverify(ctx, db.UserSetEmailAndUnverifyParams{ID: id, Email: trimmed}); err != nil {
		return err
	}

	return s.RequestEmailVerification(ctx, trimmed, 0)
}

// RequestEmailChange initiates an email change by sending a verification code to the new email.
// The current email is NOT changed until the user confirms via ConfirmEmailChange.
// Also sends a notification to the old email for security.
func (s *Service) RequestEmailChange(ctx context.Context, userID, newEmail string) error {
	if s.pg == nil {
		return fmt.Errorf("postgres not configured")
	}

	if err := ValidateEmail(newEmail); err != nil {
		return err
	}
	trimmed := NormalizeEmail(newEmail)

	// Get user
	u, err := s.getUserByID(ctx, userID)
	if err != nil {
		return err
	}
	if u == nil {
		return fmt.Errorf("user not found")
	}

	// Check if trying to change to the same email
	if u.Email != nil && strings.EqualFold(*u.Email, trimmed) {
		return fmt.Errorf("new email is the same as current email")
	}

	// Check if new email is already in use by another user
	existing, _ := s.getUserByEmail(ctx, trimmed)
	if existing != nil && existing.ID != userID {
		return fmt.Errorf("email already in use")
	}

	// Generate manual code + link token.
	code := randAlphanumeric(6)
	codeHash := sha256Hex(code)
	linkToken := randB64(32)
	linkHash := sha256Hex(linkToken)

	// Hold the new email in the unified pending-change store (applied to the
	// profile only on confirmation). Split TTLs: code + link token.
	if err := s.storePendingChange(ctx, pendingChange{
		Kind:   KindChangeEmail,
		Target: trimmed,
		UserID: userID,
	}, map[string]time.Duration{
		codeHash: defaultEmailVerificationTTL,
		linkHash: defaultEmailVerificationTTL,
	}); err != nil {
		return err
	}

	username := ""
	if u.Username != nil {
		username = *u.Username
	}

	// Send verification message to NEW email
	msg := VerificationMessage{Code: code, LinkToken: linkToken}
	if s.email != nil {
		sendCtx := s.contextWithUserPreferredLocale(ctx, userID)
		if err := s.withSendTimeout(sendCtx, func(sendCtx context.Context) error { return s.email.SendVerification(sendCtx, trimmed, username, msg) }); err != nil {
			return emailDeliveryError(err)
		}
	} else if !s.isDevEnvironment() {
		return fmt.Errorf("email change verification unavailable: email sender not configured")
	}

	// Send notification to OLD email about the change request
	if u.Email != nil && s.email != nil {
		// Host applications can implement dedicated change-notification messages if needed.
		// In production, you'd want a dedicated SendEmailChangeNotification method
		stdlog.Printf("[authkit/security] Email change requested for user %s from %s to %s", userID, *u.Email, trimmed)
	}

	return nil
}

// ConfirmEmailChange verifies the code and updates the user's email address.
// This is called when the user enters the verification code sent to their new email.
func (s *Service) ConfirmEmailChange(ctx context.Context, userID, code string) error {
	if s.pg == nil {
		return jwt.ErrTokenUnverifiable
	}

	// Load the pending change by the code's hash and validate it belongs to this
	// user, then finalize (apply the new email) and clear the pending record.
	hash := sha256Hex(code)
	rec, ok, err := s.loadPendingChangeByToken(ctx, hash)
	if err != nil || !ok || rec.Kind != KindChangeEmail {
		return jwt.ErrTokenUnverifiable
	}
	if rec.UserID != userID {
		return jwt.ErrTokenInvalidClaims
	}
	if _, err := s.finalizeChangeEmail(ctx, rec); err != nil {
		return err
	}
	s.deletePendingChangeByToken(ctx, hash)
	return nil
}

// ResendEmailChangeCode resends the verification code for a pending email change.
func (s *Service) ResendEmailChangeCode(ctx context.Context, userID string) error {
	u, err := s.getUserByID(ctx, userID)
	if err != nil {
		return err
	}
	if u == nil {
		return fmt.Errorf("user not found")
	}

	rec, ok := s.findPendingChangeByUser(ctx, KindChangeEmail, userID)
	if !ok {
		return fmt.Errorf("no pending email change found")
	}
	pendingEmail := rec.Target

	// Generate new verification credentials; storePendingChange supersedes the old record.
	code := randAlphanumeric(6)
	codeHash := sha256Hex(code)
	linkToken := randB64(32)
	linkHash := sha256Hex(linkToken)
	if err := s.storePendingChange(ctx, pendingChange{
		Kind:   KindChangeEmail,
		Target: pendingEmail,
		UserID: userID,
	}, map[string]time.Duration{
		codeHash: defaultEmailVerificationTTL,
		linkHash: defaultEmailVerificationTTL,
	}); err != nil {
		return err
	}

	username := ""
	if u.Username != nil {
		username = *u.Username
	}

	msg := VerificationMessage{Code: code, LinkToken: linkToken}
	// Send new credentials.
	if s.email != nil {
		sendCtx := s.contextWithUserPreferredLocale(ctx, userID)
		if err := s.withSendTimeout(sendCtx, func(sendCtx context.Context) error {
			return s.email.SendVerification(sendCtx, pendingEmail, username, msg)
		}); err != nil {
			return emailDeliveryError(err)
		}
	} else if !s.isDevEnvironment() {
		return fmt.Errorf("email change verification unavailable: email sender not configured")
	}

	return nil
}

// GetPendingEmailChange retrieves the pending email change for a user, if any.
// A unified change_email record exists only for an actual change (verifying the
// current address uses a separate store), so its presence already means "change".
func (s *Service) GetPendingEmailChange(ctx context.Context, userID string) (string, error) {
	if !s.useEphemeralStore() {
		return "", nil
	}
	rec, ok := s.findPendingChangeByUser(ctx, KindChangeEmail, userID)
	if !ok {
		return "", nil
	}
	return rec.Target, nil
}

// CancelEmailChange aborts a pending email-change for the user, clearing the
// unified pending-change record. The new email is applied only on confirmation,
// so there is nothing to roll back. Idempotent: a no-op when none is pending.
func (s *Service) CancelEmailChange(ctx context.Context, userID string) error {
	if !s.useEphemeralStore() {
		return nil
	}
	s.deletePendingChangeByUser(ctx, KindChangeEmail, userID)
	return nil
}

func (s *Service) updateBiography(ctx context.Context, id string, bio *string) error {
	if s.pg == nil {
		return nil
	}
	return s.q.UserSetBiography(ctx, db.UserSetBiographyParams{ID: id, Biography: bio})
}

// setPasswordSet removed; presence of password is inferred from profiles.user_passwords

func (s *Service) getPasswordHash(ctx context.Context, userID string) (hash, algo string, params []byte, err error) {
	if s.pg == nil {
		return "", "", nil, nil
	}
	row, err := s.q.UserPasswordRow(ctx, userID)
	return row.PasswordHash, row.HashAlgo, row.HashParams, err
}

func (s *Service) upsertPasswordHash(ctx context.Context, userID, hash, algo string, params []byte) error {
	if s.pg == nil {
		return nil
	}
	return s.q.UserPasswordUpsert(ctx, db.UserPasswordUpsertParams{UserID: userID, PasswordHash: hash, HashAlgo: algo, HashParams: params})
}

// email verification tokens
type emailVerifyToken struct {
	UserID string
	Email  *string
}

func (s *Service) useEmailVerifyToken(ctx context.Context, tokenHash string) (*emailVerifyToken, error) {
	if s.useEphemeralStore() {
		return s.consumeEmailVerification(ctx, tokenHash)
	}
	return nil, jwt.ErrTokenUnverifiable
}

func (s *Service) useResetToken(ctx context.Context, tokenHash string) (struct{ UserID string }, error) {
	if s.useEphemeralStore() {
		userID, err := s.consumePasswordReset(ctx, tokenHash)
		return struct{ UserID string }{UserID: userID}, err
	}
	return struct{ UserID string }{}, jwt.ErrTokenUnverifiable
}

func (s *Service) createResetToken(ctx context.Context, userID, tokenHash string, expiresAt time.Time) error {
	if s.useEphemeralStore() {
		ttl := time.Until(expiresAt)
		if ttl <= 0 {
			ttl = time.Hour
		}
		return s.storePasswordReset(ctx, tokenHash, userID, ttl)
	}
	return fmt.Errorf("ephemeral store not configured")
}

// listRoleSlugsByUser returns a user's platform role names. The legacy global
// roles plane was hard-cut; "roles" in the admin directory now means a user's
// Layer-2 platform roles (profiles.platform_user_roles).
func (s *Service) listRoleSlugsByUser(ctx context.Context, userID string) []string {
	if s.pg == nil {
		return nil
	}
	roles, err := s.PlatformRolesForUser(ctx, userID)
	if err != nil {
		return nil
	}
	return roles
}

var ErrReservedRoleSlug = errors.New("reserved_role_slug")
var ErrUserRoleNotFound = errors.New("user_role_not_found")

// ErrCannotRemoveLastAdminRole is retained for the admin HTTP adapter's error
// mapping. The platform layer has no "last admin" lock (super-admin is seeded
// out-of-band via the bootstrap manifest), so core no longer returns it, but
// the exported symbol stays so dependents keep compiling.
var ErrCannotRemoveLastAdminRole = errors.New("cannot_remove_last_admin_role")

// assignRoleBySlug grants a user a platform role by name (defining the role if
// it does not yet exist). A manifest/admin role named "admin" is mapped onto the
// platform super-admin (platform:*); any other name becomes a same-named
// platform role with no perms until they are set explicitly.
func (s *Service) assignRoleBySlug(ctx context.Context, userID, slug string) error {
	if strings.EqualFold(strings.TrimSpace(slug), "owner") {
		return ErrReservedRoleSlug
	}
	if s.pg == nil {
		return nil
	}
	role := strings.ToLower(strings.TrimSpace(slug))
	if role == "admin" {
		return s.EnsurePlatformSuperAdmin(ctx, userID)
	}
	if err := s.DefinePlatformRole(ctx, role); err != nil {
		return err
	}
	return s.AssignPlatformRole(ctx, userID, role)
}

// upsertRoleBySlug defines a platform role by name. The legacy global-role
// name/description fields no longer exist; "admin" seeds the super-admin role
// (platform:*) and every other name is defined as an empty platform role.
func (s *Service) upsertRoleBySlug(ctx context.Context, name, slug string, description *string) error {
	if s.pg == nil {
		return nil
	}
	_ = name
	_ = description
	role := strings.ToLower(strings.TrimSpace(slug))
	if role == "" {
		return fmt.Errorf("invalid_role")
	}
	if role == "owner" {
		return ErrReservedRoleSlug
	}
	if role == "admin" {
		if err := s.DefinePlatformRole(ctx, PlatformSuperAdminRole); err != nil {
			return err
		}
		return s.SetPlatformRolePermissions(ctx, PlatformSuperAdminRole, []string{PlatformSuperAdminGrant})
	}
	return s.DefinePlatformRole(ctx, role)
}

// removeRoleBySlug revokes a user's platform role by name. "admin" maps onto the
// super-admin role.
func (s *Service) removeRoleBySlug(ctx context.Context, userID, slug string) error {
	if s.pg == nil {
		return nil
	}
	role := strings.ToLower(strings.TrimSpace(slug))
	if role == "admin" {
		role = PlatformSuperAdminRole
	}
	removed, err := s.UnassignPlatformRole(ctx, userID, role)
	if err != nil {
		return err
	}
	if !removed {
		return ErrUserRoleNotFound
	}
	return nil
}

// Exported wrappers for admin endpoints
func (s *Service) AssignRoleBySlug(ctx context.Context, userID, slug string) error {
	return s.assignRoleBySlug(ctx, userID, slug)
}
func (s *Service) UpsertRoleBySlug(ctx context.Context, name, slug string, description *string) error {
	return s.upsertRoleBySlug(ctx, name, slug, description)
}
func (s *Service) RemoveRoleBySlug(ctx context.Context, userID, slug string) error {
	return s.removeRoleBySlug(ctx, userID, slug)
}

// Public helpers for HTTP adapters
func (s *Service) ListRoleSlugsByUser(ctx context.Context, userID string) []string {
	return s.listRoleSlugsByUser(ctx, userID)
}
func (s *Service) GetEmailByUserID(ctx context.Context, id string) (string, error) {
	u, err := s.getUserByID(ctx, id)
	if err != nil || u == nil {
		return "", err
	}
	if u.Email == nil {
		return "", nil
	}
	return *u.Email, nil
}
func (s *Service) UpdateUsername(ctx context.Context, id, username string) error {
	return s.updateUsername(ctx, id, username)
}
func (s *Service) UpdateEmail(ctx context.Context, id, email string) error {
	return s.updateEmail(ctx, id, email)
}
func (s *Service) UpdateBiography(ctx context.Context, id string, bio *string) error {
	return s.updateBiography(ctx, id, bio)
}
func (s *Service) IsUserAllowed(ctx context.Context, userID string) (bool, error) {
	if s.pg == nil {
		return true, nil
	}
	u, err := s.getUserByID(ctx, userID)
	if err != nil || u == nil {
		return false, err
	}
	if err := s.ensureUserAccess(ctx, u); err != nil {
		if errors.Is(err, ErrUserBanned) || errors.Is(err, jwt.ErrTokenInvalidClaims) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// Admin listing/get/delete
type AdminUser struct {
	ID              string     `json:"id"`
	Email           *string    `json:"email"` // Nullable for phone-only users
	PhoneNumber     *string    `json:"phone_number"`
	Username        *string    `json:"username"`
	DiscordUsername *string    `json:"discord_username"`
	EmailVerified   bool       `json:"email_verified"`
	PhoneVerified   bool       `json:"phone_verified"`
	BannedAt        *time.Time `json:"banned_at,omitempty"`
	BannedUntil     *time.Time `json:"banned_until,omitempty"`
	BanReason       *string    `json:"ban_reason,omitempty"`
	BannedBy        *string    `json:"banned_by,omitempty"`
	DeletedAt       *time.Time `json:"deleted_at"`
	Biography       *string    `json:"biography"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
	LastLogin       *time.Time `json:"last_login"`
	Roles           []string   `json:"roles"`
	Entitlements    []string   `json:"entitlements"`
}

// AdminListUsersResult contains paginated user list with total count
type AdminListUsersResult struct {
	Users  []AdminUser `json:"users"`
	Total  int64       `json:"total"`
	Limit  int         `json:"limit"`
	Offset int         `json:"offset"`
}

// AdminUserStatus filters the directory by account state.
type AdminUserStatus string

const (
	AdminUserStatusActive  AdminUserStatus = "active"  // not deleted, not banned
	AdminUserStatusBanned  AdminUserStatus = "banned"  // not deleted, currently banned
	AdminUserStatusDeleted AdminUserStatus = "deleted" // soft-deleted
	AdminUserStatusAny     AdminUserStatus = "any"     // no deleted/banned predicate
	// "" (zero value) defaults to non-deleted (the historical "All users" behavior).
)

// AdminUserSort selects the directory ordering column.
type AdminUserSort string

const (
	AdminUserSortCreatedAt AdminUserSort = "created_at" // default
	AdminUserSortLastLogin AdminUserSort = "last_login"
	AdminUserSortUsername  AdminUserSort = "username"
	AdminUserSortEmail     AdminUserSort = "email"
)

// AdminUserListOptions is the GENERIC admin user-directory query (issue #91). It
// carries no host product knowledge: Role is any global-role slug, OrgSlug is any
// org slug, Status/Sort are closed enums. Entitlement filtering delegates to the
// billing provider (EntitlementFilterProvider), never a cross-schema join.
type AdminUserListOptions struct {
	Page        int
	PageSize    int
	Search      string          // ILIKE over username/email/phone_number
	Role        string          // global-role slug (e.g. "admin"); empty = no role filter
	OrgSlug     string          // org membership; empty = no org filter
	Status      AdminUserStatus // empty = non-deleted (historical default)
	Sort        AdminUserSort   // empty = created_at
	Desc        bool            // true = descending
	Entitlement string          // empty = no entitlement filter; else provider-backed
}

// ErrEntitlementFilterUnavailable is returned by AdminListUsers/AdminCountUsers
// when an Entitlement filter is requested but no EntitlementFilterProvider is
// configured — fail loud rather than silently return everyone.
var ErrEntitlementFilterUnavailable = errors.New("authkit: entitlement filtering requires an EntitlementFilterProvider")

func (o AdminUserListOptions) normalize() AdminUserListOptions {
	if o.Page <= 0 {
		o.Page = 1
	}
	if o.PageSize <= 0 || o.PageSize > 200 {
		o.PageSize = 50
	}
	return o
}

// adminUserDirectoryQuery builds the shared FROM + WHERE + args for the directory
// list and count (no ORDER BY / pagination). When an Entitlement filter is set it
// resolves the subject set via the provider HERE, so list and count agree and the
// provider is hit once per call.
func (s *Service) adminUserDirectoryQuery(ctx context.Context, o AdminUserListOptions) (from string, where []string, args []any, err error) {
	from = "profiles.users u"
	args = []any{}
	argIdx := 1

	switch o.Status {
	case AdminUserStatusActive:
		where = append(where, "u.deleted_at IS NULL", "u.banned_at IS NULL")
	case AdminUserStatusBanned:
		where = append(where, "u.deleted_at IS NULL", "u.banned_at IS NOT NULL")
	case AdminUserStatusDeleted:
		where = append(where, "u.deleted_at IS NOT NULL")
	case AdminUserStatusAny:
		// no deleted/banned predicate
	default:
		where = append(where, "u.deleted_at IS NULL")
	}

	if slug := strings.TrimSpace(o.Role); slug != "" {
		// "role" now filters on a user's Layer-2 platform role (the legacy global
		// roles plane was hard-cut). admin == the seeded super-admin role.
		if strings.EqualFold(slug, "admin") {
			slug = PlatformSuperAdminRole
		}
		from += " JOIN profiles.platform_user_roles pur ON pur.user_id = u.id AND pur.role = $" + fmt.Sprint(argIdx)
		args = append(args, slug)
		argIdx++
	}

	if slug := strings.TrimSpace(o.OrgSlug); slug != "" {
		from += " JOIN profiles.org_memberships m ON m.member_id = u.id::text AND m.member_kind = 'user' JOIN profiles.orgs o ON o.id = m.org_id AND o.deleted_at IS NULL AND o.slug = $" + fmt.Sprint(argIdx)
		args = append(args, slug)
		argIdx++
	}

	if search := strings.TrimSpace(o.Search); search != "" {
		where = append(where, "(u.username ILIKE $"+fmt.Sprint(argIdx)+" OR u.email ILIKE $"+fmt.Sprint(argIdx)+" OR u.phone_number ILIKE $"+fmt.Sprint(argIdx)+")")
		args = append(args, "%"+search+"%")
		argIdx++
	}

	if ent := strings.TrimSpace(o.Entitlement); ent != "" {
		fp, ok := s.entitlements.(EntitlementFilterProvider)
		if !ok {
			return "", nil, nil, ErrEntitlementFilterUnavailable
		}
		subjects, ferr := fp.ListSubjectsWithEntitlement(ctx, ent)
		if ferr != nil {
			return "", nil, nil, fmt.Errorf("authkit: entitlement filter provider failed: %w", ferr)
		}
		where = append(where, "u.id::text = ANY($"+fmt.Sprint(argIdx)+"::text[])")
		args = append(args, subjects)
		argIdx++
	}

	if len(where) == 0 {
		where = append(where, "TRUE")
	}
	return from, where, args, nil
}

// adminUserOrderBy renders a safe ORDER BY (closed enum) with a stable id
// tiebreaker. Every column referenced is in the SELECT list so SELECT DISTINCT
// is legal.
func adminUserOrderBy(o AdminUserListOptions) string {
	col := "u.created_at"
	switch o.Sort {
	case AdminUserSortLastLogin:
		col = "u.last_login"
	case AdminUserSortUsername:
		col = "u.username"
	case AdminUserSortEmail:
		col = "u.email"
	}
	dir := "ASC"
	if o.Desc {
		dir = "DESC"
	}
	return col + " " + dir + ", u.id::text " + dir
}

// AdminCountUsers returns the number of users matching opts (same filters as
// AdminListUsers, ignoring pagination/sort).
func (s *Service) AdminCountUsers(ctx context.Context, opts AdminUserListOptions) (int64, error) {
	if s.pg == nil {
		return 0, nil
	}
	from, where, args, err := s.adminUserDirectoryQuery(ctx, opts)
	if err != nil {
		return 0, err
	}
	q := db.RewriteSQL("SELECT COUNT(DISTINCT u.id) FROM "+from+" WHERE "+strings.Join(where, " AND "), s.dbSchema())
	var total int64
	if err := s.pg.QueryRow(ctx, q, args...).Scan(&total); err != nil {
		return 0, err
	}
	return total, nil
}

// AdminListUsers is the generic admin user-directory list (issue #91): generic
// role/org/status filter + search + sort + offset pagination, with optional
// provider-backed entitlement filtering. Each row is enriched with role slugs
// and (via the entitlements provider) entitlement names.
func (s *Service) AdminListUsers(ctx context.Context, opts AdminUserListOptions) (*AdminListUsersResult, error) {
	opts = opts.normalize()
	if s.pg == nil {
		return &AdminListUsersResult{Users: []AdminUser{}, Total: 0, Limit: opts.PageSize, Offset: 0}, nil
	}
	offset := (opts.Page - 1) * opts.PageSize

	from, where, args, err := s.adminUserDirectoryQuery(ctx, opts)
	if err != nil {
		return nil, err
	}

	// Intentionally raw pgx (not sqlc): the filter/search/pagination clauses are
	// assembled at runtime, which sqlc's static compilation cannot express.
	// Written against the default "profiles." qualifier and rewritten to the
	// configured schema, same mechanism as the sqlc path (issue 69).
	countQuery := db.RewriteSQL("SELECT COUNT(DISTINCT u.id) FROM "+from+" WHERE "+strings.Join(where, " AND "), s.dbSchema())
	var total int64
	if err := s.pg.QueryRow(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, err
	}

	argIdx := len(args) + 1
	selectCols := "u.id::text, u.email, u.phone_number, u.username, u.discord_username, u.email_verified, u.phone_verified, u.banned_at, u.banned_until, u.ban_reason, u.banned_by, u.deleted_at, u.biography, u.created_at, u.updated_at, u.last_login"
	query := "SELECT DISTINCT " + selectCols + " FROM " + from + " WHERE " + strings.Join(where, " AND ") + " ORDER BY " + adminUserOrderBy(opts) + " OFFSET $" + fmt.Sprint(argIdx) + " LIMIT $" + fmt.Sprint(argIdx+1)
	args = append(args, offset, opts.PageSize)

	rows, err := s.pg.Query(ctx, db.RewriteSQL(query, s.dbSchema()), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AdminUser
	for rows.Next() {
		var a AdminUser
		if err := rows.Scan(&a.ID, &a.Email, &a.PhoneNumber, &a.Username, &a.DiscordUsername, &a.EmailVerified, &a.PhoneVerified, &a.BannedAt, &a.BannedUntil, &a.BanReason, &a.BannedBy, &a.DeletedAt, &a.Biography, &a.CreatedAt, &a.UpdatedAt, &a.LastLogin); err != nil {
			return nil, err
		}
		a.Roles = s.listRoleSlugsByUser(ctx, a.ID)
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	s.enrichEntitlements(ctx, out)
	return &AdminListUsersResult{Users: out, Total: total, Limit: opts.PageSize, Offset: offset}, nil
}

// enrichEntitlements fills Entitlements for a page of users: one provider call
// when the provider implements BatchEntitlementsProvider, per-user otherwise.
// Provider failures log and degrade to no entitlements.
func (s *Service) enrichEntitlements(ctx context.Context, users []AdminUser) {
	if s.entitlements == nil || len(users) == 0 {
		return
	}
	if bp, ok := s.entitlements.(BatchEntitlementsProvider); ok {
		ids := make([]string, 0, len(users))
		for i := range users {
			ids = append(ids, users[i].ID)
		}
		ents, err := bp.ListEntitlementsBatch(ctx, ids)
		if err != nil {
			stdlog.Printf("authkit: error: batch entitlements provider failed for %d users; reporting no entitlements: %v", len(users), err)
			return
		}
		for i := range users {
			users[i].Entitlements = ents[users[i].ID]
		}
		return
	}
	for i := range users {
		users[i].Entitlements = s.ListEntitlements(ctx, users[i].ID)
	}
}

func (s *Service) AdminGetUser(ctx context.Context, id string) (*AdminUser, error) {
	u, err := s.getUserByID(ctx, id)
	if err != nil || u == nil {
		return nil, err
	}
	a := &AdminUser{
		ID: u.ID, Email: u.Email, PhoneNumber: u.PhoneNumber, Username: u.Username, DiscordUsername: u.DiscordUsername,
		EmailVerified: u.EmailVerified, PhoneVerified: u.PhoneVerified,
		BannedAt: u.BannedAt, BannedUntil: u.BannedUntil, BanReason: u.BanReason, BannedBy: u.BannedBy, DeletedAt: u.DeletedAt,
		Biography: u.Biography, CreatedAt: u.CreatedAt, UpdatedAt: u.UpdatedAt, LastLogin: u.LastLogin,
	}
	a.Roles = s.listRoleSlugsByUser(ctx, id)
	a.Entitlements = s.ListEntitlements(ctx, id)
	return a, nil
}

func (s *Service) AdminDeleteUser(ctx context.Context, id string) error {
	if s.pg == nil {
		return nil
	}
	// Revoke all sessions
	_ = s.q.SessionsRevokeAllQuiet(ctx, db.SessionsRevokeAllQuietParams{UserID: id, Issuer: s.opts.Issuer})
	// Delete user
	return s.q.UserDeleteHard(ctx, id)
}

// Additional public helpers used by OIDC flow
func (s *Service) GetProviderLink(ctx context.Context, providerSlug, subject string) (string, *string, error) {
	return s.getProviderLinkBySlug(ctx, providerSlug, subject)
}
func (s *Service) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	return s.getUserByEmail(ctx, email)
}
func (s *Service) GetUserByUsername(ctx context.Context, username string) (*User, error) {
	return s.getUserByUsername(ctx, username)
}
func (s *Service) CreateUser(ctx context.Context, email, username string) (*User, error) {
	return s.createUser(ctx, email, username)
}
func (s *Service) LinkProvider(ctx context.Context, userID, provider, subject string, email *string) error {
	return s.linkProvider(ctx, userID, provider, subject, email)
}
func (s *Service) SetProviderUsername(ctx context.Context, userID, provider, subject, username string) error {
	return s.setProviderUsername(ctx, userID, provider, subject, username)
}
func (s *Service) GetProviderUsername(ctx context.Context, userID, provider string) (string, error) {
	return s.getProviderUsername(ctx, userID, provider)
}

// Convenience: Discord username
func (s *Service) GetDiscordUsername(ctx context.Context, userID string) (string, error) {
	return s.getProviderUsername(ctx, userID, "discord")
}
func (s *Service) SetEmailVerified(ctx context.Context, id string, v bool) error {
	return s.setEmailVerified(ctx, id, v)
}
func (s *Service) UpsertPasswordHash(ctx context.Context, userID, hash, algo string, params []byte) error {
	return s.upsertPasswordHash(ctx, userID, hash, algo, params)
}
func (s *Service) DeriveUsername(email string) string { return deriveUsername(email) }

// LogSessionCreated records a session creation event via the configured AuthEventLogger (best-effort).
func (s *Service) LogSessionCreated(ctx context.Context, userID string, method string, sessionID string, ip *string, ua *string) {
	if s.authlog == nil {
		return
	}
	m := strings.TrimSpace(method)
	var mPtr *string
	if m != "" {
		mPtr = &m
	}
	e := AuthSessionEvent{
		OccurredAt: time.Now().UTC(),
		Issuer:     s.opts.Issuer,
		UserID:     userID,
		SessionID:  sessionID,
		Event:      SessionEventCreated,
		Method:     mPtr,
		Reason:     nil,
		IPAddr:     ip,
		UserAgent:  ua,
	}
	_ = s.authlog.LogSessionEvent(ctx, e)
}

func (s *Service) logSessionRevoked(ctx context.Context, userID string, sessionID string, reason *string) {
	if s.authlog == nil {
		return
	}
	e := AuthSessionEvent{
		OccurredAt: time.Now().UTC(),
		Issuer:     s.opts.Issuer,
		UserID:     userID,
		SessionID:  sessionID,
		Event:      SessionEventRevoked,
		Method:     nil,
		Reason:     reason,
		IPAddr:     nil,
		UserAgent:  nil,
	}
	_ = s.authlog.LogSessionEvent(ctx, e)
}

// LogPasswordChanged records a password change event for a user (best-effort).
func (s *Service) LogPasswordChanged(ctx context.Context, userID string, sessionID string, ip *string, ua *string) {
	if s.authlog == nil {
		return
	}
	e := AuthSessionEvent{
		OccurredAt: time.Now().UTC(),
		Issuer:     s.opts.Issuer,
		UserID:     userID,
		SessionID:  sessionID,
		Event:      SessionEventPasswordChange,
		Method:     nil,
		Reason:     nil,
		IPAddr:     ip,
		UserAgent:  ua,
	}
	_ = s.authlog.LogSessionEvent(ctx, e)
}

// LogPasswordRecovery records a password recovery event for a user (best-effort).

func (s *Service) LogPasswordRecovery(ctx context.Context, userID string, method, sessionID string, ip *string, ua *string) {
	if s.authlog == nil {
		return
	}
	e := AuthSessionEvent{
		OccurredAt: time.Now().UTC(),
		Issuer:     s.opts.Issuer,
		UserID:     userID,
		SessionID:  sessionID,
		Event:      SessionEventPasswordRecovery,
		Method:     &method,
		Reason:     nil,
		IPAddr:     ip,
		UserAgent:  ua,
	}
	_ = s.authlog.LogSessionEvent(ctx, e)
}

// LogSessionFailed records a failed session event for a user (best-effort).

func (s *Service) LogSessionFailed(ctx context.Context, userID string, sessionID string, reason *string, ip *string, ua *string) {
	if s.authlog == nil {
		return
	}
	e := AuthSessionEvent{
		OccurredAt: time.Now().UTC(),
		Issuer:     s.opts.Issuer,
		UserID:     userID,
		SessionID:  sessionID,
		Event:      SessionEventFailed,
		Method:     nil,
		Reason:     reason,
		IPAddr:     ip,
		UserAgent:  ua,
	}
	_ = s.authlog.LogSessionEvent(ctx, e)
}

// SendWelcome triggers the welcome email if an EmailSender is configured.
func (s *Service) SendWelcome(ctx context.Context, userID string) {
	if s.email == nil || s.pg == nil || strings.TrimSpace(userID) == "" {
		return
	}
	// Look up user's email and username
	u, err := s.getUserByID(ctx, userID)
	if err != nil || u == nil || u.Email == nil {
		return
	}
	username := ""
	if u.Username != nil {
		username = *u.Username
	}
	sendCtx := s.contextWithUserPreferredLocale(ctx, userID)
	_ = s.email.SendWelcome(sendCtx, *u.Email, username)
}

// Provider link management
func (s *Service) countProviderLinks(ctx context.Context, userID string) int {
	if s.pg == nil {
		return 0
	}
	n, _ := s.q.UserProvidersCount(ctx, userID)
	return int(n)
}
func (s *Service) hasPassword(ctx context.Context, userID string) bool {
	if s.pg == nil {
		return false
	}
	exists, _ := s.q.UserHasPassword(ctx, userID)
	return exists
}
func (s *Service) unlinkProvider(ctx context.Context, userID, provider string) error {
	if s.pg == nil {
		return nil
	}
	return s.q.UserProviderDeleteBySlug(ctx, db.UserProviderDeleteBySlugParams{UserID: userID, ProviderSlug: &provider})
}

// Public wrappers
func (s *Service) CountProviderLinks(ctx context.Context, userID string) int {
	return s.countProviderLinks(ctx, userID)
}
func (s *Service) HasPassword(ctx context.Context, userID string) bool {
	return s.hasPassword(ctx, userID)
}
func (s *Service) UnlinkProvider(ctx context.Context, userID, provider string) error {
	return s.unlinkProvider(ctx, userID, provider)
}

// Issuer-based provider link helpers (preferred)
func (s *Service) GetProviderLinkByIssuer(ctx context.Context, issuer, subject string) (string, *string, error) {
	return s.getProviderLinkByIssuerInternal(ctx, issuer, subject)
}
func (s *Service) LinkProviderByIssuer(ctx context.Context, userID, issuer, providerSlug, subject string, email *string) error {
	// Store provider slug for UI, enforce uniqueness on (issuer, subject) and (user_id, issuer)
	// Remove any existing provider link for this user+issuer with different subject (allows switching Discord accounts)
	if s.pg == nil {
		return nil
	}
	// First delete old Discord link if user is switching to a different Discord account
	_ = s.q.UserProviderDeleteOtherSubjects(ctx, db.UserProviderDeleteOtherSubjectsParams{UserID: userID, Issuer: issuer, Subject: subject})
	// Then insert/update the new link
	providerID, err := newUUIDV7String()
	if err != nil {
		return err
	}
	if err := s.q.UserProviderUpsertByIssuer(ctx, db.UserProviderUpsertByIssuerParams{
		ID:              providerID,
		UserID:          userID,
		Issuer:          issuer,
		ProviderSlug:    &providerSlug,
		Subject:         subject,
		EmailAtProvider: email,
	}); err != nil {
		return err
	}
	if providerSlug == SolanaProviderSlug && issuer == s.solanaIssuer() {
		s.maybeResolveSolanaSNSAfterLink(ctx, userID, subject)
	}
	return nil
}

// ListEntitlements returns current entitlement names for a user (fresh from
// the provider). A provider failure is logged and returned as none — callers
// (admin user views) degrade rather than fail.
func (s *Service) ListEntitlements(ctx context.Context, userID string) []string {
	if s.entitlements == nil {
		return nil
	}
	ents, err := s.entitlements.ListEntitlements(ctx, userID)
	if err != nil {
		stdlog.Printf("authkit: error: entitlements provider failed for user %s; reporting no entitlements: %v", userID, err)
		return nil
	}
	return ents
}

func (s *Service) getProviderLinkByIssuerInternal(ctx context.Context, issuer, subject string) (userID string, email *string, err error) {
	if s.pg == nil {
		return "", nil, nil
	}
	row, err := s.q.ProviderLinkByIssuer(ctx, db.ProviderLinkByIssuerParams{Issuer: issuer, Subject: subject})
	if err != nil {
		return "", nil, err
	}
	return row.UserID, row.EmailAtProvider, nil
}

func (s *Service) getProviderLinkBySlug(ctx context.Context, providerSlug, subject string) (userID string, email *string, err error) {
	if s.pg == nil {
		return "", nil, nil
	}
	row, err := s.q.ProviderLinkBySlug(ctx, db.ProviderLinkBySlugParams{ProviderSlug: &providerSlug, Subject: subject})
	if err != nil {
		return "", nil, err
	}
	return row.UserID, row.EmailAtProvider, nil
}

func (s *Service) linkProvider(ctx context.Context, userID, issuer, subject string, email *string) error {
	if s.pg == nil {
		return nil
	}
	providerID, err := newUUIDV7String()
	if err != nil {
		return err
	}
	return s.q.UserProviderInsertSimple(ctx, db.UserProviderInsertSimpleParams{ID: providerID, UserID: userID, Issuer: issuer, Subject: subject, EmailAtProvider: email})
}

// setProviderUsername stores a provider-specific username into profile jsonb as {"username": <value>}.
func (s *Service) setProviderUsername(ctx context.Context, userID, issuer, subject, username string) error {
	if s.pg == nil {
		return nil
	}
	return s.q.UserProviderSetUsername(ctx, db.UserProviderSetUsernameParams{UserID: userID, Issuer: issuer, Subject: subject, Username: username})
}

// getProviderUsername fetches provider profile->>'username' for the given user (first match by provider).
func (s *Service) getProviderUsername(ctx context.Context, userID, provider string) (string, error) {
	if s.pg == nil {
		return "", nil
	}
	uname, err := s.q.UserProviderUsername(ctx, db.UserProviderUsernameParams{UserID: userID, ProviderSlug: &provider})
	if err != nil {
		return "", err
	}
	if uname == nil {
		return "", nil
	}
	return *uname, nil
}

// deriveUsername makes a safe username from email's local part.
func deriveUsername(email string) string {
	base := email
	if i := strings.Index(email, "@"); i > 0 {
		base = email[:i]
	}
	base = strings.ToLower(base)
	// keep alnum and underscore
	clean := make([]rune, 0, len(base))
	for _, r := range base {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' {
			clean = append(clean, r)
		}
	}
	if len(clean) == 0 {
		clean = []rune{'u', 's', 'e', 'r'}
	}
	if clean[0] < 'a' || clean[0] > 'z' {
		clean = append([]rune{'u'}, clean...)
	}
	if len(clean) > usernameMaxLen {
		clean = clean[:usernameMaxLen]
	}
	out := string(clean)
	if len(out) < usernameMinLen {
		out += "_user"
	}
	return out
}

// getDiscordUsername retrieves the discord username for a user, preferring the
// dedicated column on profiles.users and falling back to user_providers.profile JSON.
func (s *Service) getDiscordUsername(ctx context.Context, userID string) (string, error) {
	if s.pg == nil {
		return "", nil
	}
	// Prefer stored column
	if uname, err := s.q.UserDiscordUsername(ctx, userID); err == nil {
		if uname != nil {
			return *uname, nil
		}
	}
	// Fallback to provider profile JSON
	return s.getProviderUsername(ctx, userID, "discord")
}

// (legacy ChangePassword removed in favor of unified ChangePassword with session revocation)

// --- Pending Registration Helpers ---

// PendingRegistration represents an unverified registration
type PendingRegistration struct {
	Email           string
	Username        string
	PasswordHash    string
	PreferredLocale string
}

// GetPendingRegistrationByEmail looks up a pending registration by email.
func (s *Service) GetPendingRegistrationByEmail(ctx context.Context, email string) (*PendingRegistration, error) {
	if !s.useEphemeralStore() {
		return nil, nil
	}
	rec, ok := s.findPendingChangeByTarget(ctx, KindRegisterEmail, email)
	if !ok {
		return nil, nil
	}
	return &PendingRegistration{
		Email:           rec.Target,
		Username:        rec.Username,
		PasswordHash:    rec.PasswordHash,
		PreferredLocale: rec.PreferredLocale,
	}, nil
}

// GetPendingPhoneRegistrationByPhone looks up a pending phone registration by phone number.
// (PendingRegistration.Email carries the phone for phone registrations, preserving prior behavior.)
func (s *Service) GetPendingPhoneRegistrationByPhone(ctx context.Context, phone string) (*PendingRegistration, error) {
	if !s.useEphemeralStore() {
		return nil, nil
	}
	rec, ok := s.findPendingChangeByTarget(ctx, KindRegisterPhone, phone)
	if !ok {
		return nil, nil
	}
	return &PendingRegistration{
		Email:           rec.Target,
		Username:        rec.Username,
		PasswordHash:    rec.PasswordHash,
		PreferredLocale: rec.PreferredLocale,
	}, nil
}

// VerifyPendingPassword checks if the provided password matches the pending registration's hash.
// Returns true if password is correct, false otherwise.
func (s *Service) VerifyPendingPassword(ctx context.Context, email, pass string) bool {
	pr, err := s.GetPendingRegistrationByEmail(ctx, email)
	if err != nil || pr == nil {
		return false
	}

	// Pending registrations always use argon2id (from CreatePendingRegistration)
	ok, err := password.VerifyArgon2id(pr.PasswordHash, pass)
	return err == nil && ok
}

// VerifyPendingPhonePassword checks if the provided password matches the pending
// phone registration's hash. Returns true if password is correct, false otherwise.
func (s *Service) VerifyPendingPhonePassword(ctx context.Context, phone, pass string) bool {
	pr, err := s.GetPendingPhoneRegistrationByPhone(ctx, phone)
	if err != nil || pr == nil {
		return false
	}
	ok, err := password.VerifyArgon2id(pr.PasswordHash, pass)
	return err == nil && ok
}

// --- Two-Factor Authentication (2FA) ---

// TwoFactorSettings represents a user's 2FA configuration
type TwoFactorSettings struct {
	UserID      string
	Enabled     bool
	Method      string // "email" or "sms"
	PhoneNumber *string
	BackupCodes []string // Hashed backup codes
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// Enable2FA enables two-factor authentication for a user and generates backup codes.
// Returns the plaintext backup codes (caller must show these to user ONCE).
func (s *Service) Enable2FA(ctx context.Context, userID, method string, phoneNumber *string) ([]string, error) {
	if s.pg == nil {
		return nil, fmt.Errorf("postgres not configured")
	}

	// Validate method
	if method != "email" && method != "sms" {
		return nil, fmt.Errorf("invalid 2FA method: must be 'email' or 'sms'")
	}

	// If SMS, phone number is required
	if method == "sms" && (phoneNumber == nil || *phoneNumber == "") {
		return nil, fmt.Errorf("phone number required for SMS 2FA")
	}

	// Generate 10 backup codes (8-character alphanumeric)
	plaintextCodes := make([]string, 10)
	hashedCodes := make([]string, 10)
	for i := 0; i < 10; i++ {
		code := randAlphanumericUppercase(8) // Generate 8-char code
		plaintextCodes[i] = code
		hashedCodes[i] = sha256Hex(code)
	}

	// Insert or update 2FA settings
	if err := s.q.TwoFactorEnable(ctx, db.TwoFactorEnableParams{UserID: userID, Method: method, PhoneNumber: phoneNumber, BackupCodes: hashedCodes}); err != nil {
		return nil, err
	}

	return plaintextCodes, nil
}

// Disable2FA disables two-factor authentication for a user
func (s *Service) Disable2FA(ctx context.Context, userID string) error {
	if s.pg == nil {
		return fmt.Errorf("postgres not configured")
	}

	return s.q.TwoFactorDisable(ctx, userID)
}

// Get2FASettings retrieves a user's 2FA settings
func (s *Service) Get2FASettings(ctx context.Context, userID string) (*TwoFactorSettings, error) {
	if s.pg == nil {
		return nil, fmt.Errorf("postgres not configured")
	}

	row, err := s.q.TwoFactorSettingsByUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	return &TwoFactorSettings{
		UserID:      row.UserID,
		Enabled:     row.Enabled,
		Method:      row.Method,
		PhoneNumber: row.PhoneNumber,
		BackupCodes: row.BackupCodes,
		CreatedAt:   row.CreatedAt,
		UpdatedAt:   row.UpdatedAt,
	}, nil
}

// Require2FAForLogin sends a 2FA code to the user's configured method.
// Returns the destination (email/phone) where the code was sent.
// This should be called after successful password verification.
func (s *Service) Require2FAForLogin(ctx context.Context, userID string) (string, error) {
	// Get user's 2FA settings
	settings, err := s.Get2FASettings(ctx, userID)
	if err != nil {
		return "", fmt.Errorf("2FA not enabled")
	}
	if !settings.Enabled {
		return "", fmt.Errorf("2FA not enabled")
	}

	// Get user info for email/username
	user, err := s.AdminGetUser(ctx, userID)
	if err != nil {
		return "", err
	}

	// Generate 6-digit numeric code
	code := randAlphanumeric(6)
	hash := sha256Hex(code)

	// Determine destination
	var destination string
	if settings.Method == "email" {
		if user.Email == nil {
			return "", fmt.Errorf("no email address configured")
		}
		destination = *user.Email
	} else { // sms
		if settings.PhoneNumber == nil {
			return "", fmt.Errorf("no phone number configured for SMS 2FA")
		}
		destination = *settings.PhoneNumber
	}

	exp := time.Now().Add(10 * time.Minute) // 10 minute expiration for 2FA codes
	if s.useEphemeralStore() {
		if err := s.storeTwoFactorCode(ctx, userID, hash, settings.Method, destination, time.Until(exp)); err != nil {
			return "", err
		}
	} else {
		return "", fmt.Errorf("ephemeral store not configured")
	}

	// Send the code
	username := ""
	if user.Username != nil {
		username = *user.Username
	}

	if settings.Method == "email" {
		if s.email != nil {
			sendCtx := s.contextWithUserPreferredLocale(ctx, userID)
			if err := s.withSendTimeout(sendCtx, func(sendCtx context.Context) error {
				return s.email.SendLoginCode(sendCtx, destination, username, code)
			}); err != nil {
				return "", emailDeliveryError(err)
			}
		} else {
			// In production, require email to be configured for email 2FA
			if !s.isDevEnvironment() {
				return "", fmt.Errorf("email 2FA unavailable: email sender not configured (email 2FA requires email in production)")
			}
		}
	} else { // sms
		if s.sms != nil {
			sendCtx := s.contextWithUserPreferredLocale(ctx, userID)
			if err := s.withSendTimeout(sendCtx, func(sendCtx context.Context) error { return s.sms.SendLoginCode(sendCtx, destination, code) }); err != nil {
				return "", smsDeliveryError(err)
			}
		} else {
			// In production, require SMS to be configured for SMS 2FA
			if !s.isDevEnvironment() {
				return "", fmt.Errorf("SMS 2FA unavailable: SMS sender not configured (SMS 2FA requires delivery in production)")
			}
		}
	}

	return destination, nil
}

// Create2FAChallenge creates a short-lived challenge to prove password verification before 2FA.
func (s *Service) Create2FAChallenge(ctx context.Context, userID string) (string, error) {
	if !s.useEphemeralStore() {
		return "", fmt.Errorf("ephemeral store not configured")
	}
	challenge := randB64(32)
	hash := sha256Hex(challenge)
	if err := s.storeTwoFactorChallenge(ctx, userID, hash, 10*time.Minute); err != nil {
		return "", err
	}
	return challenge, nil
}

// Verify2FAChallenge verifies the challenge created during the password step.
func (s *Service) Verify2FAChallenge(ctx context.Context, userID, challenge string) (bool, error) {
	if strings.TrimSpace(challenge) == "" {
		return false, nil
	}
	if !s.useEphemeralStore() {
		return false, fmt.Errorf("ephemeral store not configured")
	}
	stored, ok, err := s.getTwoFactorChallenge(ctx, userID)
	if err != nil || !ok {
		return false, err
	}
	return stored == sha256Hex(challenge), nil
}

// Clear2FAChallenge removes the stored challenge after successful 2FA verification.
func (s *Service) Clear2FAChallenge(ctx context.Context, userID string) error {
	if !s.useEphemeralStore() {
		return fmt.Errorf("ephemeral store not configured")
	}
	return s.deleteTwoFactorChallenge(ctx, userID)
}

// Verify2FACode verifies a 2FA code entered by the user during login.
// Returns true if code is valid, false otherwise.
func (s *Service) Verify2FACode(ctx context.Context, userID, code string) (bool, error) {
	hash := sha256Hex(code)

	if s.useEphemeralStore() {
		return s.consumeTwoFactorCode(ctx, userID, hash)
	}
	return false, fmt.Errorf("ephemeral store not configured")
}

// VerifyBackupCode verifies a 2FA backup code for account recovery.
// On success, removes the used backup code from the user's backup codes.
func (s *Service) VerifyBackupCode(ctx context.Context, userID, backupCode string) (bool, error) {
	if s.pg == nil {
		return false, fmt.Errorf("postgres not configured")
	}

	settings, err := s.Get2FASettings(ctx, userID)
	if err != nil || !settings.Enabled {
		return false, fmt.Errorf("2FA not enabled")
	}

	hash := sha256Hex(backupCode)

	// Check if backup code exists
	found := false
	for _, hashedCode := range settings.BackupCodes {
		if hashedCode == hash {
			found = true
			break
		}
	}

	if !found {
		return false, nil
	}

	// Remove the used backup code
	newCodes := make([]string, 0, len(settings.BackupCodes)-1)
	for _, hashedCode := range settings.BackupCodes {
		if hashedCode != hash {
			newCodes = append(newCodes, hashedCode)
		}
	}

	if err := s.q.TwoFactorSetBackupCodes(ctx, db.TwoFactorSetBackupCodesParams{BackupCodes: newCodes, UserID: userID}); err != nil {
		return false, err
	}

	return true, nil
}

// RegenerateBackupCodes generates new backup codes for a user (invalidating old ones).
// Returns the plaintext codes (caller must show these to user ONCE).
func (s *Service) RegenerateBackupCodes(ctx context.Context, userID string) ([]string, error) {
	if s.pg == nil {
		return nil, fmt.Errorf("postgres not configured")
	}

	// Verify 2FA is enabled
	settings, err := s.Get2FASettings(ctx, userID)
	if err != nil || !settings.Enabled {
		return nil, fmt.Errorf("2FA not enabled")
	}

	// Generate 10 new backup codes
	plaintextCodes := make([]string, 10)
	hashedCodes := make([]string, 10)
	for i := 0; i < 10; i++ {
		code := randAlphanumericUppercase(8)
		plaintextCodes[i] = code
		hashedCodes[i] = sha256Hex(code)
	}

	if err := s.q.TwoFactorSetBackupCodes(ctx, db.TwoFactorSetBackupCodesParams{BackupCodes: hashedCodes, UserID: userID}); err != nil {
		return nil, err
	}

	return plaintextCodes, nil
}

// randAlphanumericUppercase generates a random uppercase alphanumeric string (A-Z, 0-9)
// Used for backup codes which are longer and case-sensitive
func randAlphanumericUppercase(n int) string {
	const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789" // Exclude ambiguous chars
	b := make([]byte, n)
	for i := 0; i < n; i++ {
		b[i] = chars[randInt(len(chars))]
	}
	return string(b)
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

// (SetUserActive removed; use BanUser/UnbanUser or SoftDeleteUser.)
