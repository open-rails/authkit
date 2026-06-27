package authcore

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
	authkit "github.com/open-rails/authkit"
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
	// Optional link building.
	BaseURL string
	// OIDCReturnPath is the host-owned frontend route that receives full-page OIDC login results.
	OIDCReturnPath            string
	FrontendVerifyPath        string
	FrontendPasswordResetPath string
	FrontendPasswordlessPath  string
	FrontendInvitePath        string
	PasskeyRPID               string
	PasskeyRPDisplayName      string
	PasskeyOrigins            []string
	PasskeyUserVerification   string
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

	// NativeUserRegistrationMode controls public native-user self-registration.
	NativeUserRegistrationMode RegistrationMode
	// PasswordlessLoginEnabled enables contact-based passwordless sessions.
	PasswordlessLoginEnabled bool
	// PasswordlessAutoRegistrationEnabled allows unknown verified contacts to
	// create no-password users during passwordless confirmation.
	PasswordlessAutoRegistrationEnabled bool

	// Environment is host-provided runtime mode used for dev/prod behavior checks.
	Environment string
	// SolanaNetwork is host-provided chain selector for SIWS flows. SNS resolution is
	// AuthKit-owned and always-on with a fixed timeout/cache — there is no host override.
	SolanaNetwork string

	// APIKeyPrefix is the issuing application's brand prefix for generated API
	// keys (validated lowercase-alnum, 1-16 chars; empty -> bare st_).
	APIKeyPrefix string
	// APIKeyMaxTTL caps a minted API key's expiry (0 = no cap).
	APIKeyMaxTTL time.Duration
	// TOTPSecretKey encrypts persisted authenticator-app shared secrets.
	TOTPSecretKey []byte
	// TwoFactorMode is the account-wide 2FA policy (Disabled/Optional/Required).
	// Empty is treated as Optional. Mapped from TwoFactorConfig.Mode.
	TwoFactorMode TwoFactorMode
	// TwoFactorMethods is the set of enabled second-factor channels. Empty means
	// all (email/sms/totp). Mapped from TwoFactorConfig.Methods.
	TwoFactorMethods []TwoFactorMethod
	// RequireMFAEnrollment forces every user to enroll a second factor: without
	// usable 2FA, a user cannot establish or refresh a session (returns
	// ErrTwoFAEnrollmentRequired). Derived from TwoFactorMode == Required.
	RequireMFAEnrollment bool
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
	ErrUserBanned = authkit.ErrUserBanned
	// ErrPasswordResetRequired indicates the account's stored password hash is
	// flagged HashAlgoLegacyResetRequired: no plaintext can ever verify against
	// it, so the user must complete a password reset before password auth (login,
	// step-up, change-password) can succeed. HTTP layers map this to the stable
	// code "password_reset_required".
	ErrPasswordResetRequired = authkit.ErrPasswordResetRequired
	// ErrUserNotFound indicates a user does not exist (or is not visible).
	ErrUserNotFound = authkit.ErrUserNotFound
	// ErrInvalidUntil indicates a time-limited operation has a non-future expiry.
	ErrInvalidUntil = authkit.ErrInvalidUntil
	// ErrEmailAlreadyVerified indicates an email verification request targeted an already-verified email.
	ErrEmailAlreadyVerified = authkit.ErrEmailAlreadyVerified
	// ErrPhoneAlreadyVerified indicates a phone verification request targeted an already-verified phone.
	ErrPhoneAlreadyVerified = authkit.ErrPhoneAlreadyVerified
	// ErrPendingRegistrationNotFound indicates a registration resend request did not match a pending registration.
	ErrPendingRegistrationNotFound = authkit.ErrPendingRegistrationNotFound
	// ErrRegistrationDisabled indicates a public user-creation path was attempted
	// while native-user registration is bootstrap-only. Existing-user
	// authentication is unaffected; only NEW account creation through
	// public/auto-registration is blocked.
	ErrRegistrationDisabled = authkit.ErrRegistrationDisabled
	// ErrVerificationLinkExpired indicates a verification link/token no longer has a pending verification record.
	ErrVerificationLinkExpired = authkit.ErrVerificationLinkExpired
	ErrEmailInUse              = authkit.ErrEmailInUse
	ErrPhoneInUse              = authkit.ErrPhoneInUse
	ErrEmailSenderUnavailable  = authkit.ErrEmailSenderUnavailable
	ErrSMSSenderUnavailable    = authkit.ErrSMSSenderUnavailable
	ErrPasswordlessDisabled    = authkit.ErrPasswordlessDisabled
)

const (
	defaultOIDCReturnPath            = "/login/callback"
	defaultFrontendVerifyPath        = "/verify"
	defaultFrontendPasswordResetPath = "/reset"
	defaultFrontendPasswordlessPath  = "/passwordless"
	defaultFrontendInvitePath        = "/accept-invite"
)

// (storage layer collapsed into direct Postgres/Redis helpers)

// Service is the core auth service used by HTTP adapters.
type Service struct {
	opts              Options
	keys              Keyset
	email             EmailSender
	sms               SMSSender
	pg                *pgxpool.Pool
	q                 *db.Queries
	schema            string       // validated Postgres schema name; db.DefaultSchema when unset
	groupSchema       *GroupSchema // #111 permission-group persona schema (nil ⇒ root-only default)
	entitlements      EntitlementsProvider
	authlog           *clickHouseAuthLog // session-event sink/reader; nil unless WithClickHouse
	solanaSNSResolver defaultSolanaSNSResolver
	// snsCacheTTLOverride is a test-only seam for forcing SNS cache staleness; 0 in
	// production, where solanaSNSCacheTTL() falls back to the fixed 24h constant.
	snsCacheTTLOverride time.Duration
	ephemeralStore      EphemeralStore
	ephemeralMode       EphemeralMode
	// cfg is the host Config this Service was built from, retained so the HTTP
	// transport (client-first NewServer) can read HTTP-layer config that rides in
	// Config but the engine doesn't consume (OIDC providers/descriptors). Zero
	// value for NewService-constructed (config-less) services.
	cfg            Config
	verifyWarnOnce sync.Once

	// SMS deliverability health, populated by CheckSMSHealth. Until a check has
	// run, SMS is considered available whenever a sender is configured (legacy
	// behavior). Once a check runs, phone flows gate on the result.
	smsHealthChecked atomic.Bool
	smsHealthy       atomic.Bool
	smsHealthReason  atomic.Value // string
}

func NewService(opts Options, keys Keyset, coreOpts ...Option) *Service {
	if mode, err := normalizeRegistrationMode(opts.NativeUserRegistrationMode); err == nil {
		opts.NativeUserRegistrationMode = mode
	}
	if strings.TrimSpace(opts.OIDCReturnPath) == "" {
		opts.OIDCReturnPath = defaultOIDCReturnPath
	}
	if strings.TrimSpace(opts.FrontendVerifyPath) == "" {
		opts.FrontendVerifyPath = defaultFrontendVerifyPath
	}
	if strings.TrimSpace(opts.FrontendPasswordResetPath) == "" {
		opts.FrontendPasswordResetPath = defaultFrontendPasswordResetPath
	}
	if strings.TrimSpace(opts.FrontendPasswordlessPath) == "" {
		opts.FrontendPasswordlessPath = defaultFrontendPasswordlessPath
	}
	if strings.TrimSpace(opts.FrontendInvitePath) == "" {
		opts.FrontendInvitePath = defaultFrontendInvitePath
	}
	opts.PasskeyUserVerification = normalizePasskeyUserVerification(opts.PasskeyUserVerification)
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
	s := &Service{opts: opts, keys: keys, schema: schema, ephemeralMode: EphemeralMemory, solanaSNSResolver: newDefaultSolanaSNSResolver()}
	for _, o := range coreOpts {
		if o != nil {
			o(s)
		}
	}
	return s
}

// NewFromConfig creates a Service from high-level Config + Stores.
// If Keys is nil, auto-discovers keys from environment variables, filesystem, or generates development keys.
func NewFromConfig(cfg Config, pg *pgxpool.Pool, extraOpts ...Option) (*Service, error) {
	// Handle nil Keys - auto-discover from env vars, <KeysPath>/keys.json, or
	// generate for dev. The filesystem directory is host-overridable via
	// cfg.Keys.Path, then the AUTHKIT_KEYS_PATH env var, defaulting to
	// /vault/auth so existing embedders are unchanged.
	keySource := cfg.Keys.Source
	if keySource == nil && cfg.Keys.VerifyOnly {
		// #87: explicit verify-only — NO signer and NO key discovery. Minting
		// returns ErrMissingSigner; verification, RBAC reads, and the (empty)
		// JWKS endpoint all work. A pure resource-server / control-plane boots
		// without any env/file/dev key.
		keySource = jwtkit.StaticKeySource{}
	}
	if keySource == nil {
		keysPath := strings.TrimSpace(cfg.Keys.Path)
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
	issuer := strings.TrimSpace(cfg.Token.Issuer)
	if issuer == "" {
		return nil, fmt.Errorf("authkit: Issuer is required (e.g., \"https://myapp.com\")")
	}
	baseURL := strings.TrimSpace(cfg.Frontend.BaseURL)
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
	oidcReturnPath, err := normalizeOIDCReturnPath(cfg.Frontend.OIDCReturnPath)
	if err != nil {
		return nil, err
	}
	frontendVerifyPath, err := normalizeFrontendPath("FrontendVerifyPath", cfg.Frontend.VerifyPath, defaultFrontendVerifyPath)
	if err != nil {
		return nil, err
	}
	frontendPasswordResetPath, err := normalizeFrontendPath("FrontendPasswordResetPath", cfg.Frontend.PasswordResetPath, defaultFrontendPasswordResetPath)
	if err != nil {
		return nil, err
	}
	frontendPasswordlessPath, err := normalizeFrontendPath("FrontendPasswordlessPath", cfg.Frontend.PasswordlessPath, defaultFrontendPasswordlessPath)
	if err != nil {
		return nil, err
	}
	frontendInvitePath, err := normalizeFrontendPath("FrontendInvitePath", cfg.Frontend.InvitePath, defaultFrontendInvitePath)
	if err != nil {
		return nil, err
	}
	passkeyRPID, passkeyName, passkeyOrigins, passkeyUV, err := normalizePasskeyConfig(cfg.Passkeys, baseURL, issuer)
	if err != nil {
		return nil, err
	}

	issuedAudiences := cfg.Token.IssuedAudiences
	if len(issuedAudiences) == 0 {
		return nil, fmt.Errorf("authkit: IssuedAudiences is required (e.g., []string{\"myapp\", \"billing-app\"})")
	}
	expectedAudiences := cfg.Token.ExpectedAudiences
	if len(expectedAudiences) == 0 {
		return nil, fmt.Errorf("authkit: ExpectedAudiences is required (e.g., []string{\"myapp\"})")
	}

	maxSess := cfg.Token.SessionMaxPerUser
	if maxSess == 0 {
		maxSess = 3
	}
	accessTTL := cfg.Token.AccessTokenDuration
	if accessTTL == 0 {
		// Short default bounds revocation lag (logout / ban / password-change)
		// to one TTL window; refresh-token rotation re-issues silently. See
		// authkit #90 — we deliberately rely on this bound instead of a
		// per-request jti/liveness lookup.
		accessTTL = 15 * time.Minute
	}
	refTTL := cfg.Token.RefreshTokenDuration // 0 or less => indefinite sessions

	registrationVerification, err := normalizeRegistrationVerification(cfg.Registration.Verification)
	if err != nil {
		return nil, err
	}
	nativeUserRegistrationMode, err := normalizeRegistrationMode(cfg.Registration.NativeUserMode)
	if err != nil {
		return nil, fmt.Errorf("authkit: invalid NativeUserRegistrationMode %q (want one of: open, invite_only, closed)", cfg.Registration.NativeUserMode)
	}
	tokenPrefix := strings.TrimSpace(cfg.APIKeys.Prefix)
	if !validAPIKeyPrefix(tokenPrefix) {
		return nil, fmt.Errorf("authkit: invalid APIKeyPrefix %q (want lowercase alphanumeric, 1-16 chars, or empty)", tokenPrefix)
	}
	maxTTL := cfg.APIKeys.MaxTTL
	schema := strings.TrimSpace(cfg.Schema)
	if schema == "" {
		schema = db.DefaultSchema
	}
	if !db.ValidSchemaName(schema) {
		return nil, fmt.Errorf("authkit: invalid Schema %q (want lowercase identifier matching ^[a-z_][a-z0-9_]*$, max 63 bytes)", cfg.Schema)
	}
	opts := Options{
		Issuer:                              issuer,
		IssuedAudiences:                     issuedAudiences,
		ExpectedAudiences:                   expectedAudiences,
		AccessTokenDuration:                 accessTTL,
		RefreshTokenDuration:                refTTL,
		SessionMaxPerUser:                   maxSess,
		BaseURL:                             baseURL,
		OIDCReturnPath:                      oidcReturnPath,
		FrontendVerifyPath:                  frontendVerifyPath,
		FrontendPasswordResetPath:           frontendPasswordResetPath,
		FrontendPasswordlessPath:            frontendPasswordlessPath,
		FrontendInvitePath:                  frontendInvitePath,
		PasskeyRPID:                         passkeyRPID,
		PasskeyRPDisplayName:                passkeyName,
		PasskeyOrigins:                      passkeyOrigins,
		PasskeyUserVerification:             passkeyUV,
		Schema:                              schema,
		RegistrationVerification:            registrationVerification,
		NativeUserRegistrationMode:          nativeUserRegistrationMode,
		PasswordlessLoginEnabled:            cfg.Registration.PasswordlessLogin,
		PasswordlessAutoRegistrationEnabled: cfg.Registration.PasswordlessAutoRegistration,
		Environment:                         strings.TrimSpace(cfg.Environment),
		SolanaNetwork:                       strings.TrimSpace(cfg.SolanaNetwork),
		APIKeyPrefix:                        tokenPrefix,
		APIKeyMaxTTL:                        maxTTL,
		TOTPSecretKey:                       append([]byte(nil), cfg.TwoFactor.TOTPSecretKey...),
		TwoFactorMode:                       normalizeTwoFactorMode(cfg.TwoFactor.Mode),
		TwoFactorMethods:                    append([]TwoFactorMethod(nil), cfg.TwoFactor.Methods...),
		RequireMFAEnrollment:                normalizeTwoFactorMode(cfg.TwoFactor.Mode) == TwoFactorRequired,
	}
	// pg is positional but MAY be nil at the core layer (verify-only construction
	// or config-only unit tests need no store); WithPostgres(nil) is a no-op, so a
	// nil pg simply yields a Service with no querier. The mandatory-Postgres
	// contract (#106) is enforced at the host-facing authhttp.NewServer, not here.
	coreOpts := append([]Option{WithPostgres(pg)}, extraOpts...)
	svc := NewService(opts, ks, coreOpts...)
	// #111: build + validate the permission-group schema (intrinsic root injected
	// when the app declares none). A bad catalog/containment fails construction.
	gs, gerr := BuildSchema(cfg.RBAC...)
	if gerr != nil {
		return nil, fmt.Errorf("permission-group schema: %w", gerr)
	}
	svc.groupSchema = gs
	svc.cfg = cfg
	return svc, nil
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
		RegistrationModeClosed:
		return value, nil
	default:
		return "", fmt.Errorf("invalid_registration_mode")
	}
}

func normalizeOIDCReturnPath(raw string) (string, error) {
	return normalizeFrontendPath("OIDCReturnPath", raw, defaultOIDCReturnPath)
}

func normalizeFrontendPath(name, raw, defaultPath string) (string, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return defaultPath, nil
	}
	if strings.Contains(value, "#") {
		return "", fmt.Errorf("authkit: %s must not contain a fragment", name)
	}
	u, err := url.Parse(value)
	if err != nil {
		return "", fmt.Errorf("authkit: invalid %s %q: %w", name, raw, err)
	}
	if u.IsAbs() || u.Host != "" || strings.HasPrefix(value, "//") {
		return "", fmt.Errorf("authkit: %s must be a relative absolute-path, got %q", name, raw)
	}
	if u.Path == "" || !strings.HasPrefix(u.Path, "/") {
		return "", fmt.Errorf("authkit: %s must start with '/', got %q", name, raw)
	}
	if u.Fragment != "" {
		return "", fmt.Errorf("authkit: %s must not contain a fragment", name)
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

// PublicNativeUserRegistrationEnabled reports whether public native-user
// self-registration / auto-registration is allowed.
func (o Options) PublicNativeUserRegistrationEnabled() bool {
	mode, err := normalizeRegistrationMode(o.NativeUserRegistrationMode)
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

	if u.PhoneNumber != nil && strings.EqualFold(*u.PhoneNumber, trimmed) {
		if u.PhoneVerified {
			return ErrPhoneAlreadyVerified
		}
		return s.SendPhoneVerificationToUser(ctx, trimmed, userID, 0)
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

	msg := VerificationMessage{Code: code, LinkURL: s.phoneVerificationURL(linkToken), Purpose: "contact_change"}

	// Send verification message to new phone
	if s.sms != nil {
		sendCtx := s.contextWithUserPreferredLanguage(ctx, userID)
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

// ConfirmPhoneChangeByToken applies a pending phone change using its high-entropy link token.
func (s *Service) ConfirmPhoneChangeByToken(ctx context.Context, token string) (string, error) {
	return s.consumePendingChangeByToken(ctx, sha256Hex(token), KindChangePhone)
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

	msg := VerificationMessage{Code: code, LinkURL: s.phoneVerificationURL(linkToken), Purpose: "contact_change"}
	// Send new credentials.
	if s.sms != nil {
		sendCtx := s.contextWithUserPreferredLanguage(ctx, userID)
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
	return s.q.UserSetPhoneVerifiedByID(ctx, db.UserSetPhoneVerifiedByIDParams{ID: id, PhoneVerified: v})
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
		sendCtx := s.contextWithUserPreferredLanguage(ctx, userID)
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
		_, err := s.CreatePendingRegistrationWithLanguage(ctx, email, pending.Username, pending.PasswordHash, ttl, pending.PreferredLanguage)
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
		return err
	}
	username := ""
	if u.Username != nil {
		username = *u.Username
	}
	msg := VerificationMessage{Code: code, LinkURL: s.emailVerificationURL(linkToken), Purpose: "contact_verify"}
	if err := msg.Validate(); err != nil {
		return nil
	}
	if s.email != nil {
		sendCtx := s.contextWithUserPreferredLanguage(ctx, u.ID)
		if err := s.withSendTimeout(sendCtx, func(sendCtx context.Context) error { return s.email.SendVerification(sendCtx, *u.Email, username, msg) }); err != nil {
			return emailDeliveryError(err)
		}
	} else if !s.isDevEnvironment() {
		return fmt.Errorf("email verification unavailable: email sender not configured")
	}
	return nil
}

// ConfirmEmailVerification verifies a short typed code for a SPECIFIC email and
// marks email_verified = true. The code is only 6 digits, so it is brute-force
// resistant ONLY because it is scoped to the address it was issued to (a guessed
// code that happens to match another account's record is rejected here without
// being consumed) and the HTTP layer caps attempts per-identifier (AK security
// audit F1). For the unguessable 256-bit emailed link token use
// ConfirmEmailVerificationByToken instead.
func (s *Service) ConfirmEmailVerification(ctx context.Context, email, code string) (userID string, err error) {
	if s.pg == nil {
		return "", jwt.ErrTokenUnverifiable
	}
	if !s.useEphemeralStore() {
		return "", jwt.ErrTokenUnverifiable
	}
	email = NormalizeEmail(strings.TrimSpace(email))
	if email == "" {
		return "", jwt.ErrTokenInvalidClaims
	}
	tokenHash := sha256Hex(code)
	data, ok := s.peekEmailVerification(ctx, tokenHash)
	if !ok {
		return "", jwt.ErrTokenUnverifiable
	}
	// Email-scope: the short code is honored only for the address it was issued
	// to. Do NOT consume on mismatch — leave the legitimate owner's code intact.
	if data.Email == nil || !strings.EqualFold(NormalizeEmail(*data.Email), email) {
		return "", jwt.ErrTokenInvalidClaims
	}
	u, err := s.getUserByID(ctx, data.UserID)
	if err != nil || u == nil {
		return "", errOrUnauthorized(err)
	}
	// The supplied address must still be the account's current email.
	if u.Email == nil || !strings.EqualFold(*u.Email, email) {
		return "", jwt.ErrTokenInvalidClaims
	}
	if err := s.setEmailVerified(ctx, data.UserID, true); err != nil {
		return "", err
	}
	s.deleteEmailVerificationByToken(ctx, tokenHash)
	return data.UserID, nil
}

// ConfirmEmailVerificationByToken verifies the 256-bit emailed link token and
// marks email_verified = true. The token's own entropy is the security boundary
// (it is unguessable), so this path is global-lookup and needs no email scoping.
func (s *Service) ConfirmEmailVerificationByToken(ctx context.Context, token string) (userID string, err error) {
	if s.pg == nil {
		return "", jwt.ErrTokenUnverifiable
	}
	rec, err := s.useEmailVerifyToken(ctx, sha256Hex(token))
	if err != nil {
		return "", err
	}
	u, err := s.getUserByID(ctx, rec.UserID)
	if err != nil || u == nil {
		return "", errOrUnauthorized(err)
	}
	if rec.Email != nil && u.Email != nil && !strings.EqualFold(*u.Email, *rec.Email) {
		// Email changed since request; token consumed but invalid for current address.
		return "", jwt.ErrTokenInvalidClaims
	}
	if err := s.setEmailVerified(ctx, rec.UserID, true); err != nil {
		return "", err
	}
	return rec.UserID, nil
}

// --- Pending Registration (for email/password signups) ---

// CreatePendingRegistration creates a pending registration and sends verification email.
// Returns token for verification. Allows duplicate pending registrations (last one wins).
func (s *Service) CreatePendingRegistration(ctx context.Context, email, username, passwordHash string, ttl time.Duration) (string, error) {
	return s.CreatePendingRegistrationWithLanguage(ctx, email, username, passwordHash, ttl, "")
}

func (s *Service) CreatePendingRegistrationWithLanguage(ctx context.Context, email, username, passwordHash string, ttl time.Duration, preferredLanguage string) (string, error) {
	allowed, err := s.registrationAllowedForEmail(ctx, email)
	if err != nil {
		return "", err
	}
	if !allowed {
		return "", ErrRegistrationDisabled
	}
	language, err := NormalizePreferredLanguage(preferredLanguage)
	if err != nil {
		return "", err
	}
	sendCtx := contextWithPreferredLanguage(ctx, language)
	switch s.opts.RegistrationVerificationPolicy() {
	case RegistrationVerificationNone:
		userID, err := s.createEmailRegistrationUser(ctx, email, username, passwordHash, true)
		if err != nil {
			return "", err
		}
		if language != "" {
			if err := s.SetPreferredLanguage(ctx, userID, language); err != nil {
				return "", err
			}
		}
		if err := s.consumeAccountRegistrationInvite(ctx, email, userID); err != nil {
			return "", err
		}
		return "", nil
	case RegistrationVerificationOptional:
		verified := s.email == nil
		userID, err := s.createEmailRegistrationUser(ctx, email, username, passwordHash, verified)
		if err != nil {
			return "", err
		}
		if language != "" {
			if err := s.SetPreferredLanguage(ctx, userID, language); err != nil {
				return "", err
			}
		}
		if verified {
			if err := s.consumeAccountRegistrationInvite(ctx, email, userID); err != nil {
				return "", err
			}
			return "", nil
		}
		if ttl <= 0 {
			ttl = defaultEmailVerificationTTL
		}
		code := randAlphanumeric(6)
		codeHash := sha256Hex(code)
		linkToken := randB64(32)
		linkHash := sha256Hex(linkToken)
		normEmail := NormalizeEmail(email)
		if err := s.storeEmailVerificationTokens(ctx, userID, &normEmail, map[string]time.Duration{
			codeHash: ttl,
			linkHash: defaultEmailVerificationTTL,
		}); err != nil {
			return "", err
		}
		msg := VerificationMessage{Code: code, LinkURL: s.emailVerificationURL(linkToken), Purpose: "signup"}
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
				Kind:              KindRegisterEmail,
				Target:            email,
				Username:          username,
				PasswordHash:      passwordHash,
				PreferredLanguage: language,
			}, map[string]time.Duration{
				codeHash: ttl,
				linkHash: defaultEmailVerificationTTL,
			}); err != nil {
				return "", err
			}
		} else {
			return "", fmt.Errorf("ephemeral store not configured")
		}

		msg := VerificationMessage{Code: code, LinkURL: s.emailVerificationURL(linkToken), Purpose: "signup"}
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

// ConfirmPendingRegistration finalizes a pending email registration from a short
// typed code scoped to a SPECIFIC email. Like ConfirmEmailVerification, the 6-digit
// code is brute-force resistant only because it is bound to the target address (a
// guessed code matching another pending signup is rejected without being consumed)
// and the HTTP layer caps attempts per-identifier (AK security audit F1). For the
// 256-bit emailed link token use ConfirmPendingRegistrationByToken instead.
func (s *Service) ConfirmPendingRegistration(ctx context.Context, email, code string) (userID string, err error) {
	if !s.opts.PublicNativeUserRegistrationEnabled() {
		return "", ErrRegistrationDisabled
	}
	if !s.useEphemeralStore() {
		return "", jwt.ErrTokenUnverifiable
	}
	email = NormalizeEmail(strings.TrimSpace(email))
	if email == "" {
		return "", jwt.ErrTokenInvalidClaims
	}
	tokenHash := sha256Hex(code)
	rec, ok, err := s.loadPendingChangeByToken(ctx, tokenHash)
	if err != nil || !ok || rec.Kind != KindRegisterEmail {
		return "", jwt.ErrTokenUnverifiable
	}
	// Email-scope the short code: only honor it for the address it was issued to.
	// Do NOT consume on mismatch — leave the legitimate signup's code intact.
	if !strings.EqualFold(normalizePendingTarget(KindRegisterEmail, rec.Target), email) {
		return "", jwt.ErrTokenInvalidClaims
	}
	// The register_email finalizer enforces "first to verify wins", creates the
	// verified user, and applies language.
	uid, err := s.finalizePendingChange(ctx, rec)
	if err != nil {
		return "", err
	}
	s.deletePendingChangeByToken(ctx, tokenHash)
	return uid, nil
}

// ConfirmPendingRegistrationByToken finalizes a pending email registration from
// the 256-bit emailed link token. The token's entropy is the security boundary,
// so this path is global-lookup and needs no email scoping.
func (s *Service) ConfirmPendingRegistrationByToken(ctx context.Context, token string) (userID string, err error) {
	if !s.opts.PublicNativeUserRegistrationEnabled() {
		return "", ErrRegistrationDisabled
	}
	if !s.useEphemeralStore() {
		return "", jwt.ErrTokenUnverifiable
	}
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
	return s.CreatePendingPhoneRegistrationWithLanguage(ctx, phone, username, passwordHash, "")
}

func (s *Service) CreatePendingPhoneRegistrationWithLanguage(ctx context.Context, phone, username, passwordHash, preferredLanguage string) (string, error) {
	if !s.opts.PublicNativeUserRegistrationEnabled() {
		return "", ErrRegistrationDisabled
	}
	language, err := NormalizePreferredLanguage(preferredLanguage)
	if err != nil {
		return "", err
	}
	sendCtx := contextWithPreferredLanguage(ctx, language)
	switch s.opts.RegistrationVerificationPolicy() {
	case RegistrationVerificationNone:
		userID, err := s.createPhoneRegistrationUser(ctx, phone, username, passwordHash, true)
		if err != nil {
			return "", err
		}
		if language != "" {
			if err := s.SetPreferredLanguage(ctx, userID, language); err != nil {
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
		if language != "" {
			if err := s.SetPreferredLanguage(ctx, userID, language); err != nil {
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
		msg := VerificationMessage{Code: code, LinkURL: s.phoneVerificationURL(linkToken), Purpose: "signup"}
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
				Kind:              KindRegisterPhone,
				Target:            phone,
				Username:          username,
				PasswordHash:      passwordHash,
				PreferredLanguage: language,
			}, map[string]time.Duration{
				codeHash: defaultPhoneVerificationTTL,
				linkHash: defaultPhoneVerificationTTL,
			}); err != nil {
				return "", err
			}
		} else {
			return "", fmt.Errorf("ephemeral store not configured")
		}

		msg := VerificationMessage{Code: code, LinkURL: s.phoneVerificationURL(linkToken), Purpose: "signup"}
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
	// verified user, and applies language; consume deletes on success.
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
		_, err := s.CreatePendingPhoneRegistrationWithLanguage(ctx, phone, pending.Username, pending.PasswordHash, pending.PreferredLanguage)
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
			return err
		}
	} else {
		return nil
	}

	msg := VerificationMessage{Code: code, LinkURL: s.phoneVerificationURL(linkToken), Purpose: "contact_verify"}
	if err := msg.Validate(); err != nil {
		return nil
	}

	// Send SMS
	if s.sms != nil {
		sendCtx := s.contextWithUserPreferredLanguage(ctx, userID)
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

// User is defined in the lean authkit contract package (#138 inversion); aliased
// here so engine code keeps using the bare name.
type User = authkit.User

func userFromByIDRow(r db.UserByIDRow) *User {
	return &User{ID: r.ID, Email: r.Email, PhoneNumber: r.PhoneNumber, Username: r.Username, EmailVerified: r.EmailVerified, PhoneVerified: r.PhoneVerified, BannedAt: r.BannedAt, BannedUntil: r.BannedUntil, BanReason: r.BanReason, BannedBy: r.BannedBy, DeletedAt: r.DeletedAt, Biography: r.Biography, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt, LastLogin: r.LastLogin}
}

func userFromByEmailRow(r db.UserByEmailRow) *User {
	return &User{ID: r.ID, Email: r.Email, PhoneNumber: r.PhoneNumber, Username: r.Username, EmailVerified: r.EmailVerified, PhoneVerified: r.PhoneVerified, BannedAt: r.BannedAt, BannedUntil: r.BannedUntil, BanReason: r.BanReason, BannedBy: r.BannedBy, DeletedAt: r.DeletedAt, Biography: r.Biography, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt, LastLogin: r.LastLogin}
}

func userFromByUsernameRow(r db.UserByUsernameRow) *User {
	return &User{ID: r.ID, Email: r.Email, PhoneNumber: r.PhoneNumber, Username: r.Username, EmailVerified: r.EmailVerified, PhoneVerified: r.PhoneVerified, BannedAt: r.BannedAt, BannedUntil: r.BannedUntil, BanReason: r.BanReason, BannedBy: r.BannedBy, DeletedAt: r.DeletedAt, Biography: r.Biography, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt, LastLogin: r.LastLogin}
}

func userFromByPhoneRow(r db.UserByPhoneRow) *User {
	return &User{ID: r.ID, Email: r.Email, PhoneNumber: r.PhoneNumber, Username: r.Username, EmailVerified: r.EmailVerified, PhoneVerified: r.PhoneVerified, BannedAt: r.BannedAt, BannedUntil: r.BannedUntil, BanReason: r.BanReason, BannedBy: r.BannedBy, DeletedAt: r.DeletedAt, Biography: r.Biography, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt, LastLogin: r.LastLogin}
}

var preferredLanguageRe = regexp.MustCompile(`^[A-Za-z]{2}$`)

func NormalizePreferredLanguage(language string) (string, error) {
	language = strings.TrimSpace(strings.ToLower(language))
	if language == "" {
		return "", nil
	}
	if !preferredLanguageRe.MatchString(language) {
		return "", fmt.Errorf("invalid_preferred_language")
	}
	return language, nil
}

type PreferredLanguage = authkit.PreferredLanguage

func (s *Service) SetPreferredLanguage(ctx context.Context, userID, language string) error {
	if s.pg == nil {
		return fmt.Errorf("postgres not configured")
	}
	userID = strings.TrimSpace(userID)
	normalized, err := NormalizePreferredLanguage(language)
	if err != nil {
		return err
	}
	if userID == "" || normalized == "" {
		return fmt.Errorf("invalid_request")
	}
	return s.q.UserSetPreferredLanguage(ctx, db.UserSetPreferredLanguageParams{ID: userID, PreferredLanguage: &normalized})
}

func (s *Service) GetPreferredLanguage(ctx context.Context, userID string) (PreferredLanguage, error) {
	if s.pg == nil {
		return PreferredLanguage{}, nil
	}
	row, err := s.q.UserPreferredLanguage(ctx, strings.TrimSpace(userID))
	return PreferredLanguage{Language: row}, err
}

func contextWithPreferredLanguage(ctx context.Context, language string) context.Context {
	if strings.TrimSpace(language) == "" {
		return ctx
	}
	return authlang.WithLanguage(ctx, language)
}

func (s *Service) contextWithUserPreferredLanguage(ctx context.Context, userID string) context.Context {
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return ctx
	}
	preferred, err := s.GetPreferredLanguage(ctx, userID)
	if err != nil || strings.TrimSpace(preferred.Language) == "" {
		return ctx
	}
	return contextWithPreferredLanguage(ctx, preferred.Language)
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

type ImportUserInput = authkit.ImportUserInput

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
	userID, err := newUUIDV7String()
	if err != nil {
		return nil, err
	}
	ins, err := s.q.UserInsert(ctx, db.UserInsertParams{ID: userID, Email: email, Username: &username})
	if err != nil {
		return nil, err
	}
	u := User{ID: ins.ID, Email: ins.Email, Username: ins.Username, EmailVerified: ins.EmailVerified, BannedAt: ins.BannedAt, DeletedAt: ins.DeletedAt}
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
	if err := validateImportUsername(username); err != nil {
		return nil, nil, "", nil, "", time.Time{}, time.Time{}, err
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
		PhoneVerified: input.PhoneVerified,
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
	updatedID, err := s.q.UserImportUpdate(ctx, db.UserImportUpdateParams{
		ID:            userID,
		Email:         email,
		PhoneNumber:   phone,
		Username:      &username,
		EmailVerified: input.EmailVerified,
		PhoneVerified: input.PhoneVerified,
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

	tx, err := s.pg.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := s.qtx(tx)

	userID, err := newUUIDV7String()
	if err != nil {
		return "", err
	}
	if _, err := q.UserInsert(ctx, db.UserInsertParams{ID: userID, Email: email, Username: &username}); err != nil {
		return "", err
	}
	if err := q.UserPasswordInsert(ctx, db.UserPasswordInsertParams{UserID: userID, PasswordHash: passwordHash}); err != nil {
		return "", err
	}
	if err := q.UserSetEmailVerified(ctx, db.UserSetEmailVerifiedParams{ID: userID, EmailVerified: emailVerified}); err != nil {
		return "", err
	}
	if err := tx.Commit(ctx); err != nil {
		return "", err
	}
	return userID, nil
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

	tx, err := s.pg.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := s.qtx(tx)

	userID, err := newUUIDV7String()
	if err != nil {
		return "", err
	}
	if _, err := q.UserInsert(ctx, db.UserInsertParams{ID: userID, Email: "", Username: &username}); err != nil {
		return "", err
	}
	if err := q.UserPasswordInsert(ctx, db.UserPasswordInsertParams{UserID: userID, PasswordHash: passwordHash}); err != nil {
		return "", err
	}
	if err := q.UserSetPhoneAndVerified(ctx, db.UserSetPhoneAndVerifiedParams{ID: userID, PhoneNumber: &phone, PhoneVerified: phoneVerified}); err != nil {
		return "", err
	}
	if err := tx.Commit(ctx); err != nil {
		return "", err
	}
	return userID, nil
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
	if until != nil && !until.UTC().After(now) {
		return ErrInvalidUntil
	}
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
	if err := ValidateUsername(newUsername); err != nil {
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

	// Cooldown check (issue #58). Walks the `(user_id, renamed_at DESC)` index
	// to grab the most recent rename.
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

	if u.Email != nil && strings.EqualFold(*u.Email, trimmed) {
		if u.EmailVerified {
			return ErrEmailAlreadyVerified
		}
		return s.sendEmailVerificationToUser(ctx, u, 0)
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
	msg := VerificationMessage{Code: code, LinkURL: s.emailVerificationURL(linkToken), Purpose: "contact_change"}
	if s.email != nil {
		sendCtx := s.contextWithUserPreferredLanguage(ctx, userID)
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
func (s *Service) ConfirmEmailChange(ctx context.Context, userID, email, code string) error {
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
	if strings.TrimSpace(email) != "" && !strings.EqualFold(NormalizeEmail(email), rec.Target) {
		return jwt.ErrTokenUnverifiable
	}
	if _, err := s.finalizeChangeEmail(ctx, rec); err != nil {
		return err
	}
	s.deletePendingChangeByToken(ctx, hash)
	return nil
}

// ConfirmEmailChangeByToken applies a pending email change using its high-entropy link token.
func (s *Service) ConfirmEmailChangeByToken(ctx context.Context, token string) (string, error) {
	return s.consumePendingChangeByToken(ctx, sha256Hex(token), KindChangeEmail)
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

	msg := VerificationMessage{Code: code, LinkURL: s.emailVerificationURL(linkToken), Purpose: "contact_change"}
	// Send new credentials.
	if s.email != nil {
		sendCtx := s.contextWithUserPreferredLanguage(ctx, userID)
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

// normalizeRootRoleSlug canonicalises a root role slug. "admin" is not special:
// apps declare their own bounded `admin` catalog role when they need one.
func normalizeRootRoleSlug(slug string) string {
	return strings.ToLower(strings.TrimSpace(slug))
}

func (s *Service) splitConfiguredRootRoles(roles []string) (live []string, removed []string) {
	if len(roles) == 0 {
		return nil, nil
	}
	valid := map[string]struct{}{}
	if s.groupSchema != nil {
		if root, ok := s.groupSchema.types[RootPersona]; ok {
			for _, r := range root.Roles {
				valid[normalizeRootRoleSlug(r.Name)] = struct{}{}
			}
		}
	}
	if len(valid) == 0 {
		live = append([]string(nil), roles...)
		sort.Strings(live)
		return live, nil
	}
	liveSeen := map[string]struct{}{}
	removedSeen := map[string]struct{}{}
	for _, raw := range roles {
		role := normalizeRootRoleSlug(raw)
		if role == "" {
			continue
		}
		if _, ok := valid[role]; ok {
			liveSeen[role] = struct{}{}
			continue
		}
		removedSeen[role] = struct{}{}
	}
	for role := range liveSeen {
		live = append(live, role)
	}
	for role := range removedSeen {
		removed = append(removed, role)
	}
	sort.Strings(live)
	sort.Strings(removed)
	return live, removed
}

// rootRoleSlugsByUser returns a user's configured root permission-group roles
// and any stored roles removed from the current schema.
func (s *Service) rootRoleSlugsByUser(ctx context.Context, userID string) ([]string, []string) {
	if s.pg == nil {
		return nil, nil
	}
	st := s.groupStore()
	gid, err := st.RootGroupID(ctx)
	if err != nil {
		return nil, nil
	}
	asg, err := st.WalkAssignments(ctx, gid, strings.TrimSpace(userID), SubjectKindUser)
	if err != nil {
		return nil, nil
	}
	var roles []string
	for _, a := range asg {
		roles = append(roles, a.Roles...)
	}
	return s.splitConfiguredRootRoles(roles)
}

// listRoleSlugsByUser returns a user's configured root permission-group roles.
// Operator authority is a root-group assignment.
func (s *Service) listRoleSlugsByUser(ctx context.Context, userID string) []string {
	live, _ := s.rootRoleSlugsByUser(ctx, userID)
	return live
}

var ErrUserRoleNotFound = authkit.ErrUserRoleNotFound

// ErrCannotRemoveLastAdminRole is retained for the admin HTTP adapter's error
// mapping. The root layer has no "last admin" lock, so core no longer returns
// it, but the exported symbol stays so dependents keep compiling.
var ErrCannotRemoveLastAdminRole = authkit.ErrCannotRemoveLastAdminRole

// assignRoleBySlug grants a user a role in the root permission-group (#111).
// The unchecked path is for genesis/bootstrap/migration; runtime callers use the
// actor-aware AssignRoleBySlugAs path.
func (s *Service) assignRoleBySlug(ctx context.Context, userID, slug string) error {
	if s.pg == nil {
		return nil
	}
	if _, err := s.EnsureRootGroup(ctx); err != nil {
		return err
	}
	role := normalizeRootRoleSlug(slug)
	return s.AssignGroupRole(ctx, RootPersona, "", strings.TrimSpace(userID), SubjectKindUser, role)
}

// upsertRoleBySlug is a no-op under the permission-group model: catalog roles
// live in core.Config (the GroupSchema), not the DB, so there is nothing to
// "define" at runtime. It validates the slug is a known root catalog role,
// ensures the root group exists, and returns.
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
	if _, err := s.EnsureRootGroup(ctx); err != nil {
		return err
	}
	role = normalizeRootRoleSlug(slug)
	if !s.validRoleForPersona(s.groupSchemaOrDefault(), RootPersona, role) {
		return fmt.Errorf("invalid_role")
	}
	return nil
}

// removeRoleBySlug revokes a user's role in the root permission-group.
func (s *Service) removeRoleBySlug(ctx context.Context, userID, slug string) error {
	if s.pg == nil {
		return nil
	}
	role := normalizeRootRoleSlug(slug)
	if err := s.UnassignGroupRole(ctx, RootPersona, "", strings.TrimSpace(userID), SubjectKindUser, role); err != nil {
		return err
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
type AdminUser = authkit.AdminUser

// AdminListUsersResult contains paginated user list with total count
type AdminListUsersResult = authkit.AdminListUsersResult

// AdminUserStatus filters the directory by account state.
type AdminUserStatus = authkit.AdminUserStatus

const (
	AdminUserStatusActive  = authkit.AdminUserStatusActive
	AdminUserStatusBanned  = authkit.AdminUserStatusBanned
	AdminUserStatusDeleted = authkit.AdminUserStatusDeleted
	AdminUserStatusAny     = authkit.AdminUserStatusAny
	// "" (zero value) defaults to non-deleted (the historical "All users" behavior).
)

// AdminUserSort selects the directory ordering column.
type AdminUserSort = authkit.AdminUserSort

const (
	AdminUserSortCreatedAt = authkit.AdminUserSortCreatedAt
	AdminUserSortLastLogin = authkit.AdminUserSortLastLogin
	AdminUserSortUsername  = authkit.AdminUserSortUsername
	AdminUserSortEmail     = authkit.AdminUserSortEmail
)

// AdminUserListOptions is the admin dashboard user-directory query. It carries
// no host product knowledge: Role is the root_role query param, a singleton-root
// permission-group role slug. Status/Sort are closed enums. Entitlement
// filtering delegates to the billing provider, never a cross-schema join.
type AdminUserListOptions = authkit.AdminUserListOptions

// ErrEntitlementFilterUnavailable is returned by AdminListUsers/AdminCountUsers
// when an Entitlement filter is requested but no EntitlementFilterProvider is
// configured — fail loud rather than silently return everyone.
var ErrEntitlementFilterUnavailable = authkit.ErrEntitlementFilterUnavailable

func normalizeAdminUserListOptions(o AdminUserListOptions) AdminUserListOptions {
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
		// root_role filters on a user's role in the singleton root group. Use
		// WHERE EXISTS (not a JOIN) so the result is one row per user — no
		// duplication, so no SELECT DISTINCT is needed and the (col, id) sort can
		// use an index.
		slug = normalizeRootRoleSlug(slug)
		where = append(where, "EXISTS (SELECT 1 FROM profiles.group_user_roles gur"+
			" JOIN profiles.permission_groups pg ON pg.id = gur.permission_group_id"+
			" WHERE gur.user_id = u.id AND gur.deleted_at IS NULL AND gur.role = $"+fmt.Sprint(argIdx)+
			" AND pg.persona = 'root' AND pg.deleted_at IS NULL)")
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
// tiebreaker. The id tiebreaker is the raw uuid (not ::text) so the (col, id)
// admin indexes can serve the ordering; uuidv7 byte order matches the canonical
// string's lexical order, so the row order is unchanged from the prior ::text cast.
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
	return col + " " + dir + ", u.id " + dir
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
// role/status filter + search + sort + offset pagination, with optional
// provider-backed entitlement filtering. Each row is enriched with role slugs
// and (via the entitlements provider) entitlement names.
func (s *Service) AdminListUsers(ctx context.Context, opts AdminUserListOptions) (*AdminListUsersResult, error) {
	opts = normalizeAdminUserListOptions(opts)
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
	selectCols := "u.id::text, u.email, u.phone_number, u.username, u.email_verified, u.phone_verified, u.banned_at, u.banned_until, u.ban_reason, u.banned_by, u.deleted_at, u.biography, u.created_at, u.updated_at, u.last_login"
	query := "SELECT " + selectCols + " FROM " + from + " WHERE " + strings.Join(where, " AND ") + " ORDER BY " + adminUserOrderBy(opts) + " OFFSET $" + fmt.Sprint(argIdx) + " LIMIT $" + fmt.Sprint(argIdx+1)
	args = append(args, offset, opts.PageSize)

	rows, err := s.pg.Query(ctx, db.RewriteSQL(query, s.dbSchema()), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AdminUser
	for rows.Next() {
		var a AdminUser
		if err := rows.Scan(&a.ID, &a.Email, &a.PhoneNumber, &a.Username, &a.EmailVerified, &a.PhoneVerified, &a.BannedAt, &a.BannedUntil, &a.BanReason, &a.BannedBy, &a.DeletedAt, &a.Biography, &a.CreatedAt, &a.UpdatedAt, &a.LastLogin); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// Enrich root-group roles for the whole page in ONE query instead of two per
	// row. Resolution failures degrade to empty roles (matching the prior
	// per-row swallow), so the listing still renders.
	if len(out) > 0 {
		st := s.groupStore()
		if gid, gErr := st.RootGroupID(ctx); gErr == nil {
			ids := make([]string, len(out))
			for i := range out {
				ids[i] = out[i].ID
			}
			if rolesByUser, rErr := st.RootRolesForUsers(ctx, gid, ids); rErr == nil {
				for i := range out {
					out[i].Roles, out[i].RemovedRoles = s.splitConfiguredRootRoles(rolesByUser[out[i].ID])
				}
			}
		}
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
	a.Roles, a.RemovedRoles = s.rootRoleSlugsByUser(ctx, id)
	a.Entitlements = s.ListEntitlements(ctx, id)
	return a, nil
}

type AdminRecoverUserInput struct {
	Email       string
	PhoneNumber string
}

// AdminRecoverUser locks down a compromised account and replaces its primary
// recovery identifier before sending a password-reset link/code to that new
// identifier.
func (s *Service) AdminRecoverUser(ctx context.Context, userID string, input AdminRecoverUserInput) error {
	if s.pg == nil {
		return nil
	}
	userID = strings.TrimSpace(userID)
	email := NormalizeEmail(input.Email)
	phone := NormalizePhone(input.PhoneNumber)
	if userID == "" || (email == "") == (phone == "") {
		return fmt.Errorf("invalid_request")
	}
	if email != "" {
		if err := ValidateEmail(email); err != nil {
			return err
		}
		if !s.HasEmailSender() {
			return ErrEmailSenderUnavailable
		}
		existing, err := s.getUserByEmail(ctx, email)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if existing != nil && strings.TrimSpace(existing.ID) != userID {
			return ErrEmailInUse
		}
	} else {
		if err := ValidatePhone(phone); err != nil {
			return err
		}
		if !s.HasSMSSender() {
			return ErrSMSSenderUnavailable
		}
		existing, err := s.GetUserByPhone(ctx, phone)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if existing != nil && strings.TrimSpace(existing.ID) != userID {
			return ErrPhoneInUse
		}
	}

	tx, err := s.pg.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	qtx := s.qtx(tx)
	if _, err := qtx.UserByID(ctx, userID); errors.Is(err, pgx.ErrNoRows) {
		return ErrUserNotFound
	} else if err != nil {
		return err
	}

	sessionIDs, err := qtx.SessionsRevokeAll(ctx, db.SessionsRevokeAllParams{UserID: userID, Issuer: s.opts.Issuer})
	if err != nil {
		return err
	}
	if err := qtx.UserPasswordDelete(ctx, userID); err != nil {
		return err
	}
	if err := qtx.UserProvidersDeleteByUser(ctx, userID); err != nil {
		return err
	}
	if err := qtx.MFADelete(ctx, userID); err != nil {
		return err
	}
	if err := qtx.UserClearLoginIdentifiers(ctx, userID); err != nil {
		return err
	}
	if email != "" {
		if err := qtx.UserSetEmailAndVerified(ctx, db.UserSetEmailAndVerifiedParams{ID: userID, Email: email}); err != nil {
			return err
		}
	} else {
		verified := true
		if err := qtx.UserSetPhoneAndVerified(ctx, db.UserSetPhoneAndVerifiedParams{ID: userID, PhoneNumber: &phone, PhoneVerified: verified}); err != nil {
			return err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	reason := string(SessionRevokeReasonAdminRevokeAll)
	for _, sessionID := range sessionIDs {
		s.logSessionRevoked(ctx, userID, sessionID, &reason)
	}
	if email != "" {
		return s.RequestPasswordReset(ctx, email, 0, nil, nil)
	}
	return s.RequestPhonePasswordReset(ctx, phone, 0, nil, nil)
}

func (s *Service) AdminDeleteUser(ctx context.Context, id string) error {
	if s.pg == nil {
		return nil
	}
	// Revoke all sessions
	_ = s.q.SessionsRevokeAllQuiet(ctx, db.SessionsRevokeAllQuietParams{UserID: id, Issuer: s.opts.Issuer})
	if err := s.q.GroupAssignmentsDeleteByUser(ctx, id); err != nil {
		return err
	}
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

// SessionEventHistoryEnabled reports whether ClickHouse session-event history is
// wired (WithClickHouse). The admin sign-in routes report unavailable when false.
func (s *Service) SessionEventHistoryEnabled() bool { return s.authlog != nil }

// ListSessionEvents returns a user's recent session events from ClickHouse, most
// recent first. Empty when ClickHouse is not configured.
func (s *Service) ListSessionEvents(ctx context.Context, userID string, eventTypes ...SessionEventType) ([]AuthSessionEvent, error) {
	if s.authlog == nil {
		return nil, nil
	}
	return s.authlog.ListSessionEvents(ctx, userID, eventTypes...)
}

// LogSessionCreated records a session creation event to ClickHouse (best-effort).
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
	sendCtx := s.contextWithUserPreferredLanguage(ctx, userID)
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

// UserProfileLinks returns the user's linked provider slugs (non-null) and username
// aliases — the two extra lists GET /me needs beyond AdminGetUser. Keeps raw
// db.Queries out of the HTTP layer, which previously built its own db handle inline.
func (s *Service) UserProfileLinks(ctx context.Context, userID string) (providerSlugs []string, aliases []string, err error) {
	if s.pg == nil {
		return nil, nil, nil
	}
	providerSlugs, err = s.q.UserProviderSlugs(ctx, userID)
	if err != nil {
		return nil, nil, err
	}
	aliases, err = s.q.UserSlugAliases(ctx, userID)
	if err != nil {
		return nil, nil, err
	}
	return providerSlugs, aliases, nil
}

// UnlinkProviderUnlessLast atomically removes the provider link only if the user
// retains a login method afterward (a password, or another provider). Returns
// (false, nil) when removal would strip the last login method. The check and the
// delete run in one transaction, and UserProviderCountForUpdate locks the user's
// provider rows so two concurrent unlinks of different providers cannot both pass
// the "not last" check and leave the user with zero login methods.
func (s *Service) UnlinkProviderUnlessLast(ctx context.Context, userID, provider string) (bool, error) {
	if s.pg == nil {
		return false, nil
	}
	tx, err := s.pg.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := s.qtx(tx)
	links, err := q.UserProviderCountForUpdate(ctx, userID)
	if err != nil {
		return false, err
	}
	hasPwd, err := q.UserHasPassword(ctx, userID)
	if err != nil {
		return false, err
	}
	// Mirror the prior guard semantics (no password AND ≤1 provider ⇒ this is the
	// last login method), now evaluated under the row lock.
	if !hasPwd && links <= 1 {
		return false, nil
	}
	if err := q.UserProviderDeleteBySlug(ctx, db.UserProviderDeleteBySlugParams{UserID: userID, ProviderSlug: &provider}); err != nil {
		return false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return false, err
	}
	return true, nil
}

// Issuer-based provider link helpers (preferred)
func (s *Service) GetProviderLinkByIssuer(ctx context.Context, issuer, subject string) (string, *string, error) {
	return s.getProviderLinkByIssuerInternal(ctx, issuer, subject)
}

func (s *Service) LinkProviderByIssuer(ctx context.Context, userID, issuer, providerSlug, subject string, email *string) error {
	// Store provider slug for UI, enforce uniqueness on (issuer, subject) and (user_id, issuer).
	// The delete-other-subjects (allows switching e.g. Discord accounts) and the upsert run in
	// ONE transaction: a failure can't leave the user's old link deleted and the new one missing.
	if s.pg == nil {
		return nil
	}
	providerID, err := newUUIDV7String()
	if err != nil {
		return err
	}

	tx, err := s.pg.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	qtx := s.qtx(tx)

	// First delete any old link for this user+issuer with a different subject.
	if err := qtx.UserProviderDeleteOtherSubjects(ctx, db.UserProviderDeleteOtherSubjectsParams{UserID: userID, Issuer: issuer, Subject: subject}); err != nil {
		return err
	}
	// The upsert's ON CONFLICT (issuer, subject) DO UPDATE is constrained to the same user_id,
	// so a subject already owned by a DIFFERENT user yields zero affected rows (no cross-user
	// write) and RETURNING produces pgx.ErrNoRows — surfaced as a 409-class conflict.
	if _, err := qtx.UserProviderUpsertByIssuer(ctx, db.UserProviderUpsertByIssuerParams{
		ID:              providerID,
		UserID:          userID,
		Issuer:          issuer,
		ProviderSlug:    &providerSlug,
		Subject:         subject,
		EmailAtProvider: email,
	}); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return authkit.ErrProviderAlreadyLinked
		}
		return err
	}
	if err := tx.Commit(ctx); err != nil {
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

// (legacy ChangePassword removed in favor of unified ChangePassword with session revocation)

// --- Pending Registration Helpers ---

// PendingRegistration represents an unverified registration
type PendingRegistration struct {
	Email             string
	Username          string
	PasswordHash      string
	PreferredLanguage string
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
		Email:             rec.Target,
		Username:          rec.Username,
		PasswordHash:      rec.PasswordHash,
		PreferredLanguage: rec.PreferredLanguage,
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
		Email:             rec.Target,
		Username:          rec.Username,
		PasswordHash:      rec.PasswordHash,
		PreferredLanguage: rec.PreferredLanguage,
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
	UserID       string
	Enabled      bool
	Method       string // "email", "sms", or "totp"
	PhoneNumber  *string
	TOTPSecret   []byte
	LastTOTPStep *int64
	BackupCodes  []string // Hashed backup codes
	Factors      []TwoFactorFactor
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

type TwoFactorFactor struct {
	ID           string
	UserID       string
	Method       string
	PhoneNumber  *string
	TOTPSecret   []byte
	LastTOTPStep *int64
	IsDefault    bool
	Enabled      bool
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// Enable2FA enables two-factor authentication for a user and generates backup codes.
// Returns the plaintext backup codes (caller must show these to user ONCE).
func (s *Service) Enable2FA(ctx context.Context, userID, method string, phoneNumber *string) ([]string, error) {
	return s.enable2FA(ctx, userID, method, phoneNumber, nil, nil, false)
}

func (s *Service) Enable2FADefault(ctx context.Context, userID, method string, phoneNumber *string) ([]string, error) {
	return s.enable2FA(ctx, userID, method, phoneNumber, nil, nil, true)
}

func (s *Service) enable2FA(ctx context.Context, userID, method string, phoneNumber *string, totpSecret []byte, lastTOTPStep *int64, makeDefault bool) ([]string, error) {
	if s.pg == nil {
		return nil, fmt.Errorf("postgres not configured")
	}

	method = strings.ToLower(strings.TrimSpace(method))
	if method != "email" && method != "sms" && method != "totp" {
		return nil, fmt.Errorf("invalid 2FA method: must be 'email', 'sms', or 'totp'")
	}
	if method == "sms" && (phoneNumber == nil || *phoneNumber == "") {
		return nil, fmt.Errorf("phone number required for SMS 2FA")
	}
	if method == "totp" && len(totpSecret) == 0 {
		return nil, fmt.Errorf("totp secret required for TOTP 2FA")
	}

	tx, err := s.pg.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	qtx := s.qtx(tx)

	var currentBackupCodes []string
	if settings, err := qtx.MFASettingsByUser(ctx, userID); err == nil && settings.Enabled {
		currentBackupCodes = settings.BackupCodes
	}

	factors, err := qtx.MFAListFactorsByUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	firstFactor := len(factors) == 0
	makeDefault = makeDefault || firstFactor

	plaintextCodes := []string(nil)
	if len(currentBackupCodes) == 0 {
		plaintextCodes, currentBackupCodes = generateBackupCodes()
	}

	if makeDefault {
		if err := qtx.MFAClearDefaultFactors(ctx, userID); err != nil {
			return nil, err
		}
	}
	factor, err := qtx.MFAUpsertFactor(ctx, db.MFAUpsertFactorParams{
		UserID:       userID,
		Method:       method,
		PhoneNumber:  phoneNumber,
		TotpSecret:   totpSecret,
		LastTotpStep: lastTOTPStep,
		IsDefault:    makeDefault,
	})
	if err != nil {
		return nil, err
	}

	_ = factor // per-factor data lives only on mfa_factors (#125)
	// Settings holds only the account-level gate + backup codes (#125).
	if err := qtx.MFAUpsertSettings(ctx, db.MFAUpsertSettingsParams{
		UserID:      userID,
		BackupCodes: currentBackupCodes,
	}); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return plaintextCodes, nil
}

// Disable2FA disables two-factor authentication for a user.
func (s *Service) Disable2FA(ctx context.Context, userID string) error {
	_, err := s.Disable2FAWithRemovedRoles(ctx, userID)
	return err
}

// Disable2FAWithRemovedRoles disables account MFA and removes active user role
// assignments whose catalog role requires MFA.
func (s *Service) Disable2FAWithRemovedRoles(ctx context.Context, userID string) ([]RemovedMFARoleAssignment, error) {
	if s.pg == nil {
		return nil, fmt.Errorf("postgres not configured")
	}

	tx, err := s.pg.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := db.ForSchema(tx, s.dbSchema())
	qtx := s.qtx(tx)
	removed, err := s.removeMFARequiredUserRoles(ctx, q, strings.TrimSpace(userID))
	if err != nil {
		return nil, err
	}
	if err := qtx.MFADeleteAllFactors(ctx, userID); err != nil {
		return nil, err
	}
	if err := qtx.MFADisable(ctx, userID); err != nil {
		return nil, err
	}
	return removed, tx.Commit(ctx)
}

func (s *Service) Disable2FAFactor(ctx context.Context, userID, factorID string) error {
	_, err := s.Disable2FAFactorWithRemovedRoles(ctx, userID, factorID)
	return err
}

func (s *Service) Disable2FAFactorWithRemovedRoles(ctx context.Context, userID, factorID string) ([]RemovedMFARoleAssignment, error) {
	if s.pg == nil {
		return nil, fmt.Errorf("postgres not configured")
	}
	if strings.TrimSpace(factorID) == "" {
		return nil, fmt.Errorf("factor id required")
	}
	tx, err := s.pg.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := db.ForSchema(tx, s.dbSchema())
	qtx := s.qtx(tx)
	rows, err := qtx.MFADeleteFactor(ctx, db.MFADeleteFactorParams{UserID: userID, ID: factorID})
	if err != nil {
		return nil, err
	}
	if rows == 0 {
		return nil, pgx.ErrNoRows
	}
	factors, err := qtx.MFAListFactorsByUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	removed := []RemovedMFARoleAssignment(nil)
	if len(factors) == 0 {
		removed, err = s.removeMFARequiredUserRoles(ctx, q, strings.TrimSpace(userID))
		if err != nil {
			return nil, err
		}
		if err := qtx.MFADisable(ctx, userID); err != nil {
			return nil, err
		}
		return removed, tx.Commit(ctx)
	}
	// Promote a new default if the deleted factor was the default.
	hasDefault := false
	for _, f := range factors {
		if f.IsDefault {
			hasDefault = true
			break
		}
	}
	if !hasDefault {
		if _, err := qtx.MFASetDefaultFactor(ctx, db.MFASetDefaultFactorParams{UserID: userID, ID: factors[0].ID}); err != nil {
			return nil, err
		}
	}
	return removed, tx.Commit(ctx)
}

func (s *Service) SetDefault2FAFactor(ctx context.Context, userID, factorID string) error {
	if s.pg == nil {
		return fmt.Errorf("postgres not configured")
	}
	if strings.TrimSpace(factorID) == "" {
		return fmt.Errorf("factor id required")
	}
	tx, err := s.pg.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	qtx := s.qtx(tx)
	factors, err := qtx.MFAListFactorsByUser(ctx, userID)
	if err != nil {
		return err
	}
	var selected *db.ProfilesMfaFactor
	for i := range factors {
		if factors[i].ID == factorID {
			selected = &factors[i]
			break
		}
	}
	if selected == nil {
		return pgx.ErrNoRows
	}
	if err := qtx.MFAClearDefaultFactors(ctx, userID); err != nil {
		return err
	}
	if _, err := qtx.MFASetDefaultFactor(ctx, db.MFASetDefaultFactorParams{UserID: userID, ID: factorID}); err != nil {
		return err
	}
	_ = selected // existence check only; per-factor data is not mirrored to settings (#125)
	return tx.Commit(ctx)
}

// Get2FASettings retrieves a user's 2FA settings
func (s *Service) Get2FASettings(ctx context.Context, userID string) (*TwoFactorSettings, error) {
	if s.pg == nil {
		return nil, fmt.Errorf("postgres not configured")
	}

	row, err := s.q.MFASettingsByUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	// Settings holds only the account gate + backup codes (#125); the displayed
	// method/phone/secret are derived from the default factor below.
	settings := &TwoFactorSettings{
		UserID:      row.UserID,
		Enabled:     row.Enabled,
		BackupCodes: row.BackupCodes,
		CreatedAt:   row.CreatedAt,
		UpdatedAt:   row.UpdatedAt,
	}
	factors, err := s.List2FAFactors(ctx, userID)
	if err == nil {
		settings.Factors = factors
		for _, factor := range factors {
			if factor.IsDefault {
				settings.Method = factor.Method
				settings.PhoneNumber = factor.PhoneNumber
				settings.TOTPSecret = factor.TOTPSecret
				settings.LastTOTPStep = factor.LastTOTPStep
				break
			}
		}
	}
	return settings, nil
}

func (s *Service) List2FAFactors(ctx context.Context, userID string) ([]TwoFactorFactor, error) {
	if s.pg == nil {
		return nil, fmt.Errorf("postgres not configured")
	}
	rows, err := s.q.MFAListFactorsByUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	out := make([]TwoFactorFactor, 0, len(rows))
	for _, row := range rows {
		out = append(out, twoFactorFactorFromFields(row.ID, row.UserID, row.Method, row.PhoneNumber, row.TotpSecret, row.LastTotpStep, row.IsDefault, row.CreatedAt, row.UpdatedAt))
	}
	return out, nil
}

// Require2FAForLogin sends a 2FA code to the user's configured method.
// Returns the destination (email/phone) where the code was sent.
// This should be called after successful password verification.
func (s *Service) Require2FAForLogin(ctx context.Context, userID string) (string, error) {
	destination, _, _, err := s.Require2FAForLoginFactor(ctx, userID, "")
	return destination, err
}

func (s *Service) Require2FAForLoginFactor(ctx context.Context, userID, factorID string) (destination, method string, factor TwoFactorFactor, err error) {
	factor, err = s.twoFactorFactor(ctx, userID, factorID)
	if err != nil {
		return "", "", TwoFactorFactor{}, err
	}
	destination, err = s.send2FACodeForFactor(ctx, userID, "", factor)
	return destination, factor.Method, factor, err
}

func (s *Service) send2FACodeForFactor(ctx context.Context, userID, sessionID string, factor TwoFactorFactor) (string, error) {
	if !factor.Enabled {
		return "", fmt.Errorf("2FA not enabled")
	}
	if factor.Method == "totp" {
		return "authenticator app", nil
	}
	user, err := s.AdminGetUser(ctx, userID)
	if err != nil {
		return "", err
	}

	code := randAlphanumeric(6)
	hash := sha256Hex(code)

	var destination string
	if factor.Method == "email" {
		if user.Email == nil {
			return "", fmt.Errorf("no email address configured")
		}
		destination = *user.Email
	} else { // sms
		if factor.PhoneNumber == nil {
			return "", fmt.Errorf("no phone number configured for SMS 2FA")
		}
		destination = *factor.PhoneNumber
	}

	if !s.useEphemeralStore() {
		return "", fmt.Errorf("ephemeral store not configured")
	}
	if strings.TrimSpace(sessionID) == "" {
		if err := s.storeMFACode(ctx, userID, hash, factor.Method, destination, 10*time.Minute); err != nil {
			return "", err
		}
	} else if err := s.storeMFAStepUpCode(ctx, userID, sessionID, hash, factor.Method, destination, 10*time.Minute); err != nil {
		return "", err
	}

	username := ""
	if user.Username != nil {
		username = *user.Username
	}

	if factor.Method == "email" {
		if s.email != nil {
			sendCtx := s.contextWithUserPreferredLanguage(ctx, userID)
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
			sendCtx := s.contextWithUserPreferredLanguage(ctx, userID)
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

// Require2FAForStepUp sends a 2FA code for authenticated step-up.
func (s *Service) Require2FAForStepUp(ctx context.Context, userID, sessionID string) (destination, method string, err error) {
	destination, method, _, err = s.Require2FAForStepUpMethod(ctx, userID, sessionID, "")
	return destination, method, err
}

func (s *Service) Require2FAForStepUpFactor(ctx context.Context, userID, sessionID, factorID string) (destination, method string, factor TwoFactorFactor, err error) {
	if strings.TrimSpace(sessionID) == "" {
		return "", "", TwoFactorFactor{}, jwt.ErrTokenInvalidClaims
	}
	factor, err = s.twoFactorFactor(ctx, userID, factorID)
	if err != nil {
		return "", "", TwoFactorFactor{}, err
	}
	destination, err = s.send2FACodeForFactor(ctx, userID, sessionID, factor)
	return destination, factor.Method, factor, err
}

func (s *Service) Require2FAForStepUpMethod(ctx context.Context, userID, sessionID, method string) (destination, selectedMethod string, factor TwoFactorFactor, err error) {
	if strings.TrimSpace(sessionID) == "" {
		return "", "", TwoFactorFactor{}, jwt.ErrTokenInvalidClaims
	}
	factor, err = s.twoFactorFactorByMethod(ctx, userID, method)
	if err != nil {
		return "", "", TwoFactorFactor{}, err
	}
	destination, err = s.send2FACodeForFactor(ctx, userID, sessionID, factor)
	return destination, factor.Method, factor, err
}

// Verify2FAStepUpCode verifies a session-scoped 2FA step-up code.
func (s *Service) Verify2FAStepUpCode(ctx context.Context, userID, sessionID, code string) (bool, error) {
	return s.Verify2FAStepUpMethodCode(ctx, userID, sessionID, "", code)
}

func (s *Service) Verify2FAStepUpFactorCode(ctx context.Context, userID, sessionID, factorID, code string) (bool, error) {
	if strings.TrimSpace(sessionID) == "" {
		return false, jwt.ErrTokenInvalidClaims
	}
	factor, err := s.twoFactorFactor(ctx, userID, factorID)
	if err != nil {
		return false, err
	}
	if factor.Method == "totp" {
		return s.verifyTOTPFactorCode(ctx, factor, code)
	}
	if !s.useEphemeralStore() {
		return false, fmt.Errorf("ephemeral store not configured")
	}
	return s.consumeMFAStepUpCode(ctx, userID, sessionID, sha256Hex(code), factor.Method)
}

func (s *Service) Verify2FAStepUpMethodCode(ctx context.Context, userID, sessionID, method, code string) (bool, error) {
	if strings.TrimSpace(sessionID) == "" {
		return false, jwt.ErrTokenInvalidClaims
	}
	factor, err := s.twoFactorFactorByMethod(ctx, userID, method)
	if err != nil {
		return false, err
	}
	if factor.Method == "totp" {
		return s.verifyTOTPFactorCode(ctx, factor, code)
	}
	if !s.useEphemeralStore() {
		return false, fmt.Errorf("ephemeral store not configured")
	}
	return s.consumeMFAStepUpCode(ctx, userID, sessionID, sha256Hex(code), factor.Method)
}

// Create2FAChallenge creates a short-lived challenge to prove password verification before 2FA.
func (s *Service) Create2FAChallenge(ctx context.Context, userID string) (string, error) {
	if !s.useEphemeralStore() {
		return "", fmt.Errorf("ephemeral store not configured")
	}
	challenge := randB64(32)
	hash := sha256Hex(challenge)
	if err := s.storeMFAChallenge(ctx, userID, hash, 10*time.Minute); err != nil {
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
	stored, ok, err := s.getMFAChallenge(ctx, userID)
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
	return s.deleteMFAChallenge(ctx, userID)
}

// Verify2FACode verifies a 2FA code entered by the user during login.
// Returns true if code is valid, false otherwise.
func (s *Service) Verify2FACode(ctx context.Context, userID, code string) (bool, error) {
	return s.Verify2FAFactorCode(ctx, userID, "", code)
}

func (s *Service) Verify2FAFactorCode(ctx context.Context, userID, factorID, code string) (bool, error) {
	factor, err := s.twoFactorFactor(ctx, userID, factorID)
	if err != nil {
		return false, err
	}
	if factor.Method == "totp" {
		return s.verifyTOTPFactorCode(ctx, factor, code)
	}

	hash := sha256Hex(code)

	if s.useEphemeralStore() {
		return s.consumeMFACode(ctx, userID, hash)
	}
	return false, fmt.Errorf("ephemeral store not configured")
}

func (s *Service) verifyTOTPFactorCode(ctx context.Context, factor TwoFactorFactor, code string) (bool, error) {
	secret, err := s.decryptTOTPSecret(factor.TOTPSecret)
	if err != nil {
		return false, err
	}
	step, ok, err := matchingTOTPStep(secret, code, time.Now())
	if err != nil || !ok {
		return false, err
	}
	if strings.TrimSpace(factor.ID) == "" {
		return false, fmt.Errorf("totp factor has no id")
	}
	rows, err := s.q.MFAConsumeFactorTOTPStep(ctx, db.MFAConsumeFactorTOTPStepParams{ID: factor.ID, UserID: factor.UserID, Step: &step})
	return rows > 0, err
}

// VerifyBackupCode verifies a 2FA backup code for account recovery.
// On success, removes the used backup code from the user's backup codes.
func (s *Service) VerifyBackupCode(ctx context.Context, userID, backupCode string) (bool, error) {
	if s.pg == nil {
		return false, fmt.Errorf("postgres not configured")
	}

	// Atomic single-use consume in one statement: the DB removes the hashed code
	// and reports whether THIS call was the one that removed it. This replaces the
	// former read-filter-rewrite, which let two concurrent submissions of the same
	// code both succeed. The query's `enabled = true` predicate also subsumes the
	// old "2FA not enabled" check (callers treat (false, nil) and that error
	// identically — both reject the code).
	hash := sha256Hex(backupCode)
	rows, err := s.q.MFAConsumeBackupCode(ctx, db.MFAConsumeBackupCodeParams{CodeHash: hash, UserID: userID})
	if err != nil {
		return false, err
	}
	return rows == 1, nil
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

	if err := s.q.MFASetBackupCodes(ctx, db.MFASetBackupCodesParams{BackupCodes: hashedCodes, UserID: userID}); err != nil {
		return nil, err
	}

	return plaintextCodes, nil
}

func (s *Service) twoFactorFactor(ctx context.Context, userID, factorID string) (TwoFactorFactor, error) {
	if s.pg == nil {
		return TwoFactorFactor{}, fmt.Errorf("postgres not configured")
	}
	factors, err := s.List2FAFactors(ctx, userID)
	if err != nil {
		return TwoFactorFactor{}, err
	}
	if len(factors) == 0 {
		settings, err := s.Get2FASettings(ctx, userID)
		if err != nil || !settings.Enabled || len(settings.Factors) == 0 {
			return TwoFactorFactor{}, fmt.Errorf("2FA not enabled")
		}
		factors = settings.Factors
	}
	if strings.TrimSpace(factorID) != "" {
		for _, factor := range factors {
			if factor.ID == factorID {
				return factor, nil
			}
		}
		return TwoFactorFactor{}, pgx.ErrNoRows
	}
	for _, factor := range factors {
		if factor.IsDefault {
			return factor, nil
		}
	}
	return factors[0], nil
}

func (s *Service) twoFactorFactorByMethod(ctx context.Context, userID, method string) (TwoFactorFactor, error) {
	method = strings.ToLower(strings.TrimSpace(method))
	if method == "" {
		return s.twoFactorFactor(ctx, userID, "")
	}
	if method != "email" && method != "sms" && method != "totp" {
		return TwoFactorFactor{}, fmt.Errorf("invalid 2FA method: must be 'email', 'sms', or 'totp'")
	}
	factors, err := s.List2FAFactors(ctx, userID)
	if err != nil {
		return TwoFactorFactor{}, err
	}
	if len(factors) == 0 {
		settings, err := s.Get2FASettings(ctx, userID)
		if err != nil || !settings.Enabled || len(settings.Factors) == 0 {
			return TwoFactorFactor{}, fmt.Errorf("2FA not enabled")
		}
		factors = settings.Factors
	}
	for _, factor := range factors {
		if factor.Enabled && strings.EqualFold(factor.Method, method) {
			return factor, nil
		}
	}
	return TwoFactorFactor{}, pgx.ErrNoRows
}

func twoFactorFactorFromFields(id, userID, method string, phone *string, secret []byte, step *int64, isDefault bool, createdAt, updatedAt time.Time) TwoFactorFactor {
	return TwoFactorFactor{
		ID:           id,
		UserID:       userID,
		Method:       method,
		PhoneNumber:  phone,
		TOTPSecret:   secret,
		LastTOTPStep: step,
		IsDefault:    isDefault,
		Enabled:      true, // #125: a factor row existing IS the enabled state
		CreatedAt:    createdAt,
		UpdatedAt:    updatedAt,
	}
}

func generateBackupCodes() (plaintextCodes, hashedCodes []string) {
	plaintextCodes = make([]string, 10)
	hashedCodes = make([]string, 10)
	for i := 0; i < 10; i++ {
		code := randAlphanumericUppercase(8)
		plaintextCodes[i] = code
		hashedCodes[i] = sha256Hex(code)
	}
	return plaintextCodes, hashedCodes
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

// requirePG returns an error when no Postgres pool is configured (verify-only /
// config-only construction). Store-backed methods guard on it.
func (s *Service) requirePG() error {
	if s.pg == nil {
		return fmt.Errorf("postgres not configured")
	}
	return nil
}

// dedupeStrings trims, drops empties, and de-duplicates a string slice,
// preserving first-seen order.
func dedupeStrings(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}
