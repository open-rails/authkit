package authcore

import (
	"fmt"
	stdlog "log"
	"net/url"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/open-rails/authkit/internal/db"
	"github.com/open-rails/authkit/jwtkit"
)

// Construction and Config validation. There is ONE config type (Config, #237)
// and ONE normalization pass (normalizeConfig): the Service reads the
// normalized Config directly, so a knob cannot exist internally without being
// settable by hosts. NewFromConfig is THE host construction path (key/TOTP
// resolution + required-field checks); NewService is the module-internal
// low-level seam (explicit Keyset, sparse configs) used by tests.

const (
	defaultOIDCReturnPath            = "/login/callback"
	defaultFrontendVerifyPath        = "/verify"
	defaultFrontendPasswordResetPath = "/reset"
	defaultFrontendPasswordlessPath  = "/passwordless"
	defaultFrontendInvitePath        = "/accept-invite"
)

// normalizeConfig is the single defaulting/validation pass every Service's
// Config goes through, exactly once, at construction. It returns a normalized
// COPY: trimmed strings, defaulted paths/TTLs/limits, canonical enum values.
// Required-field presence (Issuer, audiences) is NewFromConfig's job — sparse
// test configs stay constructible through NewService.
func normalizeConfig(cfg Config) (Config, error) {
	cfg.Token.Issuer = strings.TrimSpace(cfg.Token.Issuer)
	cfg.Environment = strings.TrimSpace(cfg.Environment)
	cfg.SolanaNetwork = strings.TrimSpace(cfg.SolanaNetwork)

	// BaseURL defaults from a well-formed Issuer URL.
	cfg.Frontend.BaseURL = strings.TrimSpace(cfg.Frontend.BaseURL)
	if cfg.Frontend.BaseURL == "" && isWellFormattedURL(cfg.Token.Issuer) {
		cfg.Frontend.BaseURL = cfg.Token.Issuer
	}

	var err error
	if cfg.Frontend.OIDCReturnPath, err = normalizeFrontendPath("OIDCReturnPath", cfg.Frontend.OIDCReturnPath, defaultOIDCReturnPath); err != nil {
		return Config{}, err
	}
	if cfg.Frontend.VerifyPath, err = normalizeFrontendPath("FrontendVerifyPath", cfg.Frontend.VerifyPath, defaultFrontendVerifyPath); err != nil {
		return Config{}, err
	}
	if cfg.Frontend.PasswordResetPath, err = normalizeFrontendPath("FrontendPasswordResetPath", cfg.Frontend.PasswordResetPath, defaultFrontendPasswordResetPath); err != nil {
		return Config{}, err
	}
	if cfg.Frontend.PasswordlessPath, err = normalizeFrontendPath("FrontendPasswordlessPath", cfg.Frontend.PasswordlessPath, defaultFrontendPasswordlessPath); err != nil {
		return Config{}, err
	}
	if cfg.Frontend.InvitePath, err = normalizeFrontendPath("FrontendInvitePath", cfg.Frontend.InvitePath, defaultFrontendInvitePath); err != nil {
		return Config{}, err
	}

	// Empty ExpectedAudiences defaults to IssuedAudiences (copied, not aliased).
	if len(cfg.Token.ExpectedAudiences) == 0 && len(cfg.Token.IssuedAudiences) > 0 {
		cfg.Token.ExpectedAudiences = append([]string(nil), cfg.Token.IssuedAudiences...)
	}

	// 0 (unset) => default 3; negative => unlimited (session code treats <=0 as no cap).
	if cfg.Token.SessionMaxPerUser == 0 {
		cfg.Token.SessionMaxPerUser = 3
	}
	if cfg.Token.AccessTokenDuration == 0 {
		// Short default bounds revocation lag (logout / ban / password-change)
		// to one TTL window; refresh-token rotation re-issues silently. See
		// authkit #90 — we deliberately rely on this bound instead of a
		// per-request jti/liveness lookup.
		cfg.Token.AccessTokenDuration = 15 * time.Minute
	}
	// RefreshTokenDuration: 0 or less => indefinite sessions.

	// SessionEventRetention: 0 (unset) => 365 days; negative => keep forever (#245).
	if cfg.SessionEventRetention == 0 {
		cfg.SessionEventRetention = 365 * 24 * time.Hour
	}

	if cfg.Registration.Verification, err = normalizeRegistrationVerification(cfg.Registration.Verification); err != nil {
		return Config{}, err
	}
	mode, err := normalizeRegistrationMode(cfg.Registration.NativeUserMode)
	if err != nil {
		return Config{}, fmt.Errorf("authkit: invalid NativeUserRegistrationMode %q (want one of: open, invite_only, closed)", cfg.Registration.NativeUserMode)
	}
	cfg.Registration.NativeUserMode = mode

	cfg.APIKeys.Prefix = strings.TrimSpace(cfg.APIKeys.Prefix)
	if !validAPIKeyPrefix(cfg.APIKeys.Prefix) {
		return Config{}, fmt.Errorf("authkit: invalid APIKeyPrefix %q (want lowercase alphanumeric, 1-16 chars, or empty)", cfg.APIKeys.Prefix)
	}

	if cfg.Schema, err = normalizeSchemaName(cfg.Schema); err != nil {
		return Config{}, err
	}

	cfg.TwoFactor.Mode = normalizeTwoFactorMode(cfg.TwoFactor.Mode)
	cfg.TwoFactor.Methods = append([]TwoFactorMethod(nil), cfg.TwoFactor.Methods...)

	// Passkey RP identity derives from the BaseURL origin. A non-empty BaseURL
	// must be a valid origin (fail loud, as before); an empty one is only
	// reachable via the low-level NewService path — passkeys stay unconfigured
	// there unless RPID is set explicitly.
	if cfg.Frontend.BaseURL != "" {
		rpid, name, origins, uv, err := normalizePasskeyConfig(cfg.Passkeys, cfg.Frontend.BaseURL, cfg.Token.Issuer)
		if err != nil {
			return Config{}, err
		}
		cfg.Passkeys = PasskeyConfig{RPID: rpid, RPDisplayName: name, Origins: origins, UserVerification: uv}
	} else {
		cfg.Passkeys.UserVerification = normalizePasskeyUserVerification(cfg.Passkeys.UserVerification)
	}
	return cfg, nil
}

// NewService is the low-level constructor: explicit Keyset, no key/TOTP
// resolution, no required-field checks. Module-internal plumbing (tests and
// NewFromConfig); hosts construct via embedded.New / NewFromConfig. Panics on
// config values normalizeConfig rejects (malformed schema/paths/modes) — at
// this layer they are programmer errors (NewFromConfig returns them instead).
//
// The Keyset is fixed for the lifetime of the Service — there is no rotation
// path here. Hosts that need hot-reloaded signing keys construct via
// NewFromConfig / embedded.New with a live jwtkit.KeySource (#238).
func NewService(cfg Config, keys Keyset, coreOpts ...Option) *Service {
	norm, err := normalizeConfig(cfg)
	if err != nil {
		panic(err.Error())
	}
	var gs *GroupSchema
	if len(norm.RBAC) > 0 {
		if gs, err = BuildSchema(norm.RBAC...); err != nil {
			panic(fmt.Sprintf("permission-group schema: %v", err))
		}
	}
	src := jwtkit.StaticKeySource{Active: keys.Active, Pubs: keys.PublicKeys}
	return newService(norm, src, gs, coreOpts...)
}

// newService assembles a Service from an already-normalized Config. keys is
// read per-operation via the KeySource interface (never snapshotted) so a
// live, hot-reloading source (jwtkit.FileKeySource) is observed for as long as
// the Service exists.
func newService(norm Config, keys jwtkit.KeySource, gs *GroupSchema, coreOpts ...Option) *Service {
	s := &Service{
		cfg:               norm,
		keys:              keys,
		schema:            norm.Schema,
		groupSchema:       gs,
		solanaSNSResolver: newDefaultSolanaSNSResolver(),
	}
	for _, o := range coreOpts {
		if o != nil {
			o(s)
		}
	}
	return s
}

// NewFromConfig creates a Service from the host Config + Stores.
// If Keys.Source is nil, keys are resolved from <Keys.Path>/keys.json — or,
// ONLY with the explicit Keys.AllowEphemeralDevKeys opt-in, generated for dev.
func NewFromConfig(cfg Config, pg *pgxpool.Pool, extraOpts ...Option) (*Service, error) {
	// Handle nil Keys.Source — resolve from <Keys.Path>/keys.json (empty Path ⇒
	// /vault/auth). No environment variables are consulted (#231): AuthKit is a
	// library and the HOST owns the process env; binaries (cmd/authkit-server)
	// read env at their own boundary and set these fields explicitly. With no
	// keys and no Keys.AllowEphemeralDevKeys opt-in, construction fails loudly
	// instead of silently minting dev signing keys.
	keySource := cfg.Keys.Source
	if keySource == nil && cfg.Keys.VerifyOnly {
		// #87: explicit verify-only — NO signer and NO key discovery. Minting
		// returns ErrMissingSigner; verification, RBAC reads, and the (empty)
		// JWKS endpoint all work. A pure resource-server / control-plane boots
		// without any file/dev key.
		keySource = jwtkit.StaticKeySource{}
	}
	if keySource == nil {
		var err error
		keySource, err = jwtkit.ResolveKeySource(strings.TrimSpace(cfg.Keys.Path), cfg.Keys.AllowEphemeralDevKeys)
		if err != nil {
			return nil, fmt.Errorf("authkit: failed to resolve JWT signing keys (set Keys.Path to a directory containing keys.json, provide Keys.Source, or — for development only — set Keys.AllowEphemeralDevKeys): %w", err)
		}
	}
	// keySource is held live, NOT snapshotted into a Keyset: a reloadable file
	// source hot-swaps its active signer/public keys behind an atomic pointer
	// as keys.json rotates, and the Service must keep observing it for the
	// rest of the process lifetime (#238) rather than freezing the keys seen
	// at construction time.

	norm, err := normalizeConfig(cfg)
	if err != nil {
		return nil, err
	}

	// Required host-facing fields (the low-level NewService path skips these).
	if norm.Token.Issuer == "" {
		return nil, fmt.Errorf("authkit: Issuer is required (e.g., \"https://myapp.com\")")
	}
	if !isWellFormattedURL(norm.Token.Issuer) {
		stdlog.Printf("authkit: warning: Issuer is not a well-formatted URL: %q", norm.Token.Issuer)
		if norm.Frontend.BaseURL == "" {
			return nil, fmt.Errorf("authkit: BaseURL is required when Issuer is not a well-formatted URL (issuer=%q)", norm.Token.Issuer)
		}
	}
	if len(norm.Token.IssuedAudiences) == 0 {
		return nil, fmt.Errorf("authkit: IssuedAudiences is required (e.g., []string{\"myapp\", \"billing-app\"})")
	}

	// #232: TOTP secret-encryption key — explicit override (validated) or
	// <Keys.Path>/totp.key; nil (no key configured) fails closed at enrollment.
	// The resolved key is written back into the normalized Config: the Service
	// reads Config, so what it reads IS what was resolved.
	totpSecretKey, err := resolveTOTPSecretKey(norm)
	if err != nil {
		return nil, err
	}
	norm.TwoFactor.TOTPSecretKey = totpSecretKey
	if totpSecretKey == nil && norm.TwoFactor.Mode != TwoFactorDisabled && twoFactorMethodListed(norm.TwoFactor.Methods, TwoFactorTOTP) {
		stdlog.Printf("authkit: warning: TOTP is offered by 2FA policy but no key material is configured (no %s/%s, no TwoFactor.TOTPSecretKey) — TOTP will be reported unavailable and enrollment will fail closed", totpKeysDir(norm), totpKeyFilename)
	}

	// #111: build + validate the permission-group schema (intrinsic root injected
	// when the app declares none). A bad catalog/containment fails construction.
	gs, gerr := BuildSchema(norm.RBAC...)
	if gerr != nil {
		return nil, fmt.Errorf("permission-group schema: %w", gerr)
	}

	// pg is positional but MAY be nil at the core layer (verify-only construction
	// or config-only unit tests need no store); WithPostgres(nil) is a no-op, so a
	// nil pg simply yields a Service with no querier. The mandatory-Postgres
	// contract (#106) is enforced at the host-facing authhttp.NewServer, not here.
	coreOpts := append([]Option{WithPostgres(pg)}, extraOpts...)
	return newService(norm, keySource, gs, coreOpts...), nil
}

// normalizeSchemaName trims and validates a Postgres schema name, defaulting to
// db.DefaultSchema when empty. A malformed name would be spliced into SQL text,
// so this is the single injection guard both constructors share: NewService
// panics on the error, NewFromConfig returns it.
func normalizeSchemaName(raw string) (string, error) {
	schema := strings.TrimSpace(raw)
	if schema == "" {
		schema = db.DefaultSchema
	}
	if !db.ValidSchemaName(schema) {
		return "", fmt.Errorf("authkit: invalid Schema %q (want lowercase identifier matching ^[a-z_][a-z0-9_]*$, max 63 bytes)", raw)
	}
	return schema, nil
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
		// Empty => none (matches the Config doc and the zero-config path: "required"
		// with no sender wired would make NewServer fail).
		return RegistrationVerificationNone, nil
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

// Registration-policy reads. The stored Config is normalized at construction,
// but these re-normalize defensively: some tests build a zero Service{}.

// RegistrationVerificationPolicy returns the effective registration
// verification policy ("none" when unset/invalid).
func (s *Service) RegistrationVerificationPolicy() RegistrationVerificationPolicy {
	v, err := normalizeRegistrationVerification(s.cfg.Registration.Verification)
	if err != nil {
		return RegistrationVerificationNone
	}
	return v
}

func (s *Service) RegistrationVerificationRequired() bool {
	return s.RegistrationVerificationPolicy() == RegistrationVerificationRequired
}

func (s *Service) RegistrationVerificationEnabled() bool {
	return s.RegistrationVerificationPolicy() != RegistrationVerificationNone
}

// PublicNativeUserRegistrationEnabled reports whether public native-user
// self-registration / auto-registration is allowed.
func (s *Service) PublicNativeUserRegistrationEnabled() bool {
	mode, err := normalizeRegistrationMode(s.cfg.Registration.NativeUserMode)
	return err == nil && mode == RegistrationModeOpen
}

// requireMFAEnrollment reports whether every user must enroll a second factor
// before establishing/refreshing a session (TwoFactor.Mode == "required").
func (s *Service) requireMFAEnrollment() bool {
	return normalizeTwoFactorMode(s.cfg.TwoFactor.Mode) == TwoFactorRequired
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
