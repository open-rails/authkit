package authcore

import (
	"fmt"
	stdlog "log"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/open-rails/authkit/internal/db"
	jwtkit "github.com/open-rails/authkit/jwt"
)

// Construction and Options/Config validation: the two entry points (NewService
// from low-level Options, NewFromConfig from high-level Config), the normalize*
// validators they share, and the registration-policy reads on Options.

const (
	defaultOIDCReturnPath            = "/login/callback"
	defaultFrontendVerifyPath        = "/verify"
	defaultFrontendPasswordResetPath = "/reset"
	defaultFrontendPasswordlessPath  = "/passwordless"
	defaultFrontendInvitePath        = "/accept-invite"
)

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
	schema, err := normalizeSchemaName(opts.Schema)
	if err != nil {
		// A malformed schema name would be spliced into SQL text; refusing to
		// construct the service is the injection guard for the Options path
		// (NewFromConfig returns this as an error instead).
		panic(err.Error())
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
	oidcReturnPath, err := normalizeFrontendPath("OIDCReturnPath", cfg.Frontend.OIDCReturnPath, defaultOIDCReturnPath)
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
	schema, err := normalizeSchemaName(cfg.Schema)
	if err != nil {
		return nil, err
	}
	twoFactorMode := normalizeTwoFactorMode(cfg.TwoFactor.Mode)
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
		TwoFactorMode:                       twoFactorMode,
		TwoFactorMethods:                    append([]TwoFactorMethod(nil), cfg.TwoFactor.Methods...),
		RequireMFAEnrollment:                twoFactorMode == TwoFactorRequired,
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
