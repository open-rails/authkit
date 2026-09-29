package engine

import (
	"context"
	"fmt"
	stdlog "log"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/rbac"
	"github.com/open-rails/authkit/verify"

	"github.com/open-rails/authkit/internal/db"
	"github.com/open-rails/authkit/internal/password"
	"github.com/open-rails/authkit/jwtkit"
)

// Construction and Config validation. Config mirrors the public
// authkit.Config field for field (the root maps it and a reflection test
// guards the mapping), so a knob cannot exist internally without being
// settable by hosts. ONE normalization pass (normalizeConfig) runs at
// construction. New is THE host construction path (key/TOTP resolution +
// required-field checks); newWithKeys is the low-level seam (explicit keyset,
// sparse configs) used by tests.

const (
	defaultOIDCReturnPath            = "/login/callback"
	defaultFrontendVerifyPath        = "/verify"
	defaultFrontendPasswordResetPath = "/reset"
	defaultFrontendPasswordlessPath  = "/passwordless"
	defaultFrontendInvitePath        = "/accept-invite"
)

// normalizeConfig is the single defaulting/validation pass every the engine's
// Config goes through, exactly once, at construction. It returns a normalized
// COPY: trimmed strings, defaulted paths/TTLs/limits, canonical enum values.
// Required-field presence (Issuer, audiences) is New's job — sparse
// test configs stay constructible through newWithKeys.
func normalizeConfig(cfg Config) (Config, error) {
	cfg.Token.Issuer = strings.TrimSpace(cfg.Token.Issuer)
	cfg.SolanaNetwork = strings.TrimSpace(cfg.SolanaNetwork)

	// BaseURL defaults from a well-formed Issuer URL.
	cfg.Frontend.BaseURL = strings.TrimSpace(cfg.Frontend.BaseURL)
	if cfg.Frontend.BaseURL == "" && isWellFormattedURL(cfg.Token.Issuer) {
		cfg.Frontend.BaseURL = cfg.Token.Issuer
	}

	var err error
	if cfg.Token.EntitlementAllowlist, err = normalizeEntitlementAllowlist(cfg.Token.EntitlementAllowlist); err != nil {
		return Config{}, err
	}
	if cfg.River, err = normalizeRiverConfig(cfg.River); err != nil {
		return Config{}, err
	}
	if cfg.namingPolicy, err = cfg.Naming.Normalize(); err != nil {
		return Config{}, err
	}
	policy, err := password.Policy(cfg.Password).Normalize()
	if err != nil {
		return Config{}, err
	}
	cfg.Password = PasswordPolicy(policy)
	if cfg.Username, err = cfg.Username.Normalize(); err != nil {
		return Config{}, err
	}
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

	if cfg.Token.AccountIssuers, err = normalizeAccountIssuers(cfg.Token.Issuer, cfg.Token.AccountIssuers); err != nil {
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
	// 0 (unset) => default 30s; negative => disabled (session code treats <=0 as off).
	// Long enough to cover a concurrent refresh that is already in flight, short
	// enough that a stolen token is still detected on the victim's next use.
	if cfg.Token.RefreshRotationGrace == 0 {
		cfg.Token.RefreshRotationGrace = 30 * time.Second
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

	if cfg.Delegated, err = normalizeDelegatedConfig(cfg.Delegated); err != nil {
		return Config{}, err
	}
	if cfg.Documents, err = normalizeDocumentsConfig(cfg.Documents); err != nil {
		return Config{}, err
	}

	switch cfg.TwoFactor.Mode {
	case "":
		cfg.TwoFactor.Mode = iam.TwoFactorOptional
	case iam.TwoFactorDisabled, iam.TwoFactorOptional, iam.TwoFactorRequired:
	default:
		return Config{}, fmt.Errorf("authkit: invalid TwoFactor.Mode %q (want disabled, optional, or required)", cfg.TwoFactor.Mode)
	}
	cfg.TwoFactor.Methods = append([]iam.TwoFactorMethod(nil), cfg.TwoFactor.Methods...)

	// Passkey RP identity derives from the BaseURL origin. A non-empty BaseURL
	// must be a valid origin (fail loud, as before); an empty one is only
	// reachable via the low-level newWithKeys path — passkeys stay unconfigured
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

// New builds the engine from mapped settings: the store, River, the
// permission groups and the request verifier. ctx bounds the boot-time
// database work.
func New(ctx context.Context, cfg Config, deps Deps) (*Engine, error) {
	e, err := newEngine(cfg, deps)
	if err != nil {
		return nil, err
	}
	return e.finish(ctx)
}

// newWithKeys builds from a fixed keyset, skipping key resolution and the
// required-field checks: sparse test configurations.
func newWithKeys(cfg Config, keys keyset, deps Deps) (*Engine, error) {
	e, err := newEngineWithKeys(cfg, keys, deps)
	if err != nil {
		return nil, err
	}
	return e.finish(context.Background())
}

// finish initializes the permission groups, reconciles credentials with the
// role catalog, and builds the verifier; a failure closes the engine.
func (s *Engine) finish(ctx context.Context) (_ *Engine, err error) {
	defer func() {
		if err != nil {
			s.Close()
		}
	}()
	if err := s.initializeGroups(ctx); err != nil {
		return nil, err
	}
	if err := s.reconcileRoleCatalog(ctx); err != nil {
		return nil, err
	}
	if s.verifier, err = s.newVerifier(); err != nil {
		return nil, err
	}
	return s, nil
}

// Verifier verifies requests and tokens against this engine.
func (s *Engine) Verifier() *verify.Verifier { return s.verifier }

// newEngineWithKeys is the low-level constructor: explicit Keyset, no key/TOTP
// resolution, no required-field checks. The Keyset
// is fixed for the lifetime of the engine — hosts that need hot-reloaded
// signing keys construct via New with a live jwtkit.KeySource (#238).
func newEngineWithKeys(cfg Config, keys keyset, deps Deps) (*Engine, error) {
	norm, err := normalizeConfig(cfg)
	if err != nil {
		return nil, err
	}
	gs, err := norm.Roles.schema()
	if err != nil {
		return nil, err
	}
	src := jwtkit.StaticKeySource{Active: keys.Active, Pubs: keys.PublicKeys}
	return newClient(norm, src, gs, deps)
}

// newService assembles an engine from an already-normalized Config. keys is
// read per-operation via the KeySource interface (never snapshotted) so a
// live, hot-reloading source (jwtkit.FileKeySource) is observed for as long as
// the engine exists.
func newClient(norm Config, keys jwtkit.KeySource, gs *rbac.Schema, deps Deps) (*Engine, error) {
	s := &Engine{
		cfg:               norm,
		keys:              keys,
		schema:            norm.Schema,
		groupSchema:       gs,
		solanaSNSResolver: newDefaultSolanaSNSResolver(),
		now:               time.Now,
	}
	if err := s.applyDeps(deps); err != nil {
		return nil, err
	}
	if err := s.probeMigrations(); err != nil {
		s.Close()
		return nil, err
	}
	if s.appHTTPClient == nil {
		s.appHTTPClient = newApplicationsHTTPClient(norm.Applications.AllowPrivateNetworkJWKS, nil)
	}
	if err := s.initRiver(deps.River); err != nil {
		s.Close()
		return nil, err
	}
	return s, nil
}

// newEngine builds the engine from host configuration and runtime dependencies.
// If Keys.Source is nil,
// keys are resolved from <Keys.Path>/keys.json — or, ONLY with the explicit
// Keys.AllowEphemeralDevKeys opt-in, generated for dev.
func newEngine(cfg Config, deps Deps) (_ *Engine, err error) {
	var ownedKeySource *jwtkit.FileKeySource
	defer func() {
		if err != nil && ownedKeySource != nil {
			ownedKeySource.Close()
		}
	}()
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
		keySource, err = jwtkit.ResolveKeySource(strings.TrimSpace(cfg.Keys.Path), cfg.Keys.AllowEphemeralDevKeys, nil)
		if err != nil {
			return nil, fmt.Errorf("authkit: failed to resolve JWT signing keys (set Keys.Path to a directory containing keys.json, provide Keys.Source, or — for development only — set Keys.AllowEphemeralDevKeys): %w", err)
		}
		ownedKeySource, _ = keySource.(*jwtkit.FileKeySource)
	}
	// keySource is held live, NOT snapshotted into a Keyset: a reloadable file
	// source hot-swaps its active signer/public keys behind an atomic pointer
	// as keys.json rotates, and the engine must keep observing it for the
	// rest of the process lifetime (#238) rather than freezing the keys seen
	// at construction time.

	norm, err := normalizeConfig(cfg)
	if err != nil {
		return nil, err
	}

	// Required host-facing fields (the low-level newWithKeys path skips these).
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
	// The resolved key is written back into the normalized Config: the engine
	// reads Config, so what it reads IS what was resolved.
	totpSecretKey, err := resolveTOTPSecretKey(norm)
	if err != nil {
		return nil, err
	}
	norm.TwoFactor.TOTPSecretKey = totpSecretKey
	if totpSecretKey == nil && norm.TwoFactor.Mode != iam.TwoFactorDisabled && twoFactorMethodListed(norm.TwoFactor.Methods, iam.TwoFactorTOTP) {
		stdlog.Printf("authkit: warning: TOTP is offered by 2FA policy but no key material is configured (no %s/%s, no TwoFactor.TOTPSecretKey) — TOTP will be reported unavailable and enrollment will fail closed", totpKeysDir(norm), totpKeyFilename)
	}

	// A bad persona catalog or role fails construction.
	gs, err := norm.Roles.schema()
	if err != nil {
		return nil, err
	}

	// #264: application self-registration needs a declared org persona to hang
	// service-owned orgs off; a bad reference fails construction, not the
	// first registration.
	if norm.Applications.SelfRegistration {
		persona := iam.Persona(strings.TrimSpace(string(norm.Applications.OrgPersona)))
		if _, ok := gs.Persona(persona); !ok || persona == iam.RootPersona {
			return nil, fmt.Errorf("authkit: Applications.OrgPersona %q is not a declared non-root persona", persona)
		}
	}

	// Deps.Postgres MAY be nil at the core layer (verify-only construction or
	// config-only unit tests need no store): a nil pool yields an engine with
	// no querier. The mandatory-Postgres contract (#106) is enforced at the
	// HTTP surface, not here.
	svc, err := newClient(norm, keySource, gs, deps)
	if err != nil {
		return nil, err
	}
	svc.ownedKeySource = ownedKeySource
	ownedKeySource = nil // ownership transferred to svc

	return svc, nil
}

// normalizeSchemaName trims and validates a Postgres schema name, defaulting to
// db.DefaultSchema when empty. A malformed name would be spliced into SQL text,
// so this is the single injection guard both constructors share.
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

func normalizeRegistrationVerification(v iam.RegistrationVerificationPolicy) (iam.RegistrationVerificationPolicy, error) {
	value := iam.RegistrationVerificationPolicy(strings.ToLower(strings.TrimSpace(string(v))))
	if value == "" {
		// Empty => none (matches the Config doc and the zero-config path: "required"
		// with no sender wired would make httpapi.New fail).
		return iam.RegistrationVerificationNone, nil
	}
	switch value {
	case iam.RegistrationVerificationNone, iam.RegistrationVerificationOptional, iam.RegistrationVerificationRequired:
		return value, nil
	default:
		return "", fmt.Errorf("authkit: invalid RegistrationVerification %q (want \"none\", \"optional\", or \"required\")", v)
	}
}

func normalizeRegistrationMode(v iam.RegistrationMode) (iam.RegistrationMode, error) {
	value := iam.RegistrationMode(strings.ToLower(strings.TrimSpace(string(v))))
	if value == "" {
		return iam.RegistrationModeOpen, nil
	}
	switch value {
	case iam.RegistrationModeOpen,
		iam.RegistrationModeInviteOnly,
		iam.RegistrationModeClosed:
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
// but these re-normalize defensively: some tests build a zero engine{}.

// registrationVerificationPolicy returns the effective registration
// verification policy ("none" when unset/invalid).
func (s *Engine) registrationVerificationPolicy() iam.RegistrationVerificationPolicy {
	v, err := normalizeRegistrationVerification(s.cfg.Registration.Verification)
	if err != nil {
		return iam.RegistrationVerificationNone
	}
	return v
}

func (s *Engine) registrationVerificationRequired() bool {
	return s.registrationVerificationPolicy() == iam.RegistrationVerificationRequired
}

func (s *Engine) RegistrationVerificationEnabled() bool {
	return s.registrationVerificationPolicy() != iam.RegistrationVerificationNone
}

// PublicNativeUserRegistrationEnabled reports whether public native-user
// self-registration / auto-registration is allowed.
func (s *Engine) PublicNativeUserRegistrationEnabled() bool {
	mode, err := normalizeRegistrationMode(s.cfg.Registration.NativeUserMode)
	return err == nil && mode == iam.RegistrationModeOpen
}

// requireMFAEnrollment reports whether every user must enroll a second factor
// before establishing/refreshing a session (TwoFactor.Mode == "required").
func (s *Engine) requireMFAEnrollment() bool {
	return s.cfg.TwoFactor.Mode == iam.TwoFactorRequired
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

// normalizeAccountIssuers returns issuer followed by the other configured
// account issuers, trimmed and deduplicated. Blank entries are refused.
func normalizeAccountIssuers(issuer string, configured []string) ([]string, error) {
	out := []string{issuer}
	for _, raw := range configured {
		candidate := strings.TrimSpace(raw)
		if candidate == "" {
			return nil, fmt.Errorf("authkit: Token.AccountIssuers contains a blank issuer")
		}
		if !slices.Contains(out, candidate) {
			out = append(out, candidate)
		}
	}
	return out, nil
}
