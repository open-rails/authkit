package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/db"
	"github.com/open-rails/authkit/internal/lang"
	"github.com/open-rails/authkit/internal/ratelimit"
)

// Defaults Normalize applies.
const (
	DefaultAPIPath = "/api"
	// APIVersion is the version segment AuthKit owns beneath APIPath: the
	// JSON API is {BasePath}{APIPath}/v1. A breaking change mounts /v2 beside
	// it.
	APIVersion                     = "/v1"
	DefaultPasswordMinLength       = 8
	DefaultPasswordMaxLength       = 128
	PasswordMaxLengthCeiling       = 1024
	DefaultUsernameMinLength       = 4
	DefaultUsernameMaxLength       = 30
	UsernameMaxLengthCeiling       = 64
	DefaultRenameInterval          = 72 * time.Hour
	DefaultFormerNameRetention     = 90 * 24 * time.Hour
	defaultOIDCReturnPath          = "/login/callback"
	defaultVerifyPath              = "/verify"
	defaultPasswordResetPath       = "/reset"
	defaultPasswordlessPath        = "/passwordless"
	defaultInvitePath              = "/accept-invite"
	defaultAuthorizePath           = "/authorize"
	DefaultDelegatedTTLFloor       = time.Minute
	DefaultDelegatedTTLDefault     = 15 * time.Minute
	DefaultDelegatedTTLCeiling     = time.Hour
	maxTokenEntitlements           = 32
	maxTokenEntitlementNameBytes   = 128
	maxTokenEntitlementBytes       = 2048
	defaultVerificationSendTimeout = 15 * time.Second
	DefaultAccountsPerDevice       = 5
	DefaultAccountsPerAddress      = 20
	DefaultNewDevicesPerAccount    = 10
)

// Normalize applies every default and checks every rule of c and d, once:
// authkit.New calls it and hands the result to the engine and the HTTP
// layer. It returns a normalized copy; normalizing that copy again changes
// nothing.
func Normalize(c Config, d Deps) (Config, error) {
	var err error
	if c.Schema, err = NormalizeSchema(c.Schema); err != nil {
		return Config{}, err
	}
	if err := normalizeToken(&c.Token); err != nil {
		return Config{}, err
	}
	c.SignIn = NormalizeSignIn(c.SignIn)
	switch c.SolanaNetwork {
	case "", iam.SolanaMainnet, iam.SolanaTestnet, iam.SolanaDevnet:
	default:
		return Config{}, fmt.Errorf("authkit: invalid SolanaNetwork %q (want mainnet, testnet or devnet)", c.SolanaNetwork)
	}
	if err := normalizeFrontend(&c.Frontend, c.Token.Issuer); err != nil {
		return Config{}, err
	}
	if err := normalizeRegistration(&c.Registration); err != nil {
		return Config{}, err
	}
	if c.Invitations.Disabled && c.Registration.NativeUserMode == iam.RegistrationModeInviteOnly {
		return Config{}, errors.New("authkit: Registration.NativeUserMode \"invite_only\" needs invitations, but Invitations.Disabled is set")
	}
	if c.Password, err = NormalizePassword(c.Password); err != nil {
		return Config{}, err
	}
	if c.Username, err = NormalizeUsername(c.Username); err != nil {
		return Config{}, err
	}
	switch c.TwoFactor.Mode {
	case "":
		c.TwoFactor.Mode = iam.TwoFactorOptional
	case iam.TwoFactorDisabled, iam.TwoFactorOptional, iam.TwoFactorRequired:
	default:
		return Config{}, fmt.Errorf("authkit: invalid TwoFactor.Mode %q (want disabled, optional, or required)", c.TwoFactor.Mode)
	}
	c.TwoFactor.Methods = slices.Clone(c.TwoFactor.Methods)
	for _, m := range c.TwoFactor.Methods {
		switch m {
		case iam.TwoFactorEmail, iam.TwoFactorSMS, iam.TwoFactorTOTP:
		default:
			return Config{}, fmt.Errorf("authkit: invalid TwoFactor.Methods entry %q (want email, sms, or totp)", m)
		}
	}
	if n := len(c.TwoFactor.TOTPSecretKey); n > 0 && n != 16 && n != 24 && n != 32 {
		return Config{}, fmt.Errorf("authkit: TwoFactor.TOTPSecretKey must be 16, 24, or 32 bytes, got %d", n)
	}
	if err := normalizePasskeys(&c.Passkeys, c.Frontend.BaseURL, c.Token.Issuer); err != nil {
		return Config{}, err
	}
	c.APIKeys.Prefix = strings.TrimSpace(c.APIKeys.Prefix)
	if !validAPIKeyPrefix(c.APIKeys.Prefix) {
		return Config{}, fmt.Errorf("authkit: invalid APIKeyPrefix %q (want lowercase alphanumeric, 1-16 chars, or empty)", c.APIKeys.Prefix)
	}
	if err := normalizeDelegated(&c.Delegated); err != nil {
		return Config{}, err
	}
	if err := normalizeAuthorizationServer(&c.AuthorizationServer, c); err != nil {
		return Config{}, err
	}
	if c.RemoteApplications, err = normalizeRemoteApplications(c.RemoteApplications); err != nil {
		return Config{}, err
	}
	if err := normalizeLanguages(&c.Languages); err != nil {
		return Config{}, err
	}
	if c.SenderHealthInterval <= 0 {
		c.SenderHealthInterval = 5 * time.Minute
	}
	if c.SessionEventRetention == 0 {
		c.SessionEventRetention = 365 * 24 * time.Hour
	}
	if c.River, err = NormalizeRiver(c.River); err != nil {
		return Config{}, err
	}
	if d.OnEvent != nil && d.Postgres == nil {
		return Config{}, errors.New("authkit: OnEvent requires Deps.Postgres")
	}
	if c.HTTP != nil {
		h := *c.HTTP
		if err := normalizeHTTP(&h, c, d); err != nil {
			return Config{}, err
		}
		c.HTTP = &h
	}
	return c, nil
}

// normalizeRemoteApplications trims the declared set and refuses a blank or
// repeated issuer. Nil stays nil: an undeclared set. The engine checks each
// trust source and role.
func normalizeRemoteApplications(apps []RemoteApplicationConfig) ([]RemoteApplicationConfig, error) {
	out := slices.Clone(apps)
	seen := make(map[string]bool, len(out))
	for i := range out {
		out[i].Issuer, out[i].JWKSURI = strings.TrimSpace(out[i].Issuer), strings.TrimSpace(out[i].JWKSURI)
		if out[i].Issuer == "" {
			return nil, errors.New("authkit: Config.RemoteApplications contains an application with no Issuer")
		}
		if seen[out[i].Issuer] {
			return nil, fmt.Errorf("authkit: Config.RemoteApplications declares %q twice", out[i].Issuer)
		}
		seen[out[i].Issuer] = true
	}
	return out, nil
}

// NormalizeSignIn applies the sign-in limit defaults; a negative limit is off
// and stays negative.
func NormalizeSignIn(c SignInConfig) SignInConfig {
	for _, f := range []struct {
		value *int
		def   int
	}{
		{&c.AccountsPerDevice, DefaultAccountsPerDevice},
		{&c.AccountsPerAddress, DefaultAccountsPerAddress},
		{&c.NewDevicesPerAccount, DefaultNewDevicesPerAccount},
	} {
		if *f.value == 0 {
			*f.value = f.def
		}
	}
	return c
}

func normalizeToken(t *TokenConfig) error {
	t.Issuer = strings.TrimSpace(t.Issuer)
	if t.Issuer == "" {
		return errors.New("authkit: Issuer is required (e.g., \"https://myapp.com\")")
	}
	if len(t.IssuedAudiences) == 0 {
		return errors.New("authkit: IssuedAudiences is required (e.g., []string{\"myapp\", \"billing-app\"})")
	}
	t.IssuedAudiences = slices.Clone(t.IssuedAudiences)
	if len(t.ExpectedAudiences) == 0 {
		t.ExpectedAudiences = slices.Clone(t.IssuedAudiences)
	}
	accountIssuers := []string{t.Issuer}
	for _, raw := range t.AccountIssuers {
		issuer := strings.TrimSpace(raw)
		if issuer == "" {
			return errors.New("authkit: Token.AccountIssuers contains a blank issuer")
		}
		if !slices.Contains(accountIssuers, issuer) {
			accountIssuers = append(accountIssuers, issuer)
		}
	}
	t.AccountIssuers = accountIssuers
	if t.SessionMaxPerUser == 0 {
		t.SessionMaxPerUser = 3
	}
	if t.RefreshRotationGrace == 0 {
		t.RefreshRotationGrace = 30 * time.Second
	}
	if t.AccessTokenDuration == 0 {
		// Short: it bounds how long a revoked session's token still passes
		// stateless verification. Refresh rotation re-issues silently.
		t.AccessTokenDuration = 15 * time.Minute
	}
	var err error
	t.EntitlementAllowlist, err = normalizeEntitlementAllowlist(t.EntitlementAllowlist)
	return err
}

func normalizeEntitlementAllowlist(names []string) ([]string, error) {
	if len(names) == 0 {
		return nil, nil
	}
	unique := make(map[string]struct{}, len(names))
	for _, name := range names {
		if name == "" || strings.TrimSpace(name) != name || !utf8.ValidString(name) || len(name) > maxTokenEntitlementNameBytes {
			return nil, fmt.Errorf("authkit: Token.EntitlementAllowlist names must be nonempty UTF-8 values without surrounding whitespace and at most %d bytes", maxTokenEntitlementNameBytes)
		}
		unique[name] = struct{}{}
		if len(unique) > maxTokenEntitlements {
			return nil, fmt.Errorf("authkit: Token.EntitlementAllowlist exceeds %d distinct names", maxTokenEntitlements)
		}
	}
	out := make([]string, 0, len(unique))
	for name := range unique {
		out = append(out, name)
	}
	slices.Sort(out)
	raw, err := json.Marshal(out)
	if err != nil || len(raw) > maxTokenEntitlementBytes {
		return nil, fmt.Errorf("authkit: Token.EntitlementAllowlist exceeds %d encoded bytes", maxTokenEntitlementBytes)
	}
	return out, nil
}

func normalizeFrontend(f *FrontendConfig, issuer string) error {
	f.BaseURL = strings.TrimSpace(f.BaseURL)
	if !isURL(issuer) {
		slog.Warn("authkit: Issuer is not a well-formatted URL", "issuer", issuer)
		if f.BaseURL == "" {
			return fmt.Errorf("authkit: BaseURL is required when Issuer is not a well-formatted URL (issuer=%q)", issuer)
		}
	}
	if f.BaseURL == "" {
		f.BaseURL = issuer
	}
	for _, p := range []struct {
		field string
		value *string
		def   string
	}{
		{"OIDCReturnPath", &f.OIDCReturnPath, defaultOIDCReturnPath},
		{"FrontendVerifyPath", &f.VerifyPath, defaultVerifyPath},
		{"FrontendPasswordResetPath", &f.PasswordResetPath, defaultPasswordResetPath},
		{"FrontendPasswordlessPath", &f.PasswordlessPath, defaultPasswordlessPath},
		{"FrontendInvitePath", &f.InvitePath, defaultInvitePath},
		{"FrontendAuthorizePath", &f.AuthorizePath, defaultAuthorizePath},
	} {
		v, err := frontendPath(p.field, *p.value, p.def)
		if err != nil {
			return err
		}
		*p.value = v
	}
	return nil
}

func frontendPath(name, raw, defaultPath string) (string, error) {
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
	return u.RequestURI(), nil
}

func normalizeRegistration(r *RegistrationConfig) error {
	v := iam.RegistrationVerificationPolicy(strings.ToLower(strings.TrimSpace(string(r.Verification))))
	switch v {
	case "":
		v = iam.RegistrationVerificationNone
	case iam.RegistrationVerificationNone, iam.RegistrationVerificationOptional, iam.RegistrationVerificationRequired:
	default:
		return fmt.Errorf("authkit: invalid RegistrationVerification %q (want \"none\", \"optional\", or \"required\")", r.Verification)
	}
	r.Verification = v
	mode := iam.RegistrationMode(strings.ToLower(strings.TrimSpace(string(r.NativeUserMode))))
	switch mode {
	case "":
		mode = iam.RegistrationModeOpen
	case iam.RegistrationModeOpen, iam.RegistrationModeInviteOnly, iam.RegistrationModeClosed:
	default:
		return fmt.Errorf("authkit: invalid NativeUserRegistrationMode %q (want one of: open, invite_only, closed)", r.NativeUserMode)
	}
	r.NativeUserMode = mode
	if r.VerificationSendTimeout <= 0 {
		r.VerificationSendTimeout = defaultVerificationSendTimeout
	}
	return nil
}

// NormalizePassword returns the policy with its zero lengths defaulted.
func NormalizePassword(out PasswordPolicy) (PasswordPolicy, error) {
	if out.MinLength == 0 {
		out.MinLength = DefaultPasswordMinLength
	}
	if out.MaxLength == 0 {
		out.MaxLength = max(DefaultPasswordMaxLength, out.MinLength)
	}
	if out.MinLength < 1 || out.MaxLength < out.MinLength || out.MaxLength > PasswordMaxLengthCeiling {
		return PasswordPolicy{}, fmt.Errorf("authkit: invalid password policy min_length=%d max_length=%d (want 1 <= min <= max <= %d)", out.MinLength, out.MaxLength, PasswordMaxLengthCeiling)
	}
	return out, nil
}

// NormalizeUsername applies the username defaults and rules.
func NormalizeUsername(u UsernameConfig) (UsernameConfig, error) {
	if u.MinLength == 0 {
		u.MinLength = DefaultUsernameMinLength
	}
	if u.MaxLength == 0 {
		u.MaxLength = max(DefaultUsernameMaxLength, u.MinLength)
	}
	if u.MinLength < 1 || u.MaxLength < u.MinLength || u.MaxLength > UsernameMaxLengthCeiling {
		return u, fmt.Errorf("authkit: invalid username policy min_length=%d max_length=%d (want 1 <= min <= max <= %d)", u.MinLength, u.MaxLength, UsernameMaxLengthCeiling)
	}
	if u.RenameInterval == 0 {
		u.RenameInterval = DefaultRenameInterval
	}
	switch u.FormerNames.Mode {
	case "", FormerNamesFinite:
		u.FormerNames.Mode = FormerNamesFinite
		if u.FormerNames.Duration < 0 {
			return u, errors.New("authkit: Username.FormerNames.Duration must not be negative")
		}
		if u.FormerNames.Duration == 0 {
			u.FormerNames.Duration = DefaultFormerNameRetention
		}
	case FormerNamesForever, FormerNamesImmediate:
		if u.FormerNames.Duration != 0 {
			return u, fmt.Errorf("authkit: Username.FormerNames.Duration needs Mode %q", FormerNamesFinite)
		}
	default:
		return u, fmt.Errorf("authkit: invalid Username.FormerNames.Mode %q", u.FormerNames.Mode)
	}
	return u, nil
}

// Passkey relying-party identity derives from the BaseURL origin; without a
// usable BaseURL passkeys stay unconfigured unless RPID is set.
func normalizePasskeys(p *PasskeyConfig, baseURL, issuer string) error {
	p.UserVerification = passkeyUserVerification(p.UserVerification)
	if baseURL == "" {
		return nil
	}
	u, err := url.Parse(strings.TrimRight(baseURL, "/"))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return errors.New("authkit: Passkeys require a valid BaseURL origin")
	}
	u.Path, u.RawQuery, u.Fragment = "", "", ""
	p.RPID = strings.ToLower(strings.TrimSpace(p.RPID))
	if p.RPID == "" {
		p.RPID = strings.ToLower(u.Hostname())
	}
	p.RPDisplayName = strings.TrimSpace(p.RPDisplayName)
	if p.RPDisplayName == "" {
		p.RPDisplayName = issuer
	}
	origins := slices.Clone(p.Origins)
	if len(origins) == 0 {
		origins = []string{u.String()}
	}
	for i, raw := range origins {
		o, err := url.Parse(strings.TrimRight(strings.TrimSpace(raw), "/"))
		if err != nil || o.Scheme == "" || o.Host == "" {
			return errors.New("authkit: invalid Passkey origin")
		}
		host := strings.ToLower(o.Hostname())
		if host != p.RPID && !strings.HasSuffix(host, "."+p.RPID) {
			return errors.New("authkit: Passkey origin host must match RPID or a subdomain")
		}
		o.Path, o.RawQuery, o.Fragment = "", "", ""
		origins[i] = o.String()
	}
	p.Origins = origins
	return nil
}

func passkeyUserVerification(value string) string {
	switch v := strings.ToLower(strings.TrimSpace(value)); v {
	case "required", "discouraged":
		return v
	default:
		return "preferred"
	}
}

// validAPIKeyPrefix: empty, or 1-16 lowercase alphanumeric characters.
func validAPIKeyPrefix(p string) bool {
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

// An impossible TTL triple refuses at construction, never a silent clamp.
// TTLs or DPoP set while the route is disabled are dead config and refuse too.
func normalizeDelegated(d *DelegatedConfig) error {
	d.Audiences = dedup(d.Audiences)
	if len(d.Audiences) == 0 {
		if d.AllowDPoP || d.TTLFloor != 0 || d.TTLDefault != 0 || d.TTLCeiling != 0 {
			return errors.New("authkit: Delegated TTLs or DPoP are set but Delegated.Audiences is empty — the mint route is disabled without an audience allowlist")
		}
		return nil
	}
	if d.TTLFloor < 0 || d.TTLDefault < 0 || d.TTLCeiling < 0 {
		return fmt.Errorf("authkit: Delegated TTLs must not be negative (floor=%v default=%v ceiling=%v)", d.TTLFloor, d.TTLDefault, d.TTLCeiling)
	}
	if d.TTLFloor == 0 {
		d.TTLFloor = DefaultDelegatedTTLFloor
	}
	if d.TTLDefault == 0 {
		d.TTLDefault = DefaultDelegatedTTLDefault
	}
	if d.TTLCeiling == 0 {
		d.TTLCeiling = DefaultDelegatedTTLCeiling
	}
	if d.TTLFloor > d.TTLCeiling || d.TTLDefault < d.TTLFloor || d.TTLDefault > d.TTLCeiling {
		return fmt.Errorf("authkit: Delegated TTLs must satisfy floor <= default <= ceiling (floor=%v default=%v ceiling=%v)", d.TTLFloor, d.TTLDefault, d.TTLCeiling)
	}
	return nil
}

func normalizeLanguages(l *LanguageConfig) error {
	var supported []string
	for _, raw := range l.Supported {
		code := lang.Normalize(raw)
		if code == "" {
			return fmt.Errorf("authkit: Languages.Supported %q is not a language code", raw)
		}
		if !slices.Contains(supported, code) {
			supported = append(supported, code)
		}
	}
	l.Supported = supported
	if strings.TrimSpace(l.Default) == "" {
		l.Default = lang.Default
	}
	code := lang.Normalize(l.Default)
	if code == "" {
		return fmt.Errorf("authkit: Languages.Default %q is not a language code", l.Default)
	}
	if len(supported) > 0 && !slices.Contains(supported, code) {
		return fmt.Errorf("authkit: Languages.Default %q is not in Languages.Supported", l.Default)
	}
	l.Default = code
	return nil
}

// NormalizeSchema trims and validates a PostgreSQL schema name, defaulting to
// "profiles". The name is spliced into SQL text, so this is the injection
// guard.
func NormalizeSchema(raw string) (string, error) {
	schema := strings.TrimSpace(raw)
	if schema == "" {
		schema = db.DefaultSchema
	}
	if !db.ValidSchemaName(schema) {
		return "", fmt.Errorf("authkit: invalid Schema %q (want lowercase identifier matching ^[a-z_][a-z0-9_]*$, max 63 bytes)", raw)
	}
	return schema, nil
}

// NormalizeRiver defaults River's schema to public and cleanup to hourly.
func NormalizeRiver(r RiverConfig) (RiverConfig, error) {
	r.Schema = strings.TrimSpace(r.Schema)
	if r.Schema == "" {
		r.Schema = "public"
	}
	if !db.ValidSchemaName(r.Schema) {
		return r, fmt.Errorf("authkit: invalid River.Schema %q", r.Schema)
	}
	if r.CleanupInterval == 0 {
		r.CleanupInterval = time.Hour
	}
	if r.CleanupInterval < time.Second {
		return r, errors.New("authkit: River.CleanupInterval must be at least one second")
	}
	return r, nil
}

func normalizeHTTP(h *HTTPConfig, c Config, d Deps) error {
	if d.Postgres == nil {
		return errors.New("authkit: HTTP requires Deps.Postgres")
	}
	var err error
	if h.BasePath, err = basePath(h.BasePath, c.Token.Issuer); err != nil {
		return err
	}
	h.APIPath = strings.TrimSpace(h.APIPath)
	if h.APIPath == "" {
		h.APIPath = DefaultAPIPath
	}
	if h.APIPath, err = MountPath("APIPath", h.APIPath); err != nil {
		return err
	}
	if h.APIPath == "" {
		h.APIPath = "/" // the version segment sits right beneath BasePath
	}
	if h.PublicURL, err = publicURL(h.PublicURL, c.Token.Issuer, h.BasePath); err != nil {
		return err
	}
	h.Groups = slices.Clone(h.Groups)
	h.Exclude = slices.Clone(h.Exclude)
	if _, err := ParseCIDRs("trusted proxy", h.TrustedProxies); err != nil {
		return err
	}
	if _, err := ParseCIDRs("Cloudflare proxy", h.CloudflareProxies); err != nil {
		return err
	}
	if d.ClientIP == nil && !h.DirectPeerIP && len(h.TrustedProxies) == 0 && len(h.CloudflareProxies) == 0 {
		return errors.New("authkit: a client-IP posture is required — set HTTPConfig.TrustedProxies/CloudflareProxies for the proxies in front, DirectPeerIP to assert there are none, or Deps.ClientIP; behind an undeclared proxy every client shares one rate-limit bucket")
	}
	if err := ratelimit.ValidateLimits(h.RateLimits); err != nil {
		return err
	}
	if h.RedisKeyPrefix, err = redisKeyPrefix(h.RedisKeyPrefix, c.Schema); err != nil {
		return err
	}
	if d.Email == nil && d.SMS == nil {
		if c.Registration.Verification == iam.RegistrationVerificationRequired {
			return fmt.Errorf("authkit: registration verification policy is %q but no email or SMS sender is configured", iam.RegistrationVerificationRequired)
		}
		slog.Warn("authkit: no email or SMS sender configured; verification delivery is disabled")
	}
	if len(c.Delegated.Audiences) > 0 && d.DelegatedAuthorization == nil {
		return errors.New("authkit: Config.Delegated.Audiences is set but no delegation authorizer is wired — set authkit.Deps.DelegatedAuthorization")
	}
	if len(c.Delegated.Audiences) == 0 && d.DelegatedAuthorization != nil {
		return errors.New("authkit: Deps.DelegatedAuthorization is wired but Config.Delegated.Audiences is empty — the mint route is disabled; drop the dead wiring or declare audiences")
	}
	return nil
}

// basePath derives the base from the issuer's path, or checks a set one
// against it: JWKS is only found where the issuer says. A non-URL issuer has
// no path, so any base goes.
func basePath(configured, issuer string) (string, error) {
	u, err := url.Parse(issuer)
	derived := ""
	if err == nil && isURL(issuer) {
		if derived, err = MountPath("Token.Issuer path", u.EscapedPath()); err != nil {
			return "", err
		}
	}
	if strings.TrimSpace(configured) == "" {
		return derived, nil
	}
	base, err := MountPath("BasePath", configured)
	if err != nil {
		return "", err
	}
	if isURL(issuer) && base != derived {
		return "", fmt.Errorf("authkit: BasePath %q must equal the path of Token.Issuer %q, where verifiers look for JWKS", configured, issuer)
	}
	return base, nil
}

// publicURL defaults to the issuer's origin plus base; a set value is an
// http(s) URL without query or fragment, kept without a trailing slash.
func publicURL(raw, issuer, base string) (string, error) {
	raw = strings.TrimRight(strings.TrimSpace(raw), "/")
	if raw == "" {
		if !isURL(issuer) {
			return "", nil
		}
		u, _ := url.Parse(issuer)
		return u.Scheme + "://" + u.Host + base, nil
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("authkit: HTTPConfig.PublicURL %q must be an http(s) URL without credentials, query or fragment", raw)
	}
	return raw, nil
}

// Plain segments only: framework routers read them literally, and escaped
// and unescaped forms are the same string.
var mountPathRE = regexp.MustCompile(`^(/[A-Za-z0-9_~-][A-Za-z0-9._~-]*)+$`)

// MountPath normalizes a configured path: surrounding space and trailing
// slashes are dropped, so "/" is "" (root).
func MountPath(field, p string) (string, error) {
	p = strings.TrimRight(strings.TrimSpace(p), "/")
	if p != "" && !mountPathRE.MatchString(p) {
		return "", fmt.Errorf("authkit: %s %q must be an absolute path of plain segments", field, p)
	}
	return p, nil
}

// ParseCIDRs parses proxy ranges.
func ParseCIDRs(kind string, cidrs []string) ([]netip.Prefix, error) {
	prefixes := make([]netip.Prefix, 0, len(cidrs))
	for _, c := range cidrs {
		p, err := netip.ParsePrefix(strings.TrimSpace(c))
		if err != nil {
			return nil, fmt.Errorf("authkit: invalid %s CIDR %q: %w", kind, c, err)
		}
		prefixes = append(prefixes, p)
	}
	return prefixes, nil
}

var redisKeyPrefixRE = regexp.MustCompile(`^[a-z0-9_.:-]{1,64}$`)

func redisKeyPrefix(prefix, schema string) (string, error) {
	prefix = strings.TrimSpace(prefix)
	if prefix == "" {
		prefix = "authkit:" + schema + ":"
	}
	if !strings.HasSuffix(prefix, ":") {
		prefix += ":"
	}
	if !redisKeyPrefixRE.MatchString(prefix) {
		return "", fmt.Errorf("authkit: invalid HTTPConfig.RedisKeyPrefix %q (want ^[a-z0-9_.:-]{1,64}$)", prefix)
	}
	return prefix, nil
}

func isURL(raw string) bool {
	u, err := url.Parse(strings.TrimSpace(raw))
	return err == nil && strings.TrimSpace(u.Scheme) != "" && strings.TrimSpace(u.Host) != ""
}

// dedup trims, drops empties and duplicates, preserving order.
func dedup(items []string) []string {
	var out []string
	for _, item := range items {
		if item = strings.TrimSpace(item); item != "" && !slices.Contains(out, item) {
			out = append(out, item)
		}
	}
	return out
}
