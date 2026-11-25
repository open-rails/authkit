package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
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
)

// Defaults Normalize applies.
const (
	// APIVersion is the version segment AuthKit owns beneath Surface.API: the
	// JSON API is {Base}{API}/v1. A breaking change mounts /v2 beside it.
	APIVersion               = "/v1"
	DefaultPasswordMinLength = 8
	DefaultPasswordMaxLength = 128
	PasswordMaxLengthCeiling = 1024
	DefaultUsernameMinLength = 4
	DefaultUsernameMaxLength = 30
	UsernameMaxLengthCeiling = 64
	DefaultRenameInterval    = 72 * time.Hour
	DefaultNameRetention     = 90 * 24 * time.Hour

	maxTokenEntitlements         = 32
	maxTokenEntitlementNameBytes = 128
	maxTokenEntitlementBytes     = 2048
)

// Normalize applies every default and checks every rule of c and d, once:
// authkit.New calls it and hands the result to the engine and the HTTP
// layer. It returns a normalized copy; normalizing that copy again changes
// nothing. err is a problem AuthKit cannot run safely with; degraded lists
// the survivable ones, each already handled by switching off or defaulting
// only the feature it concerns. Warnings go to d.Logger, which New has set.
func Normalize(c Config, d Deps) (_ Config, degraded []error, err error) {
	degrade := func(problem error) { degraded = append(degraded, problem) }
	if c.Tenancy != TenancySingle && c.Tenancy != TenancyMulti {
		return Config{}, nil, fmt.Errorf("authkit: invalid Tenancy %s (want TenancySingle or TenancyMulti)", c.Tenancy)
	}
	if c.Database.Schema, err = NormalizeSchema(c.Database.Schema); err != nil {
		return Config{}, nil, err
	}
	if err := normalizeNotifications(&c); err != nil {
		return Config{}, nil, err
	}
	if err := normalizeIssuer(&c); err != nil {
		return Config{}, nil, err
	}
	if err := normalizeToken(&c.Token, c.Issuer); err != nil {
		return Config{}, nil, err
	}
	if err := normalizeTuning(&c); err != nil {
		return Config{}, nil, err
	}
	switch c.SignIn.DPoP {
	case "":
		c.SignIn.DPoP = DPoPOptional
	case DPoPOptional, DPoPRequired:
	default:
		return Config{}, nil, fmt.Errorf("authkit: invalid SignIn.DPoP %q (want optional or required)", c.SignIn.DPoP)
	}
	switch c.SolanaNetwork {
	case "", iam.SolanaMainnet, iam.SolanaTestnet, iam.SolanaDevnet:
	default:
		degrade(fmt.Errorf("authkit: invalid SolanaNetwork %q (want mainnet, testnet or devnet); Sign In With Solana is off", c.SolanaNetwork))
		c.SolanaNetwork = ""
	}

	if err := normalizeRegistration(&c.Registration); err != nil {
		return Config{}, nil, err
	}
	if err := normalizeAgreements(&c); err != nil {
		return Config{}, nil, err
	}
	if err := normalizeSMS(&c.SMS); err != nil {
		return Config{}, nil, err
	}
	if c.HTTP != nil && !Mounted(c, iam.RouteInvitations) && c.Registration.NativeUserMode == iam.RegistrationModeInviteOnly {
		return Config{}, nil, errors.New("authkit: Registration.NativeUserMode \"invite_only\" needs invitations, but HTTP.Groups leaves out RouteInvitations")
	}
	if c.Password, err = NormalizePassword(c.Password); err != nil {
		return Config{}, nil, err
	}
	if c.Username, err = NormalizeUsername(c.Username); err != nil {
		return Config{}, nil, err
	}
	if c.Tenants.FormerNames, err = normalizeNameRetention("Tenants.FormerNames", c.Tenants.FormerNames, NameRetentionFinite); err != nil {
		return Config{}, nil, err
	}
	switch c.TwoFactor.Mode {
	case "":
		c.TwoFactor.Mode = iam.TwoFactorOptional
	case iam.TwoFactorDisabled, iam.TwoFactorOptional, iam.TwoFactorRequired:
	default:
		return Config{}, nil, fmt.Errorf("authkit: invalid TwoFactor.Mode %q (want disabled, optional, or required)", c.TwoFactor.Mode)
	}
	c.TwoFactor.Methods = slices.Clone(c.TwoFactor.Methods)
	for _, m := range c.TwoFactor.Methods {
		switch m {
		case iam.TwoFactorEmail, iam.TwoFactorSMS, iam.TwoFactorTOTP:
		default:
			return Config{}, nil, fmt.Errorf("authkit: invalid TwoFactor.Methods entry %q (want email, sms, or totp)", m)
		}
	}
	if n := len(c.TwoFactor.TOTPSecretKey); n > 0 && n != 16 && n != 24 && n != 32 {
		return Config{}, nil, fmt.Errorf("authkit: TwoFactor.TOTPSecretKey must be 16, 24, or 32 bytes, got %d", n)
	}

	c.APIKeys.Prefix = strings.TrimSpace(c.APIKeys.Prefix)
	if !validAPIKeyPrefix(c.APIKeys.Prefix) {
		return Config{}, nil, fmt.Errorf("authkit: invalid APIKeyPrefix %q (want lowercase alphanumeric, 1-16 chars, or empty)", c.APIKeys.Prefix)
	}
	if c.PersonalAccessTokens.DefaultTTL == 0 {
		c.PersonalAccessTokens.DefaultTTL = 30 * 24 * time.Hour
	}
	if c.PersonalAccessTokens.MaxTTL == 0 {
		c.PersonalAccessTokens.MaxTTL = 90 * 24 * time.Hour
	}
	if c.PersonalAccessTokens.DefaultTTL < time.Second || c.PersonalAccessTokens.MaxTTL < c.PersonalAccessTokens.DefaultTTL {
		return Config{}, nil, errors.New("authkit: personal token TTLs must be positive and default_ttl must not exceed max_ttl")
	}
	if err := normalizeAuthorizationServer(&c.AuthorizationServer, c); err != nil {
		return Config{}, nil, err
	}
	c.RemoteApplications = normalizeRemoteApplications(c.RemoteApplications, degrade)
	if err := normalizeResource(&c.Resource); err != nil {
		return Config{}, nil, err
	}
	normalizeLanguages(&c.Languages, degrade)

	if c.Database.RiverSchema, err = NormalizeRiverSchema(c.Database.RiverSchema); err != nil {
		return Config{}, nil, err
	}
	if c.CleanupInterval == 0 {
		c.CleanupInterval = time.Hour
	}
	if c.CleanupInterval < time.Second {
		degrade(fmt.Errorf("authkit: CleanupInterval %s is under one second; using one hour", c.CleanupInterval))
		c.CleanupInterval = time.Hour
	}
	c.Provisioning.Targets = slices.Clone(c.Provisioning.Targets)
	for i := range c.Provisioning.Targets {
		if c.Provisioning.Targets[i].TenantID.IsZero() {
			c.Provisioning.Targets[i].TenantID = c.DefaultTenantID
		}
		if c.Provisioning.Targets[i].TenantID.IsZero() && !c.tenantPending() {
			return c, nil, fmt.Errorf("authkit: Provisioning.Targets[%d] requires TenantID in an unbound deployment", i)
		}
	}
	if err := normalizeProvisioning(&c.Provisioning, d, degrade); err != nil {
		return Config{}, nil, err
	}
	if c.HTTP != nil {
		h := *c.HTTP
		if err := normalizeHTTP(&h, c, d, degrade); err != nil {
			return Config{}, nil, err
		}
		c.HTTP = &h
	}
	return c, degraded, nil
}

// normalizeRemoteApplications trims the declared set. An entry with no issuer,
// or an issuer declared twice, is dropped: an issuer no entry declares is
// disabled at boot, so its tokens are refused. Nil stays nil: an undeclared
// set. The engine checks each trust source and role.
func normalizeRemoteApplications(apps []RemoteApplicationConfig, degrade func(error)) []RemoteApplicationConfig {
	if apps == nil {
		return nil
	}
	// Issuers compare as the engine does: case-insensitively, ignoring a
	// trailing slash.
	key := func(issuer string) string { return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(issuer), "/")) }
	count, reported := map[string]int{}, map[string]bool{}
	for i := range apps {
		count[key(apps[i].Issuer)]++
	}
	out := make([]RemoteApplicationConfig, 0, len(apps))
	for _, app := range apps {
		app.Issuer = strings.TrimSpace(app.Issuer)
		switch {
		case app.Issuer == "":
			degrade(errors.New("authkit: Config.RemoteApplications contains an application with no Issuer; it is ignored"))
			continue
		case count[key(app.Issuer)] > 1:
			if k := key(app.Issuer); !reported[k] {
				degrade(fmt.Errorf("authkit: Config.RemoteApplications declares %q %d times; its tokens are refused until it is declared once", app.Issuer, count[k]))
				reported[k] = true
			}
			continue
		}
		out = append(out, app)
	}
	return out
}

// normalizeIssuer checks the issuer, the one URL the HTTP surface, links and
// relying-party names derive from, and defaults FrontendURL to its origin.
func normalizeIssuer(c *Config) error {
	c.Issuer = strings.TrimSpace(c.Issuer)
	if c.Issuer == "" {
		return errors.New("authkit: Issuer is required (e.g., \"https://myapp.com\")")
	}
	if err := secureURL("Issuer", c.Issuer); err != nil {
		return err
	}
	u, _ := url.Parse(c.Issuer)
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" || strings.Contains(c.Issuer, "#") {
		return fmt.Errorf("authkit: Issuer %q must not carry user info, a query or a fragment", c.Issuer)
	}
	if _, err := MountPath("Issuer path", u.EscapedPath()); err != nil {
		return err
	}
	c.FrontendURL = strings.TrimRight(strings.TrimSpace(c.FrontendURL), "/")
	if c.FrontendURL == "" {
		c.FrontendURL = u.Scheme + "://" + u.Host
	}
	if err := secureURL("FrontendURL", c.FrontendURL); err != nil {
		return err
	}
	if f, _ := url.Parse(c.FrontendURL); f.User != nil || f.RawQuery != "" || f.Fragment != "" || strings.Contains(c.FrontendURL, "#") {
		return fmt.Errorf("authkit: FrontendURL %q must not carry user info, a query or a fragment", c.FrontendURL)
	}
	return nil
}

func normalizeToken(t *TokenConfig, issuer string) error {
	accountIssuers := []string{issuer}
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

	if t.RefreshTokenDuration == 0 {
		t.RefreshTokenDuration = 30 * 24 * time.Hour
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

	return nil
}

var randomUsernameBase = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]*$`)

var agreementKey = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

// normalizeAgreements trims the declared documents and refuses a malformed or
// repeated key, a missing version or URL, and a registration requirement that
// names no declared document.
func normalizeAgreements(c *Config) error {
	declared := map[string]bool{}
	out := make([]AgreementConfig, 0, len(c.Agreements))
	for _, a := range c.Agreements {
		a.Key, a.Version, a.URL = strings.TrimSpace(a.Key), strings.TrimSpace(a.Version), strings.TrimSpace(a.URL)
		switch {
		case !agreementKey.MatchString(a.Key):
			return fmt.Errorf("authkit: Agreements key %q must be 1-64 lowercase letters, digits, '-' or '_'", a.Key)
		case declared[a.Key]:
			return fmt.Errorf("authkit: Agreements declares %q twice", a.Key)
		case a.Version == "" || len(a.Version) > 64:
			return fmt.Errorf("authkit: Agreements %q needs a version of 1-64 characters", a.Key)
		case !isHTTPURL(a.URL):
			return fmt.Errorf("authkit: Agreements %q needs an absolute http(s) URL", a.Key)
		}
		declared[a.Key] = true
		out = append(out, a)
	}
	if len(out) == 0 {
		out = nil
	}
	c.Agreements = out
	required := dedup(c.Registration.Agreements)
	for _, key := range required {
		if !declared[key] {
			return fmt.Errorf("authkit: Registration.Agreements names %q, which Agreements does not declare", key)
		}
	}
	c.Registration.Agreements = required
	return nil
}

// normalizeSMS upper-cases the allowed regions and refuses one that is not
// two letters.
func normalizeSMS(s *SMSConfig) error {
	regions := make([]string, 0, len(s.AllowedCountries))
	for _, r := range s.AllowedCountries {
		r = strings.ToUpper(strings.TrimSpace(r))
		if len(r) != 2 || r[0] < 'A' || r[0] > 'Z' || r[1] < 'A' || r[1] > 'Z' {
			return fmt.Errorf("authkit: SMS.AllowedCountries entry %q is not an ISO 3166-1 alpha-2 region", r)
		}
		regions = append(regions, r)
	}
	s.AllowedCountries = dedup(regions)
	return nil
}

func isHTTPURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host != ""
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
	if u.RandomNames != nil {
		if len(u.RandomNames) == 0 {
			return u, errors.New("authkit: Username.RandomNames must not be empty")
		}
		seen := make(map[string]bool, len(u.RandomNames))
		u.RandomNames = slices.Clone(u.RandomNames)
		for _, name := range u.RandomNames {
			canonical := strings.ToLower(name)
			if !randomUsernameBase.MatchString(name) || len(name)+3 < u.MinLength || len(name)+3 > u.MaxLength {
				return u, fmt.Errorf("authkit: Username.RandomNames entry %q must be a valid base whose length plus three fits %d..%d", name, u.MinLength, u.MaxLength)
			}
			if seen[canonical] {
				return u, fmt.Errorf("authkit: Username.RandomNames repeats %q (case-insensitive)", name)
			}
			seen[canonical] = true
		}
	}
	if u.RenameInterval == 0 {
		u.RenameInterval = DefaultRenameInterval
	}
	var err error
	if u.FormerNames, err = normalizeNameRetention("Username.FormerNames", u.FormerNames, NameRetentionFinite); err != nil {
		return u, err
	}
	u.DeletedNames, err = normalizeNameRetention("Username.DeletedNames", u.DeletedNames, NameRetentionForever)
	return u, err
}

// normalizeNameRetention gives an empty Mode the field's fallback, or finite
// when a Duration is set.
func normalizeNameRetention(field string, r NameRetention, fallback NameRetentionMode) (NameRetention, error) {
	if r.Mode == "" {
		r.Mode = fallback
		if r.Duration != 0 {
			r.Mode = NameRetentionFinite
		}
	}
	switch r.Mode {
	case NameRetentionFinite:
		if r.Duration < 0 {
			return r, fmt.Errorf("authkit: %s.Duration must not be negative", field)
		}
		if r.Duration == 0 {
			r.Duration = DefaultNameRetention
		}
	case NameRetentionForever, NameRetentionImmediate:
		if r.Duration != 0 {
			return r, fmt.Errorf("authkit: %s.Duration needs Mode %q", field, NameRetentionFinite)
		}
	default:
		return r, fmt.Errorf("authkit: invalid %s.Mode %q", field, r.Mode)
	}
	return r, nil
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

// normalizeLanguages drops a Supported entry that is not a language code and
// replaces an unusable Default with "en", or the first supported language.
func normalizeLanguages(l *LanguageConfig, degrade func(error)) {
	var supported []string
	for _, raw := range l.Supported {
		code := lang.Normalize(raw)
		if code == "" {
			degrade(fmt.Errorf("authkit: Languages.Supported %q is not a language code; it is ignored", raw))
			continue
		}
		if !slices.Contains(supported, code) {
			supported = append(supported, code)
		}
	}
	l.Supported = supported
	fallback := lang.Default
	if len(supported) > 0 && !slices.Contains(supported, fallback) {
		fallback = supported[0]
	}
	if strings.TrimSpace(l.Default) == "" {
		l.Default = fallback
	}
	code := lang.Normalize(l.Default)
	switch {
	case code == "":
		degrade(fmt.Errorf("authkit: Languages.Default %q is not a language code; using %q", l.Default, fallback))
		code = fallback
	case len(supported) > 0 && !slices.Contains(supported, code):
		degrade(fmt.Errorf("authkit: Languages.Default %q is not in Languages.Supported; using %q", l.Default, fallback))
		code = fallback
	}
	l.Default = code
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
		return "", fmt.Errorf("authkit: invalid Database.Schema %q (want lowercase identifier matching ^[a-z_][a-z0-9_]*$, max 63 bytes)", raw)
	}
	return schema, nil
}

// NormalizeRiverSchema defaults River's schema to public.
func NormalizeRiverSchema(raw string) (string, error) {
	schema := strings.TrimSpace(raw)
	if schema == "" {
		schema = "public"
	}
	if !db.ValidSchemaName(schema) {
		return "", fmt.Errorf("authkit: invalid Database.RiverSchema %q", raw)
	}
	return schema, nil
}

func normalizeHTTP(h *HTTPConfig, c Config, d Deps, degrade func(error)) error {
	if h.RefreshCookieName != "" {
		if strings.HasPrefix(h.RefreshCookieName, "__Host-") || (&http.Cookie{Name: h.RefreshCookieName, Value: "valid"}).Valid() != nil {
			return errors.New("authkit: HTTP.RefreshCookieName must be a valid base cookie name without __Host-")
		}
	}
	if d.Postgres == nil {
		return errors.New("authkit: HTTP requires Deps.Postgres")
	}
	h.Groups = slices.Clone(h.Groups)
	if _, err := ParseCIDRs("trusted proxy", h.TrustedProxies); err != nil {
		return err
	}
	if _, err := ParseCIDRs("Cloudflare proxy", h.CloudflareProxies); err != nil {
		return err
	}
	postures := 0
	for _, set := range []bool{len(h.TrustedProxies) > 0 || len(h.CloudflareProxies) > 0, h.DirectPeerIP, d.ClientIP != nil} {
		if set {
			postures++
		}
	}
	switch {
	case postures == 0:
		return errors.New("authkit: a client-IP posture is required — set HTTPConfig.TrustedProxies/CloudflareProxies for the proxies in front, DirectPeerIP to assert there are none, or Deps.ClientIP; behind an undeclared proxy every client shares one rate-limit bucket")
	case postures > 1:
		return errors.New("authkit: declare one client-IP posture, not several — HTTPConfig.TrustedProxies/CloudflareProxies for the proxies in front, DirectPeerIP for none, or Deps.ClientIP for the host's own")
	}

	if d.Email == nil && d.SMS == nil {
		if c.Registration.Verification == iam.RegistrationVerificationRequired && !c.Registration.AllowMissingSenders {
			degrade(fmt.Errorf("authkit: registration verification policy is %q but no email or SMS sender is configured; registration answers email_unavailable until one is", iam.RegistrationVerificationRequired))
		} else {
			d.Logger.Warn("authkit: no email or SMS sender configured; verification delivery is disabled")
		}
	}
	for _, cl := range c.AuthorizationServer.Clients {
		if len(cl.AuthorizationDetailsTypes) > 0 && d.OAuthGrants == nil {
			return fmt.Errorf("authkit: AuthorizationServer client %q declares AuthorizationDetailsTypes but no grant authorizer is wired — set authkit.Deps.OAuthGrants", cl.ID)
		}
	}
	return nil
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

// secureURL refuses raw unless it is an https URL, or http on a loopback
// host (localhost, 127.0.0.0/8, [::1]) for local development.
func secureURL(field, raw string) error {
	u, err := url.Parse(raw)
	switch {
	case err != nil || u.Host == "" || u.Scheme != "https" && u.Scheme != "http":
		return fmt.Errorf("authkit: %s %q must be an https URL", field, raw)
	case u.Scheme == "http" && !loopbackHost(u.Hostname()):
		return fmt.Errorf("authkit: %s %q must be https; http is allowed only on a loopback host (localhost, 127.0.0.1, [::1])", field, raw)
	}
	return nil
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
