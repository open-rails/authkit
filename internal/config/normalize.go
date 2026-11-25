package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/db"
	"github.com/open-rails/authkit/internal/lang"
)

// Defaults Normalize applies.
const (
	// APIVersion is the version segment AuthKit owns beneath Surface.API: the
	// JSON API is {Base}{API}/v1. A breaking change mounts /v2 beside it.
	APIVersion = "/v1"
	// The username lengths internal/naming enforces.
	usernameMinLength = 4
	usernameMaxLength = 30

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
	if err := normalizeIssuer(&c); err != nil {
		return Config{}, nil, err
	}
	if c.AccountIssuers, err = normalizeAccountIssuers(c.AccountIssuers, c.Issuer); err != nil {
		return Config{}, nil, err
	}
	if c.EntitlementClaims, err = normalizeEntitlementClaims(c.EntitlementClaims); err != nil {
		return Config{}, nil, err
	}
	if err := normalizeTuning(&c); err != nil {
		return Config{}, nil, err
	}
	switch c.SolanaNetwork {
	case "", iam.SolanaMainnet, iam.SolanaTestnet, iam.SolanaDevnet:
	default:
		degrade(fmt.Errorf("authkit: invalid SolanaNetwork %q (want mainnet, testnet or devnet); Sign In With Solana is off", c.SolanaNetwork))
		c.SolanaNetwork = ""
	}

	if c.Registration, err = normalizeRegistration(c.Registration); err != nil {
		return Config{}, nil, err
	}
	if err := normalizeAgreements(&c); err != nil {
		return Config{}, nil, err
	}
	if c.SMSCountries, err = normalizeSMSCountries(c.SMSCountries); err != nil {
		return Config{}, nil, err
	}
	if c.HTTP != nil && !Mounted(c, iam.RouteInvitations) && c.Registration == iam.RegistrationModeInviteOnly {
		return Config{}, nil, errors.New("authkit: Registration \"invite_only\" needs invitations, but HTTP.Groups leaves out RouteInvitations")
	}
	if c.Usernames, err = normalizeUsernames(c.Usernames); err != nil {
		return Config{}, nil, err
	}
	switch c.TwoFactor {
	case "":
		c.TwoFactor = iam.TwoFactorOptional
	case iam.TwoFactorDisabled, iam.TwoFactorOptional, iam.TwoFactorRequired:
	default:
		return Config{}, nil, fmt.Errorf("authkit: invalid TwoFactor %q (want disabled, optional, or required)", c.TwoFactor)
	}
	c.APIKeyPrefix = strings.TrimSpace(c.APIKeyPrefix)
	if !validAPIKeyPrefix(c.APIKeyPrefix) {
		return Config{}, nil, fmt.Errorf("authkit: invalid APIKeyPrefix %q (want lowercase alphanumeric, 1-16 chars, or empty)", c.APIKeyPrefix)
	}
	if err := normalizeAuthorizationServer(&c.AuthorizationServer, c); err != nil {
		return Config{}, nil, err
	}
	c.RemoteApplications = normalizeRemoteApplications(c.RemoteApplications, degrade)
	if err := normalizeResource(&c.Resource); err != nil {
		return Config{}, nil, err
	}
	c.Languages = normalizeLanguages(c.Languages, degrade)

	if c.Database.RiverSchema, err = NormalizeRiverSchema(c.Database.RiverSchema, c.Database.Schema); err != nil {
		return Config{}, nil, err
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

// normalizeAccountIssuers puts issuer first and drops repeats.
func normalizeAccountIssuers(raw []string, issuer string) ([]string, error) {
	out := []string{issuer}
	for _, r := range raw {
		other := strings.TrimSpace(r)
		if other == "" {
			return nil, errors.New("authkit: AccountIssuers contains a blank issuer")
		}
		if !slices.Contains(out, other) {
			out = append(out, other)
		}
	}
	return out, nil
}

func normalizeEntitlementClaims(names []string) ([]string, error) {
	if len(names) == 0 {
		return nil, nil
	}
	unique := make(map[string]struct{}, len(names))
	for _, name := range names {
		if name == "" || strings.TrimSpace(name) != name || !utf8.ValidString(name) || len(name) > maxTokenEntitlementNameBytes {
			return nil, fmt.Errorf("authkit: EntitlementClaims names must be nonempty UTF-8 values without surrounding whitespace and at most %d bytes", maxTokenEntitlementNameBytes)
		}
		unique[name] = struct{}{}
		if len(unique) > maxTokenEntitlements {
			return nil, fmt.Errorf("authkit: EntitlementClaims exceeds %d distinct names", maxTokenEntitlements)
		}
	}
	out := make([]string, 0, len(unique))
	for name := range unique {
		out = append(out, name)
	}
	slices.Sort(out)
	raw, err := json.Marshal(out)
	if err != nil || len(raw) > maxTokenEntitlementBytes {
		return nil, fmt.Errorf("authkit: EntitlementClaims exceeds %d encoded bytes", maxTokenEntitlementBytes)
	}
	return out, nil
}

func normalizeRegistration(raw iam.RegistrationMode) (iam.RegistrationMode, error) {
	mode := iam.RegistrationMode(strings.ToLower(strings.TrimSpace(string(raw))))
	switch mode {
	case "":
		return iam.RegistrationModeOpen, nil
	case iam.RegistrationModeOpen, iam.RegistrationModeInviteOnly, iam.RegistrationModeClosed:
		return mode, nil
	}
	return "", fmt.Errorf("authkit: invalid Registration %q (want one of: open, invite_only, closed)", raw)
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
	return nil
}

// normalizeSMSCountries upper-cases the allowed regions and refuses one that
// is not two letters.
func normalizeSMSCountries(raw []string) ([]string, error) {
	regions := make([]string, 0, len(raw))
	for _, r := range raw {
		r = strings.ToUpper(strings.TrimSpace(r))
		if len(r) != 2 || r[0] < 'A' || r[0] > 'Z' || r[1] < 'A' || r[1] > 'Z' {
			return nil, fmt.Errorf("authkit: SMSCountries entry %q is not an ISO 3166-1 alpha-2 region", r)
		}
		regions = append(regions, r)
	}
	return dedup(regions), nil
}

func isHTTPURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host != ""
}

// normalizeUsernames checks the generated-username pool: each entry fits
// the username length with its three-digit suffix.
func normalizeUsernames(pool []string) ([]string, error) {
	if pool == nil {
		return nil, nil
	}
	if len(pool) == 0 {
		return nil, errors.New("authkit: Usernames must not be empty")
	}
	seen := make(map[string]bool, len(pool))
	out := slices.Clone(pool)
	for _, name := range out {
		canonical := strings.ToLower(name)
		if !randomUsernameBase.MatchString(name) || len(name)+3 < usernameMinLength || len(name)+3 > usernameMaxLength {
			return nil, fmt.Errorf("authkit: Usernames entry %q must be a valid base whose length plus three fits %d..%d", name, usernameMinLength, usernameMaxLength)
		}
		if seen[canonical] {
			return nil, fmt.Errorf("authkit: Usernames repeats %q (case-insensitive)", name)
		}
		seen[canonical] = true
	}
	return out, nil
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

// normalizeLanguages drops an entry that is not a language code, and
// repeats: the first is the default.
func normalizeLanguages(raw []string, degrade func(error)) []string {
	var out []string
	for _, r := range raw {
		code := lang.Normalize(r)
		if code == "" {
			degrade(fmt.Errorf("authkit: Languages %q is not a language code; it is ignored", r))
			continue
		}
		if !slices.Contains(out, code) {
			out = append(out, code)
		}
	}
	return out
}

// DefaultLanguage is c's default language: its first, else English.
func DefaultLanguage(c Config) string {
	if len(c.Languages) > 0 {
		return c.Languages[0]
	}
	return lang.Default
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

// NormalizeRiverSchema defaults River's schema to AuthKit's own, the
// normalized schema.
func NormalizeRiverSchema(raw, schema string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw != "" {
		schema = raw
	}
	if !db.ValidSchemaName(schema) {
		return "", fmt.Errorf("authkit: invalid Database.RiverSchema %q", raw)
	}
	return schema, nil
}

func normalizeHTTP(h *HTTPConfig, c Config, d Deps, degrade func(error)) error {
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
		degrade(errors.New("authkit: no email or SMS sender is configured, so sign-ups and codes answer email_unavailable until one is"))
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
