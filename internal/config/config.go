// Package config is the one definition of AuthKit's host configuration:
// Config (plain data), Deps (everything that reaches outside the process)
// and the Roles builder. The root package re-exports each type
// under the same name (authkit.Config is config.Config), so these field docs
// are the ones hosts read. Normalize applies every default and rule once.
package config

import (
	"fmt"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/ratelimit"
)

// Config is the host configuration: plain data and policy. Everything that
// reaches outside the process (the pool, senders, keys, providers, hooks) is
// in Deps. authkit.New normalizes it once.
type Config struct {
	// Issuer is this deployment's JWT issuer and the one URL AuthKit derives
	// the rest from (required): an https URL such as "https://myapp.com", http
	// only on a loopback host (localhost, 127.0.0.1, [::1]). Tokens carry it as
	// iss and aud; the HTTP surface lives at its path (the JSON API beneath
	// /auth/v1 at the root, beneath /v1 under a path, JWKS at iam.JWKSPath);
	// cookies and DPoP proofs are scoped to it.
	Issuer string `yaml:"issuer"`
	// FrontendURL is the host SPA's base URL, which may carry a path
	// ("https://myapp.com/admin"). AuthKit's links and redirects land at fixed
	// routes beneath it: /verify, /reset, /passwordless, /invite, /authorize
	// and /login/callback. Its host names passkeys and authenticator-app
	// entries; its scheme decides whether cookies are Secure. Empty is the
	// Issuer's origin.
	FrontendURL string `yaml:"frontend_url"`

	// Tenancy is how many account directories (tenants) the deployment has.
	// TenancySingle, the zero value, is one, which AuthKit creates or adopts
	// and owns. TenancyMulti opts into CreateTenant and ForTenant over many.
	// Set it in code: it has no YAML key.
	Tenancy Tenancy `yaml:"-"`
	// DefaultTenantID is multi-tenant only: the tenant ordinary account
	// operations and HTTP authentication act in when no trusted tenant view
	// or resolver selects one; zero refuses such operations
	// (iam.ErrTenantRequired). A single-tenant deployment names no tenant
	// anywhere: its one tenant is the database's (Client.TenantID).
	DefaultTenantID iam.TenantID `yaml:"default_tenant_id"`
	// Database names the PostgreSQL schemas AuthKit's and River's tables live
	// in. New creates or upgrades them.
	Database DatabaseConfig `yaml:"database"`
	// Roles is the permission model: personas, their permissions and roles
	// (NewRoles). Nil is root-only.
	Roles *Roles `yaml:"-"`

	// Registration is public self-registration: "open" (the default),
	// "invite_only" or "closed". Every sign-up proves its email or phone
	// before the account exists; unless "closed", a verified contact signing
	// in without a password (RoutePasswordless) creates its account, once
	// invited when "invite_only". The host
	// operations (CreateUser, bootstrap, import, SCIM) work in every mode,
	// and the accounts they create sign in by password unproven.
	Registration iam.RegistrationMode `yaml:"registration"`
	// Agreements are the documents users accept, such as terms and a privacy
	// policy, each at its current version. The host reads acceptances with
	// Client.UserAgreements and gates its own features on them. Published by
	// GET {api}/capabilities.
	Agreements []AgreementConfig `yaml:"agreements"`
	// SMSCountries are the ISO 3166-1 alpha-2 regions text messages may go
	// to, such as "US" and "CA"; a number elsewhere is refused with
	// phone_country_not_allowed before anything is sent. Empty allows every
	// region.
	SMSCountries []string `yaml:"sms_countries"`
	// Usernames is the app's pool for generated usernames: a generated name
	// is one entry plus three random digits. Each is a letter, then letters,
	// digits and underscores, 1 to 27 characters. Nil uses "user"; an
	// explicit empty pool is invalid. Usernames, like tenant names, follow
	// the naming policy of github.com/open-rails/authkit/naming.
	Usernames []string `yaml:"usernames"`
	// TwoFactor is the account-wide MFA policy: iam.TwoFactorDisabled,
	// iam.TwoFactorOptional (the default) or iam.TwoFactorRequired (every
	// user enrolls before normal session use). The methods follow from Deps:
	// TOTP with a TOTP key (keys.TOTPSource), SMS with Deps.SMS; never email.
	// Persona.RequireMFA enforces MFA per permission; the root owner always
	// needs it.
	TwoFactor iam.TwoFactorMode `yaml:"two_factor"`
	// Languages are the supported two-letter language codes, the first the
	// default: the HTTP surface negotiates the request's among them, and
	// messages fall back to the first. Empty is English, accepting any.
	Languages []string `yaml:"languages"`
	// SolanaNetwork turns on Sign In With Solana for one chain; the zero value
	// leaves it off. Solana Name Service resolution is built in.
	SolanaNetwork iam.SolanaNetwork `yaml:"solana_network"`
	// APIKeyPrefix brands generated API keys ("openrails" gives
	// openrails_st_…) for secret scanning: lowercase alphanumeric, 1-16
	// characters. Empty gives the bare "st_" marker.
	APIKeyPrefix string `yaml:"api_key_prefix"`
	// EntitlementClaims are the provider-granted entitlement names
	// (Deps.Entitlements) access tokens carry. Empty skips the mint-time
	// lookup and omits the claim.
	EntitlementClaims []string `yaml:"entitlement_claims"`
	// AccountIssuers lists every issuer whose deployment shares this account
	// store (the same Schema on the same database), e.g. two sites with
	// separate logins over one set of accounts. Account-level revocations
	// (admin emergency revoke, password or contact changes, ban, deletion)
	// cover refresh sessions on all of them, and they share membership: who
	// holds which role, root included. Each declares its own Roles: a role's
	// permissions are per app, and each app re-checks only the credentials it
	// issued. Issuer is always included; empty means Issuer alone. Every
	// deployment sharing the store should list the same set.
	AccountIssuers []string `yaml:"account_issuers"`

	// AuthorizationServer makes this deployment an OAuth 2.0 authorization
	// server and OpenID provider for its registered clients: they sign users
	// in here and receive tokens for registered resource servers. The zero
	// value leaves it off and its routes unmounted.
	AuthorizationServer AuthorizationServerConfig `yaml:"authorization_server"`
	// Resource makes this deployment a resource server: Client.Authenticator
	// also admits the RFC 9068 access tokens minted for Resource.ID, by this
	// deployment's authorization server and by its trusted issuers (remote
	// applications). The zero value admits none.
	Resource ResourceConfig `yaml:"resource"`
	// RemoteApplications declares the remote applications root controls, as
	// the whole set: New registers each one and disables any this deployment
	// declared at an earlier boot and no longer does. A removed application
	// is disabled, not deleted: its tokens stop at once, and it keeps its
	// roles for when it is declared again. Nil leaves the stored applications
	// alone. Applications registered through an operation
	// (Client.UpsertRemoteApplication, the bootstrap manifest) or declared by
	// a deployment sharing the account store are never touched.
	RemoteApplications []RemoteApplicationConfig `yaml:"remote_applications"`
	// Provisioning are the SCIM 2.0 service providers the accounts are
	// pushed to. None pushes nothing.
	Provisioning []ProvisioningTarget `yaml:"provisioning"`

	// HTTP configures the HTTP surface. Nil keeps the Client headless:
	// operations and Verifier only.
	HTTP *HTTPConfig `yaml:"http"`

	// tuning is AuthKit's fixed limits, which only tests change (Tune).
	tuning Tuning
}

// Tenancy is Config.Tenancy.
type Tenancy uint8

const (
	// TenancySingle is one tenant, which Migrate creates in a fresh
	// database or adopts when it holds exactly one. A database with more
	// refuses to start; CreateTenant is iam.ErrSingleTenant.
	TenancySingle Tenancy = iota
	// TenancyMulti is any number of tenants, made with CreateTenant and
	// selected with ForTenant or Deps.RequestTenant.
	TenancyMulti
)

func (t Tenancy) String() string {
	switch t {
	case TenancySingle:
		return "single"
	case TenancyMulti:
		return "multi"
	}
	return fmt.Sprintf("Tenancy(%d)", uint8(t))
}

// AgreementConfig is one document users accept (Config.Agreements).
type AgreementConfig struct {
	// Key names it: lowercase letters, digits, '-' and '_', such as "terms".
	Key string `yaml:"key"`
	// Version is its current version, such as its date. Accepting an
	// earlier version does not accept this one.
	Version string `yaml:"version"`
	// URL is where it is read: an absolute http(s) URL.
	URL string `yaml:"url"`
	// SignUp makes every self-registration accept it at its current version:
	// a sign-up by password, code or identity provider without it is refused
	// with agreement_required, and a passwordless code stays valid for the
	// retry that accepts it. A Solana or device-key sign-up carries none, so
	// it creates no account while one is set. A user who accepted an
	// earlier version accepts this one when they next sign in (AuthResult
	// agreements_due). Host operations (CreateUser, imports, SCIM) record
	// none.
	SignUp bool `yaml:"sign_up"`
	// GroupClients makes a user accept it, at its current version, before
	// approving any group's OAuth client.
	GroupClients bool `yaml:"group_clients"`
}

// RemoteApplicationConfig declares one remote application, keyed by Issuer:
// an issuer whose access tokens this deployment accepts for the group that
// declares it (root for Config.RemoteApplications), within Role. Only the
// system changes it (trust root manual).
type RemoteApplicationConfig struct {
	// Issuer is the iss of the tokens it signs: an absolute http(s) URL.
	Issuer string `yaml:"issuer"`
	// PublicKeys are its keys, trusted statically. Empty fetches them from
	// the issuer's JWKS, at the issuer plus iam.JWKSPath.
	PublicKeys []iam.RemoteApplicationKey `yaml:"public_keys"`
	// Role is the role it holds in its group: the ceiling of what its tokens
	// may do there. Zero holds none.
	Role iam.Role `yaml:"role"`
	// RoleMap maps a role name its tokens carry (RFC 9068 §2.2.3.1 roles) to
	// a role of its group, for an issuer that cannot mint the group's
	// permissions.
	RoleMap map[string]iam.Role `yaml:"role_map"`
}

// DatabaseConfig names the PostgreSQL schemas of AuthKit's tables. New
// creates them, and creates or upgrades the tables, before anything else
// touches the database, unless SkipMigrations requires existing schemas.
// The pool in Deps.Postgres owns and uses them.
type DatabaseConfig struct {
	// SkipMigrations makes New validate existing schemas without applying DDL.
	// Prepare them explicitly with authkit.Migrate before starting the app.
	SkipMigrations bool `yaml:"skip_migrations"`
	// Schema is the PostgreSQL schema AuthKit's tables live in. Empty
	// defaults to "profiles". Deployments that must not share accounts on one
	// database use different schemas; deployments that share accounts use the
	// same one (see AccountIssuers). It must match
	// ^[a-z_][a-z0-9_]*$ (max 63 bytes).
	Schema string `yaml:"schema"`
	// RiverSchema holds the River tables AuthKit's jobs (account lifecycle,
	// events, cleanup) run in; empty is Schema. Start runs AuthKit's own
	// River client there; set it to a host fleet's schema to pass that fleet
	// to Start (WithRiverClient), which must use it.
	RiverSchema string `yaml:"river_schema"`
	// RiverConns sizes the pool of the River client Start builds when the host passes no fleet; 0 keeps 5.
	RiverConns int `yaml:"river_conns"`
}

// HTTPConfig configures the HTTP surface: one handler serving the JSON API,
// browser OIDC and JWKS, every route beneath the Issuer's path:
//
//	{path}/auth/v1/...               JSON API, issuer at the root
//	{path}/v1/...                    JSON API, issuer with a path
//	{path}/oidc/{provider}/...       browser OIDC
//	{path}/.well-known/jwks.json     JWKS
//
// Serve the paths unchanged: no StripPrefix in front. A proxy in front keeps
// the issuer's URL: DPoP proofs and assertions name it.
//
// What sits in front of AuthKit must be declared, exactly once: the proxies
// (TrustedProxies, with CloudflareProxies where Cloudflare fronts the
// origin), DirectPeerIP, or Deps.ClientIP. Undeclared, every client shares
// one proxy's per-IP rate-limit bucket; New refuses none and several.
type HTTPConfig struct {
	// Groups selects the mounted route groups, and with them the opt-in
	// features: passwordless sign-in (RoutePasswordless), device keys
	// (RouteDeviceKeys), personal access tokens (RoutePersonalAccessTokens)
	// and invitations (RouteInvitations). Nil is iam.DefaultRouteGroups();
	// non-nil mounts exactly the named groups. Deps.Wrap replaces a route's
	// handler for a host serving it itself.
	Groups []iam.RouteGroup `yaml:"groups"`
	// TrustedProxies are the CIDRs of reverse proxies whose X-Forwarded-For
	// is honoured.
	TrustedProxies []string `yaml:"trusted_proxies"`
	// CloudflareProxies are Cloudflare's egress ranges: X-Forwarded-For plus
	// CF-Connecting-IP. Set them only where Cloudflare fronts an origin locked
	// down to it.
	CloudflareProxies []string `yaml:"cloudflare_proxies"`
	// DirectPeerIP asserts nothing sits in front: RemoteAddr is the client.
	DirectPeerIP bool `yaml:"direct_peer_ip"`
}

// RateLimit allows at most Limit requests per Window in one bucket, with an
// optional Cooldown between accepted requests.
type RateLimit = ratelimit.Limit
