// Package config is the one definition of AuthKit's host configuration:
// Config (plain data), Deps (everything that reaches outside the process)
// and the Roles builder. The root package re-exports each type
// under the same name (authkit.Config is config.Config), so these field docs
// are the ones hosts read. Normalize applies every default and rule once.
package config

import (
	"fmt"
	"time"

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

	// DefaultTenantID is the tenant ordinary account operations and HTTP
	// authentication act in when no trusted tenant view or resolver selects
	// one. Single-tenant it is optional and must name the sole tenant (a
	// fresh database's is created under it); zero is the sole tenant.
	// Multi-tenant, zero refuses such operations (iam.ErrTenantRequired).
	DefaultTenantID iam.TenantID `yaml:"default_tenant_id"`

	// Database names the PostgreSQL schemas AuthKit's and River's tables live
	// in. New creates or upgrades them.
	Database DatabaseConfig `yaml:"database"`

	// Notifications enables the optional durable account inbox.
	Notifications *NotificationsConfig `yaml:"notifications"`

	// Token is the JWT issuing/verification contract and session limits.
	Token TokenConfig `yaml:"token"`
	// SignIn limits how sign-ins spread across accounts and devices: one
	// person signing in and out of many accounts, and one account shared by
	// many people. The zero value is on, with generous limits.
	SignIn SignInConfig `yaml:"sign_in"`
	// Keys controls signing-key resolution when Deps.KeySource is nil.
	Keys KeysConfig `yaml:"keys"`
	// Registration controls verification policy and public self-registration.
	Registration RegistrationConfig `yaml:"registration"`
	// Agreements are the documents users accept, such as terms and a privacy
	// policy, each at its current version. Registration.Agreements names the
	// ones every sign-up accepts; the host reads acceptances with
	// Client.UserAgreements and gates its own features on them. Published by
	// GET {api}/capabilities.
	Agreements []AgreementConfig `yaml:"agreements"`
	// SMS is the text-message policy: where messages may go.
	SMS SMSConfig `yaml:"sms"`
	// Password is the rule every password write enforces. The zero value is
	// the default policy: 8..128 characters, no composition rules, common
	// passwords rejected. Published by GET {api}/capabilities.
	Password PasswordPolicy `yaml:"password"`
	// Username is the username rule: length, and whether and how often users
	// may rename themselves. Published by GET {api}/capabilities.
	Username UsernameConfig `yaml:"username"`
	// Tenants is the tenant name policy.
	Tenants TenantsConfig `yaml:"tenants"`
	// TwoFactor configures MFA.
	TwoFactor TwoFactorConfig `yaml:"two_factor"`
	// DeviceKeys enables the refreshless native-client device-key surface.
	// Off by default: enrollment is an email-code login, so hosts opt in
	// explicitly before RouteDeviceKeys is mounted or the engine issues
	// enrollment or login challenges.
	DeviceKeys DeviceKeysConfig `yaml:"device_keys"`
	// APIKeys configures opaque permission-group-owned machine credentials.
	APIKeys APIKeysConfig `yaml:"api_keys"`
	// PersonalAccessTokens enables optional user-owned, noninteractive tokens.
	// Disabled by default; organization API keys are configured separately.
	PersonalAccessTokens PersonalAccessTokensConfig `yaml:"personal_access_tokens"`
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
	// Invitations turns invitations off. The zero value leaves them on.
	Invitations InvitationsConfig `yaml:"invitations"`
	// Provisioning pushes the accounts to SCIM 2.0 service providers. The
	// zero value pushes nothing.
	Provisioning ProvisioningConfig `yaml:"provisioning"`
	// Roles is the permission model: personas, their permissions and roles
	// (NewRoles). Nil is root-only.
	Roles *Roles `yaml:"-"`
	// RemoteApplications declares the remote applications root controls, as
	// the whole set: New registers each one and disables any this deployment
	// declared at an earlier boot and no longer does. A removed application
	// is disabled, not deleted: its tokens stop at once, and it keeps its
	// roles for when it is declared again. Nil leaves the stored applications
	// alone. Applications registered through an operation
	// (Client.UpsertRemoteApplication, the bootstrap manifest) or declared by
	// a deployment sharing the account store are never touched.
	RemoteApplications []RemoteApplicationConfig `yaml:"remote_applications"`
	// Languages declares the supported languages: the HTTP surface negotiates
	// the request's among them, and messages fall back to Default.
	Languages LanguageConfig `yaml:"languages"`

	// SolanaNetwork turns on Sign In With Solana for one chain; the zero value
	// leaves it off. Solana Name Service resolution is built in.
	SolanaNetwork iam.SolanaNetwork `yaml:"solana_network"`

	// SenderHealthInterval is how often Start re-runs the senders'
	// CheckHealth; 0 defaults to five minutes.
	SenderHealthInterval time.Duration `yaml:"sender_health_interval"`
	// SenderHealthRecheck is how soon a sender is checked again after its
	// first failed check, or after a failed send, instead of waiting
	// SenderHealthInterval; once two checks in a row have failed, checks
	// return to SenderHealthInterval. 0 defaults to 30 seconds, and it is never
	// longer than SenderHealthInterval.
	SenderHealthRecheck time.Duration `yaml:"sender_health_recheck"`

	// SessionEventRetention is how long session-event history rows
	// (sign-ins and revocations, with IP and user agent: personal data) are
	// kept. 0 defaults to 365 days; a negative value keeps them forever.
	SessionEventRetention time.Duration `yaml:"session_event_retention"`

	// EventRetention keeps committed account/group events independently of
	// readers. Zero defaults to 90 days; it must be positive after defaulting.
	EventRetention time.Duration `yaml:"event_retention"`

	// CleanupInterval is how often expired auth state is cleaned up; 0
	// defaults to one hour.
	CleanupInterval time.Duration `yaml:"cleanup_interval"`

	// HTTP configures the HTTP surface. Nil keeps the Client headless:
	// operations and Verifier only.
	HTTP *HTTPConfig `yaml:"http"`
}

// TokenConfig is the JWT issuing/verification contract plus session limits.
type TokenConfig struct {
	// AccessTokenDuration is the access-token lifetime; 0 defaults to 15
	// minutes, the longest a revoked session's token passes stateless checks.
	AccessTokenDuration time.Duration `yaml:"access_token_duration"`
	// RefreshTokenDuration is the refresh-session lifetime from sign-in: 0
	// defaults to 30 days; a negative value means sessions do not expire by age.
	RefreshTokenDuration time.Duration `yaml:"refresh_token_duration"`
	// SessionMaxPerUser caps concurrent refresh sessions per user, evicting
	// the oldest. 0 defaults to 3; a negative value means unlimited.
	SessionMaxPerUser int `yaml:"session_max_per_user"`
	// RefreshRotationGrace is how long a just-rotated refresh token keeps being
	// answered with the successor it rotated into instead of being read as
	// reuse and ending the session. It covers two holders of one token
	// refreshing at once (a shared credential file, a retried request). 0
	// defaults to 30s; a negative value makes rotation strictly single-use.
	RefreshRotationGrace time.Duration `yaml:"refresh_rotation_grace"`
	// EntitlementAllowlist selects the provider-granted entitlement names
	// (Deps.Entitlements) that access tokens carry. Empty skips the mint-time
	// lookup and omits the claim.
	EntitlementAllowlist []string `yaml:"entitlement_allowlist"`
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
	// AllowPrivateNetworkJWKS permits http and private or loopback JWKS URLs
	// for remote applications and the issuers verifiers trust, and turns off
	// the SSRF guard on remote applications' JWKS URLs. Local development only.
	AllowPrivateNetworkJWKS bool `yaml:"allow_private_network_jwks"`
}

// SignInConfig limits distinct accounts and devices over a rolling 24 hours.
// A device is a browser's device cookie (set by the HTTP surface); a client
// without one is known by its address (per /64 for IPv6). The counts live in
// the short-lived store every replica shares, never in a history.
type SignInConfig struct {
	// AccountsPerDevice caps the distinct accounts that sign in, or are
	// registered, from one device in 24 hours. Signing back into one of them
	// is always allowed; the next other account is refused with 429
	// too_many_accounts. 0 defaults to 5; negative turns it off.
	AccountsPerDevice int `yaml:"accounts_per_device"`
	// AccountsPerAddress is AccountsPerDevice for a client without a device
	// cookie, counted per client address, which many people may share. 0
	// defaults to 20; negative turns it off.
	AccountsPerAddress int `yaml:"accounts_per_address"`
	// NewDevicesPerAccount caps the new devices that sign in to one account
	// in 24 hours. A device that signed in to it within 30 days is not new.
	// Past the cap, a new device enters a code sent to the account's proven
	// email or phone (status device_verification_required); an account with
	// neither is refused with 429 too_many_devices. A sign-in that proved the
	// owner's email or phone, or a second factor, needs no code. 0 defaults
	// to 10; negative turns it off.
	NewDevicesPerAccount int `yaml:"new_devices_per_account"`
	// DPoP is how this deployment issues tokens to its own users (RFC 9449):
	// their sign-in sessions and its authorization server's user grants.
	// Optional, the default, lets each client choose at sign-in: a DPoP key
	// binds the session for good, none gives bearer tokens. Required refuses
	// a sign-in, a user grant or a refresh without a proof. It never changes
	// how tokens are validated: a bound token needs its proof, an unbound one
	// is a bearer token, whoever issued it. API keys, client credentials and
	// service tokens are never covered.
	DPoP DPoPMode `yaml:"dpop"`
}

// DPoPMode is SignInConfig.DPoP.
type DPoPMode string

const (
	// DPoPOptional lets each client choose at sign-in.
	DPoPOptional DPoPMode = "optional"
	// DPoPRequired refuses a sign-in without a DPoP key.
	DPoPRequired DPoPMode = "required"
)

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

// KeysConfig controls signing-key resolution when Deps.KeySource is nil.
type KeysConfig struct {
	// Path is the directory holding keys.json (hot-reloaded on rotation) and
	// totp.key. Empty is /vault/auth, or for a loopback Token.Issuer
	// $XDG_STATE_HOME/authkit/development/<issuer SHA-256> (falling back to
	// ~/.local/state). For a loopback issuer AuthKit generates whichever of
	// the two is missing and reuses it across restarts, marked as development
	// keys, which no other issuer loads. Any other issuer never generates.
	Path string `yaml:"path"`
	// VerifyOnly builds AuthKit with no signer: minting returns
	// iam.ErrSigningNotConfigured, verification and permission reads work, and
	// JWKS serves an empty set. Key resolution is skipped.
	VerifyOnly bool `yaml:"verify_only"`
}

// RegistrationConfig controls public self-registration and whether password
// sign-in requires contact proof for existing accounts.
type RegistrationConfig struct {
	// Verification is "none" (the default), "optional" or "required". Every
	// policy stores the address unverified until proven; "optional" also
	// sends a code at registration. Unproven accounts cannot add sign-in
	// methods.
	Verification iam.RegistrationVerificationPolicy `yaml:"verification"`
	// UnprovenPasswordSignIn lets existing accounts sign in with a password
	// without proving their email or phone when Verification is "required".
	// It defaults to false. New sign-ups still require proof; accounts that
	// sign in this way stay unproven and cannot add sign-in methods.
	UnprovenPasswordSignIn bool `yaml:"unproven_password_sign_in"`
	// NativeUserMode controls public self-registration: "open" (the default),
	// "invite_only" or "closed". The host operations (CreateUser, bootstrap,
	// import) work in every mode.
	NativeUserMode iam.RegistrationMode `yaml:"native_user_mode"`
	// PasswordlessLogin enables contact-based passwordless sessions.
	PasswordlessLogin bool `yaml:"passwordless_login"`
	// PasswordlessAutoRegistration lets a verified unknown contact create a
	// passwordless account during passwordless confirmation.
	PasswordlessAutoRegistration bool `yaml:"passwordless_auto_registration"`
	// AllowMissingSenders lets flows that deliver codes and links proceed with
	// no email or SMS sender: nothing is delivered and the engine hands the
	// code back to its caller (dev rigs read it there). By default a missing
	// sender is an error.
	AllowMissingSenders bool `yaml:"allow_missing_senders"`
	// VerificationSendTimeout bounds each in-line email or SMS send so an
	// unreachable provider cannot hang the request. 0 defaults to 15s.
	VerificationSendTimeout time.Duration `yaml:"verification_send_timeout"`
	// Agreements are the keys of Config.Agreements every self-registration
	// accepts at their current version: a sign-up by password, code or
	// identity provider without them is refused with agreement_required, and
	// a passwordless code stays valid for the retry that accepts them. A
	// Solana or device-key sign-up carries none, so it creates no account
	// while this is set. Host operations (CreateUser, imports, SCIM) record
	// none.
	Agreements []string `yaml:"agreements"`
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
	// Reaccept asks a user who accepted an earlier version to accept this one
	// when they next sign in (AuthResult agreements_due).
	Reaccept bool `yaml:"reaccept"`
}

// SMSConfig is the text-message policy. Every message also passes the send
// limits of HTTPConfig.RateLimits' sms_* buckets (per number, account,
// client address and destination country) when the HTTP surface is mounted.
type SMSConfig struct {
	// AllowedCountries are the ISO 3166-1 alpha-2 regions text messages may
	// go to, such as "US" and "CA"; a number elsewhere is refused with
	// phone_country_not_allowed before anything is sent. Empty allows every
	// region.
	AllowedCountries []string `yaml:"allowed_countries"`
}

// PasswordPolicy is the password rule, NIST SP 800-63B-style by default.
// Lengths count Unicode code points; 0 defaults to 8 and 128, and MaxLength is
// at most 1024. Composition rules are opt-in: uppercase, lowercase and digit
// use Unicode categories, and a symbol is any rune that is neither a letter
// nor a digit.
type PasswordPolicy struct {
	MinLength        int  `yaml:"min_length"`
	MaxLength        int  `yaml:"max_length"`
	RequireUppercase bool `yaml:"require_uppercase"`
	RequireLowercase bool `yaml:"require_lowercase"`
	RequireDigit     bool `yaml:"require_digit"`
	RequireSymbol    bool `yaml:"require_symbol"`
	// AllowCommon admits passwords on AuthKit's embedded common-password
	// blocklist, which the zero value refuses. The match ignores case, and
	// punctuation and spaces while MinLength characters remain: "Change.Me"
	// is "changeme".
	AllowCommon bool `yaml:"allow_common"`
}

// UsernameConfig is the username rule. The characters are fixed: a letter,
// then letters, digits and underscores.
type UsernameConfig struct {
	// RandomNames is the app's pool for generated usernames. A generated name
	// is one literal entry plus exactly three random decimal digits. Nil uses
	// a neutral "user" base fitted to the length policy; an explicit empty pool
	// is invalid. Custom entries must fit the policy with the suffix intact.
	RandomNames []string `yaml:"random_names"`

	// MinLength and MaxLength bound the length; 0 defaults to 4 and 30, and
	// MaxLength is at most 64.
	MinLength int `yaml:"min_length"`
	MaxLength int `yaml:"max_length"`
	// Renames lets users change their own username; off by default.
	Renames bool `yaml:"renames"`
	// RenameInterval is the least time between two renames of one account. 0
	// defaults to 72 hours; a negative value means no wait.
	RenameInterval time.Duration `yaml:"rename_interval"`
	// FormerNames is what happens to a username its owner renamed away from:
	// it forwards to the owner, and nobody else may claim it. The default is
	// finite, 90 days.
	FormerNames NameRetention `yaml:"former_names"`
	// DeletedNames is what happens to a deleted account's username when the
	// account is purged at the end of its recovery window: nobody may claim
	// it, and it resolves to no one. The default is forever. Names the account
	// had renamed away from keep their own expiry.
	DeletedNames NameRetention `yaml:"deleted_names"`
}

// TenantsConfig is the tenant name policy.
type TenantsConfig struct {
	// FormerNames is what happens to a name a tenant was renamed away from:
	// it forwards to the tenant, and no other tenant may claim it. The default
	// is finite, 90 days.
	FormerNames NameRetention `yaml:"former_names"`
}

// NameRetention is how long a name its owner let go of stays reserved.
type NameRetention struct {
	// Mode is NameRetentionFinite, NameRetentionForever or
	// NameRetentionImmediate. Empty takes the field's default, or finite when
	// Duration is set.
	Mode NameRetentionMode `yaml:"mode"`
	// Duration is how long a finite reservation lasts; 0 defaults to 90 days.
	Duration time.Duration `yaml:"duration"`
}

// NameRetentionMode says how long a name stays reserved.
type NameRetentionMode string

const (
	// NameRetentionFinite reserves it for NameRetention.Duration.
	NameRetentionFinite NameRetentionMode = "finite"
	// NameRetentionForever reserves it for good.
	NameRetentionForever NameRetentionMode = "forever"
	// NameRetentionImmediate frees it at once.
	NameRetentionImmediate NameRetentionMode = "immediate"
)

// TwoFactorConfig configures MFA.
type TwoFactorConfig struct {
	// Mode is the account-wide policy: iam.TwoFactorDisabled,
	// iam.TwoFactorOptional (the default) or iam.TwoFactorRequired (every user
	// enrolls before normal session use). Persona.RequireMFA enforces MFA per
	// permission; the root owner always needs it.
	Mode iam.TwoFactorMode `yaml:"mode"`
	// Methods are the enabled second-factor channels; empty enables email,
	// SMS and TOTP. A method whose dependency is missing (SMS with no sender)
	// is unavailable regardless. Unless Mode is disabled, New refuses a
	// deployment with none available: the root owner always needs MFA.
	Methods []iam.TwoFactorMethod `yaml:"methods"`
	// TOTPSecretKey encrypts stored authenticator-app secrets: 16, 24 or 32 raw
	// bytes. It overrides <Keys.Path>/totp.key; with neither, TOTP enrollment
	// is unavailable.
	TOTPSecretKey []byte `yaml:"totp_secret_key"`
}

// DeviceKeysConfig controls the native-client device-key surface.
type DeviceKeysConfig struct {
	// Enabled mounts RouteDeviceKeys and lets the engine run enrollment and
	// login ceremonies.
	Enabled bool `yaml:"enabled"`
}

// APIKeysConfig configures opaque permission-group-owned machine credentials.
type APIKeysConfig struct {
	// Prefix brands generated keys (one per deployment): lowercase
	// alphanumeric, 1-16 characters. Empty gives the bare "st_" marker.
	Prefix string `yaml:"prefix"`
	// MaxTTL caps how far ahead a key may expire; a later or absent expiry is
	// capped at creation. 0 means no cap.
	MaxTTL time.Duration `yaml:"max_ttl"`
}

type PersonalAccessTokensConfig struct {
	Enabled    bool          `yaml:"enabled"`
	DefaultTTL time.Duration `yaml:"default_ttl"`
	MaxTTL     time.Duration `yaml:"max_ttl"`
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
	// Disabled keeps it registered and refuses its tokens.
	Disabled bool `yaml:"disabled"`
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
	// same one (see TokenConfig.AccountIssuers). It must match
	// ^[a-z_][a-z0-9_]*$ (max 63 bytes).
	Schema string `yaml:"schema"`
	// RiverSchema holds the River tables AuthKit's jobs (account lifecycle,
	// events, cleanup) run in; empty defaults to "public". Start runs AuthKit's
	// own River client there, and a host fleet passed to Start with
	// WithRiverClient must use the same schema.
	RiverSchema string `yaml:"river_schema"`
}

// InvitationsConfig controls invitations: invite links and emailed
// invitations into a group, and emailed invitations to register.
type InvitationsConfig struct {
	// Disabled turns them off: no invitation is issued or honoured. The
	// invitation routes are not mounted, GET {api}/capabilities reports
	// invitations.enabled false, and CreateInvitation, redeeming a code and
	// registering with one return iam.ErrInvitationsDisabled. Listing and
	// revoking earlier invitations still work. Registration.NativeUserMode
	// "invite_only" cannot be combined with it.
	Disabled bool `yaml:"disabled"`
}

// LanguageConfig declares the supported languages as two-letter codes. The
// zero value is English only.
type LanguageConfig struct {
	// Supported are the languages requests may select; empty accepts any.
	Supported []string `yaml:"supported"`
	// Default is the language when neither the account nor the request
	// chooses one; empty defaults to "en".
	Default string `yaml:"default"`
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
	// Groups selects the mounted route groups. Nil mounts the default API
	// surface plus browser OIDC; non-nil mounts exactly the named groups.
	Groups []iam.RouteGroup `yaml:"groups"`
	// Exclude drops routes the host serves itself, named as iam.Route.Pattern
	// names them ("GET /.well-known/jwks.json"). An entry matching no route is
	// an error.
	Exclude []string `yaml:"exclude"`
	// RefreshCookie delivers the rotating refresh token as an HttpOnly cookie
	// (iam.RefreshCookieName) instead of a JSON field. Browser mounts only:
	// the SPA and this handler must share an origin.
	RefreshCookie bool `yaml:"refresh_cookie"`
	// RefreshCookieName overrides the base label. AuthKit appends a stable
	// issuer/tenant qualifier so tenant sessions never share one cookie slot.
	// Do not include __Host-: HTTPS adds that prefix automatically. Existing
	// unqualified cookies migrate after their owner is verified.
	RefreshCookieName string `yaml:"refresh_cookie_name"`

	// RateLimits overlays bucket limits onto authkit.DefaultRateLimits;
	// unknown buckets are refused. Limits are in memory and per process unless
	// Deps.Redis shares them.
	RateLimits map[string]RateLimit `yaml:"rate_limits"`

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
