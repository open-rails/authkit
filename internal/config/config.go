// Package config is the one definition of AuthKit's host configuration:
// Config (plain data), Deps (everything that reaches outside the process)
// and the Roles builder. The root package re-exports each type
// under the same name (authkit.Config is config.Config), so these field docs
// are the ones hosts read. Normalize applies every default and rule once.
package config

import (
	"time"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/ratelimit"
)

// Config is the host configuration: plain data and policy. Everything that
// reaches outside the process (the pool, senders, keys, providers, hooks) is
// in Deps. authkit.New normalizes it once.
type Config struct {
	// Database names the PostgreSQL schemas AuthKit's and River's tables live
	// in. New creates or upgrades them.
	Database DatabaseConfig `yaml:"database"`

	// Token is the JWT issuing/verification contract and session limits.
	Token TokenConfig `yaml:"token"`
	// SignIn limits how sign-ins spread across accounts and devices: one
	// person signing in and out of many accounts, and one account shared by
	// many people. The zero value is on, with generous limits.
	SignIn SignInConfig `yaml:"sign_in"`
	// Keys controls signing-key resolution when Deps.KeySource is nil.
	Keys KeysConfig `yaml:"keys"`
	// Frontend describes host-owned frontend routes used for absolute URLs.
	Frontend FrontendConfig `yaml:"frontend"`
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
	// TwoFactor configures MFA.
	TwoFactor TwoFactorConfig `yaml:"two_factor"`
	// Passkeys configures WebAuthn/FIDO2 passkey ceremonies.
	Passkeys PasskeyConfig `yaml:"passkeys"`
	// DeviceKeys enables the refreshless native-client device-key surface.
	// Off by default: enrollment is an email-code login, so hosts opt in
	// explicitly before RouteDeviceKeys is mounted or the engine issues
	// enrollment or login challenges.
	DeviceKeys DeviceKeysConfig `yaml:"device_keys"`
	// APIKeys configures opaque permission-group-owned machine credentials.
	APIKeys APIKeysConfig `yaml:"api_keys"`
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

	// SessionEventRetention is how long session-event history rows
	// (sign-ins and revocations, with IP and user agent: personal data) are
	// kept. 0 defaults to 365 days; a negative value keeps them forever.
	SessionEventRetention time.Duration `yaml:"session_event_retention"`

	// CleanupInterval is how often expired auth state is cleaned up; 0
	// defaults to one hour.
	CleanupInterval time.Duration `yaml:"cleanup_interval"`

	// HTTP configures the HTTP surface. Nil keeps the Client headless:
	// operations and Verifier only.
	HTTP *HTTPConfig `yaml:"http"`
}

// TokenConfig is the JWT issuing/verification contract plus session limits.
type TokenConfig struct {
	// Issuer is this deployment's JWT issuer (required), for example
	// "https://myapp.com". Its path, if any, is where the HTTP surface lives.
	Issuer string `yaml:"issuer"`
	// IssuedAudiences are the audiences every issued token carries (at least
	// one).
	IssuedAudiences []string `yaml:"issued_audiences"`
	// ExpectedAudiences are the audiences verification accepts; empty
	// defaults to IssuedAudiences.
	ExpectedAudiences []string `yaml:"expected_audiences"`
	// AccessTokenDuration is the access-token lifetime; 0 defaults to 15
	// minutes, the longest a revoked session's token passes stateless checks.
	AccessTokenDuration time.Duration `yaml:"access_token_duration"`
	// RefreshTokenDuration is the refresh-session lifetime; 0 or less means
	// sessions do not expire by age.
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

// KeysConfig controls signing-key resolution when Deps.KeySource is nil.
// AuthKit reads no environment variables: binaries read their environment
// once and set these fields.
type KeysConfig struct {
	// Path is the directory holding keys.json (hot-reloaded on rotation) and
	// totp.key. Empty defaults to /vault/auth. With no keys.json, New fails
	// unless AllowEphemeralDevKeys or VerifyOnly is set.
	Path string `yaml:"path"`
	// AllowEphemeralDevKeys generates an RSA signing key when Path holds no
	// keys.json, and a TOTP key when it holds no totp.key: in memory, or
	// written to Path when it is set so restarts reuse them. Development only.
	AllowEphemeralDevKeys bool `yaml:"allow_ephemeral_dev_keys"`
	// VerifyOnly builds AuthKit with no signer: minting returns
	// iam.ErrSigningNotConfigured, verification and permission reads work, and
	// JWKS serves an empty set. Key resolution is skipped.
	VerifyOnly bool `yaml:"verify_only"`
}

// FrontendConfig describes host-owned frontend routes.
type FrontendConfig struct {
	// BaseURL builds absolute links (password reset, verification, invites).
	// Empty defaults to Token.Issuer when that is a URL.
	BaseURL string `yaml:"base_url"`
	// OIDCReturnPath is the SPA route AuthKit redirects to after it finishes a
	// browser sign-in with an identity provider (not the provider callback,
	// which AuthKit owns). Empty defaults to "/login/callback".
	OIDCReturnPath string `yaml:"oidc_return_path"`
	// VerifyPath receives scanner-safe verification link landings. Empty
	// defaults to "/verify".
	VerifyPath string `yaml:"verify_path"`
	// PasswordResetPath receives scanner-safe password reset link landings.
	// Empty defaults to "/reset".
	PasswordResetPath string `yaml:"password_reset_path"`
	// PasswordlessPath receives passwordless sign-in links. Empty defaults to
	// "/passwordless".
	PasswordlessPath string `yaml:"passwordless_path"`
	// InvitePath receives group invitation links (?code=…); the SPA posts the
	// code to the redeem route. Empty defaults to "/accept-invite".
	InvitePath string `yaml:"invite_path"`
	// AuthorizePath receives an OAuth client's sign-in request
	// (?authorization=…) when the authorization server is on: the SPA signs
	// the user in, then approves the request through the API. Empty defaults
	// to "/authorize".
	AuthorizePath string `yaml:"authorize_path"`
}

// RegistrationConfig controls verification policy and public self-registration.
type RegistrationConfig struct {
	// Verification is "none" (the default), "optional" or "required". Every
	// policy stores the address unverified until proven; "optional" also
	// sends a code at registration. Unproven accounts cannot add sign-in
	// methods.
	Verification iam.RegistrationVerificationPolicy `yaml:"verification"`
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
	// blocklist, which the zero value refuses.
	AllowCommon bool `yaml:"allow_common"`
}

// UsernameConfig is the username rule. The characters are fixed: a letter,
// then letters, digits and underscores.
type UsernameConfig struct {
	// MinLength and MaxLength bound the length; 0 defaults to 4 and 30, and
	// MaxLength is at most 64.
	MinLength int `yaml:"min_length"`
	MaxLength int `yaml:"max_length"`
	// Renames lets users change their own username; off by default.
	Renames bool `yaml:"renames"`
	// RenameInterval is the least time between two renames of one account. 0
	// defaults to 72 hours; a negative value means no wait.
	RenameInterval time.Duration `yaml:"rename_interval"`
	// FormerNames is what happens to a username its owner renamed away from.
	FormerNames FormerNamesConfig `yaml:"former_names"`
}

// FormerNamesConfig keeps a renamed-away username reserved for its owner, and
// resolving to them, for a while.
type FormerNamesConfig struct {
	// Mode is FormerNamesFinite (the default), FormerNamesForever or
	// FormerNamesImmediate.
	Mode FormerNamesMode `yaml:"mode"`
	// Duration is how long a finite reservation lasts; 0 defaults to 90 days.
	Duration time.Duration `yaml:"duration"`
}

// FormerNamesMode says how long a former username stays reserved.
type FormerNamesMode string

const (
	// FormerNamesFinite reserves it for FormerNamesConfig.Duration.
	FormerNamesFinite FormerNamesMode = "finite"
	// FormerNamesForever reserves it for good.
	FormerNamesForever FormerNamesMode = "forever"
	// FormerNamesImmediate frees it at once.
	FormerNamesImmediate FormerNamesMode = "immediate"
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

// PasskeyConfig configures the WebAuthn relying party. Empty fields derive
// from Frontend.BaseURL.
type PasskeyConfig struct {
	RPID             string   `yaml:"rp_id"`
	RPDisplayName    string   `yaml:"rp_display_name"`
	Origins          []string `yaml:"origins"`
	UserVerification string   `yaml:"user_verification"`
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

// RemoteApplicationConfig declares one remote application, keyed by Issuer:
// an issuer whose access tokens this deployment accepts for the group that
// declares it (root for Config.RemoteApplications), within Role. Only the
// system changes it (trust root manual).
type RemoteApplicationConfig struct {
	// Issuer is the iss of the tokens it signs: an absolute http(s) URL.
	Issuer string `yaml:"issuer"`
	// JWKSURI is where its keys are fetched; PublicKeys is a static key list
	// instead. Set exactly one.
	JWKSURI    string                     `yaml:"jwks_uri"`
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
// touches the database: the pool in Deps.Postgres owns and uses them.
type DatabaseConfig struct {
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
// browser OIDC and JWKS, every route beneath BasePath:
//
//	{BasePath}{APIPath}/v1/...           JSON API
//	{BasePath}/oidc/{provider}/...       browser OIDC
//	{BasePath}/.well-known/jwks.json     JWKS
//
// Exactly what sits in front of AuthKit must be declared (TrustedProxies,
// CloudflareProxies, DirectPeerIP or Deps.ClientIP), or every client shares
// one proxy's per-IP rate-limit bucket.
type HTTPConfig struct {
	// Groups selects the mounted route groups. Nil mounts the default API
	// surface plus browser OIDC; non-nil mounts exactly the named groups.
	Groups []iam.RouteGroup `yaml:"groups"`
	// BasePath roots the whole surface. Empty derives it from Token.Issuer's
	// path ("https://example.com/auth" gives "/auth"); when the issuer is a
	// URL a set value must equal that path, because verifiers find JWKS at
	// the issuer plus iam.JWKSPath. Serve the paths unchanged: no StripPrefix
	// in front.
	BasePath string `yaml:"base_path"`
	// APIPath is the JSON API's prefix beneath BasePath; AuthKit adds the
	// version segment, /v1, after it. Empty means "/api"; "/" puts /v1 right
	// beneath BasePath.
	APIPath string `yaml:"api_path"`
	// PublicURL is where clients reach BasePath when a proxy in front changes
	// the origin or the path, such as "https://shop.example.com/sso". DPoP
	// proofs sent to the token endpoint, and jwt-bearer assertions' aud, must
	// name PublicURL plus its path beneath BasePath. Empty defaults to Token.Issuer's origin plus
	// BasePath.
	PublicURL string `yaml:"public_url"`
	// Exclude drops routes the host serves itself, named as iam.Route.Pattern
	// names them ("GET /.well-known/jwks.json"). An entry matching no route is
	// an error.
	Exclude []string `yaml:"exclude"`
	// RefreshCookie delivers the rotating refresh token as an HttpOnly cookie
	// (iam.RefreshCookieName) instead of a JSON field. Browser mounts only:
	// the SPA and this handler must share an origin.
	RefreshCookie bool `yaml:"refresh_cookie"`

	// RateLimits overlays bucket limits onto authkit.DefaultRateLimits;
	// unknown buckets are refused. Limits are in memory and per process unless
	// Deps.Redis shares them.
	RateLimits map[string]RateLimit `yaml:"rate_limits"`
	// RedisKeyPrefix namespaces the rate-limit keys in Deps.Redis so
	// deployments can share one Redis. Empty derives "authkit:<schema>:".
	RedisKeyPrefix string `yaml:"redis_key_prefix"`

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
