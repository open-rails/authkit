package authkit

import (
	"net/http"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/open-rails/authkit/authprovider"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/httpapi"
	"github.com/open-rails/authkit/jwtkit"
)

// Config is the host-provided configuration for an AuthKit engine. Fields are
// grouped by concern into typed sub-structs (#108). It carries DATA/POLICY only;
// runtime dependencies (Postgres, senders) are Deps.
type Config struct {
	// HTTP configures the HTTP surface New builds. The zero value keeps the
	// runtime headless: operations and Verifier only.
	HTTP HTTPConfig

	// River configures mandatory PostgreSQL cleanup; in-memory TTL stays local.
	River RiverConfig

	// Naming is the shared user/group rename policy, normalized at construction.
	Naming iam.NamingConfig

	// Token is the JWT issuing/verification contract and session limits.
	Token TokenConfig
	// Frontend describes host-owned frontend routes used for absolute-URL and
	// full-page OIDC callback construction.
	Frontend FrontendConfig
	// Registration controls verification policy and public self-registration.
	Registration RegistrationConfig
	// Password is the rule every password write enforces; the zero value is
	// 8..128 characters, no composition rules, common passwords rejected.
	// Published by GET {api}/capabilities.
	Password PasswordPolicy
	// Username bounds username length; zero fields default to 4..30. The
	// character rule is fixed (iam.UsernamePattern). Published by
	// GET {api}/capabilities.
	Username iam.UsernamePolicy
	// Keys controls signing-key resolution (or verify-only mode).
	Keys KeysConfig
	// Identity declares external OAuth2/OIDC identity providers.
	Identity IdentityConfig
	// APIKeys configures opaque permission-group-owned machine credentials.
	APIKeys APIKeysConfig
	// TwoFactor configures optional MFA features.
	TwoFactor TwoFactorConfig
	// Passkeys configures WebAuthn/FIDO2 passkey ceremonies.
	Passkeys PasskeyConfig
	// DeviceKeys enables the refreshless native-client device-key surface
	// (#278). Off by default: enrollment is an email-code login, so hosts opt
	// in explicitly before RouteDeviceKeys is mounted or the engine issues
	// enrollment/login challenges (#293).
	DeviceKeys DeviceKeysConfig
	// Roles is the permission model: personas, their permissions and roles
	// (NewRoles). nil is root-only.
	Roles *Roles

	// Applications configures application self-registration (#264): domain-
	// proven remote applications with service-owned orgs. Zero value = disabled
	// (the manual/bootstrap registration paths are unaffected).
	Applications ApplicationsConfig

	// Delegated configures the delegated-token mint route (#261): the audience
	// allowlist and the TTL floor/default/ceiling. Zero value = the route is
	// not mounted. An internally inconsistent triple refuses at construction —
	// never a silent clamp of the configuration itself (request-time TTLs ARE
	// clamped into the validated bounds).
	Delegated DelegatedConfig

	// Documents configures the published signed-document surface (#260): the
	// remote applications that may fetch documents (Auth.PublishDocument) from
	// GET|HEAD {BasePath}/.well-known/authkit/documents/{digest}. Without readers the
	// route is not mounted and nothing may be published.
	Documents DocumentsConfig

	// Schema is the Postgres schema AuthKit's tables live in. Empty defaults to
	// "profiles" (the historical hard-coded name). Set it when multiple apps
	// embed AuthKit against the same database and must not share auth tables
	// (authkit issue 69). The name must match ^[a-z_][a-z0-9_]*$ (max 63 bytes);
	// New rejects anything else. Hosts must run Migrate with
	// the same schema before New.
	Schema string

	// SolanaNetwork is the SIWS chain selector ("mainnet"/"testnet"/"devnet").
	// Empty defaults to mainnet. Solana Name Service (SNS)
	// resolution is AuthKit-owned: it uses the built-in keyless resolver, with a
	// fixed 3s lookup timeout and 24h cache TTL. There is no host override.
	SolanaNetwork string

	// SessionEventRetention is how long session-event history rows
	// (sign-ins/revocations, incl. IP + user-agent — personal data) are kept
	// before the periodic auth-state cleanup prunes them. 0 (unset) defaults to 365
	// days — the deliberate ceiling; any negative value keeps events forever.
	SessionEventRetention time.Duration
}

// PasswordPolicy is the host-configured password rule, NIST SP
// 800-63B-style by default. Zero lengths default to 8..128 characters (Unicode
// code points; MaxLength at most 1024). Composition rules are opt-in:
// uppercase/lowercase/digit use Unicode categories, and a symbol is any rune
// that is neither a letter nor a digit. AllowCommon disables the embedded
// common-password blocklist.
type PasswordPolicy struct {
	MinLength        int
	MaxLength        int
	RequireUppercase bool
	RequireLowercase bool
	RequireDigit     bool
	RequireSymbol    bool
	AllowCommon      bool
}

// ApplicationsConfig configures application self-registration (#264).
//
// The trust root is domain control (or an owning user account) — never the
// keypair alone: registration fetches
// https://<domain>/.well-known/authkit/application.json server-side, and that
// fetch IS the domain-control proof. Re-registration of the same domain
// re-proves the root and adopts the document's current keys (the boot-time
// self-heal and the rotation-from-root path).
type ApplicationsConfig struct {
	// SelfRegistration enables the POST /applications/register surface (and
	// the signed rotate/repoint routes). Off by default.
	SelfRegistration bool
	// AllowPrivateNetworkJWKS permits http and private/loopback addresses for
	// every remote-application fetch — jwks_uri values, application documents
	// and their domain proofs — and turns off the SSRF guard on the verifier's
	// JWKS client. Local federation rigs only; the default (false) refuses
	// anything that is not a public https endpoint.
	AllowPrivateNetworkJWKS bool
	// OrgPersona is the declared persona of the group each self-registered
	// application owns: registration creates it and seeds the application as
	// its owner. Required when SelfRegistration is set; must be a declared
	// non-root persona.
	OrgPersona iam.Persona
}

// DelegatedConfig configures the delegated-token mint route (#261/#277,
// POST /delegated/token under the API prefix). All four knobs are DATA: the
// mint mechanics (audience-subset clamp, TTL clamp, sender binding, grant
// check, document stamping, KID reconciliation) live in AuthKit; the host
// contributes the required delegation authorizer (Deps.DelegatedAuthorization).
type DelegatedConfig struct {
	// AllowDPoP allows browser-key binding. The authorizer must handle requests
	// with ConfirmationJWKThumbprintSHA256 set and DelegateCertificate nil.
	AllowDPoP bool `json:"allow_dpop" yaml:"allow_dpop"`
	// Audiences is the allowlist. Requested audiences must be a subset; an
	// empty request receives the full list. Empty = the route is disabled.
	Audiences []string
	// TTLFloor/TTLDefault/TTLCeiling bound the minted token TTL. Unset fields
	// default to 60s / 15m / 1h. After defaulting, the triple must satisfy
	// 0 < floor <= default <= ceiling or construction refuses (#231 house
	// style: an impossible configuration never boots).
	TTLFloor   time.Duration
	TTLDefault time.Duration
	TTLCeiling time.Duration
}

// DocumentsConfig configures reader authorization for the published
// signed-document surface (#260, #296).
type DocumentsConfig struct {
	// Readers are the remote applications allowed to fetch published
	// documents. Authorization is config, not a host callback, and it keys on
	// an identity nobody else can claim — never on the slug, which is a
	// claimable handle. Empty + a mounted documents surface is a construction
	// error, never a public route.
	Readers []DocumentReader
	// AllowRegisteredTier admits readers still at the registered tier
	// (self-registered, not yet approved by an admin). Default: approved only.
	AllowRegisteredTier bool
}

// DocumentReader pins one reader by exactly one identity:
//   - ID: the application's uuid.
//   - Domain: the proven domain of a domain-rooted (self-registered) application.
//   - Issuer: the issuer of a manually registered application the platform
//     itself holds under the root group (bootstrap manifest / root credentials
//     manager). A tenant-registered application never matches by issuer.
type DocumentReader struct {
	ID     string
	Domain string
	Issuer string
}

// NOTE (#264 ruling 5, simplified): re-verification cadence and dormancy
// scheduling are HOST policy — authkit ships no TTL machinery or background
// jobs of its own.

// TokenConfig is the JWT issuing/verification contract plus session limits.
type TokenConfig struct {
	// EntitlementAllowlist selects coarse provider-granted names for native
	// access-token snapshots. Empty skips the mint-time provider lookup and
	// omits the claim. Selection never grants an entitlement by itself.
	EntitlementAllowlist []string
	Issuer               string
	IssuedAudiences      []string // tokens issued will contain ALL of these audiences
	ExpectedAudiences    []string // audiences accepted at verification; empty defaults to IssuedAudiences
	AccessTokenDuration  time.Duration
	RefreshTokenDuration time.Duration
	// SessionMaxPerUser caps concurrent refresh sessions per user. 0 (unset)
	// applies the default of 3; any negative value (e.g. -1) means unlimited.
	// Eviction is always evict-oldest.
	SessionMaxPerUser int
	// RefreshRotationGrace is how long a just-rotated refresh token keeps being
	// answered with the successor it rotated into, instead of being read as
	// reuse and revoking the family (ak#274). It exists for the race in which
	// two holders of ONE token refresh at once — a shared credential file, a
	// retried request, a response lost in flight — which is otherwise
	// indistinguishable from theft and is punished as theft. 0 (unset) applies
	// the default of 30s; any negative value disables the window and restores
	// strictly single-use rotation.
	RefreshRotationGrace time.Duration
	// AccountIssuers lists every issuer whose deployment shares this account
	// store (same database schema), e.g. two sites with separate logins over
	// one set of accounts. Account-level revocations — admin emergency revoke,
	// password/contact changes, ban and deletion — cover refresh sessions on
	// all of them. Logout and a user's own session management stay on Issuer.
	// Issuer is always included; empty means Issuer alone. Every deployment
	// sharing the store should configure the same set.
	AccountIssuers []string
}

// FrontendConfig describes host-owned frontend routes.
type FrontendConfig struct {
	// BaseURL, if set, is used for building absolute URLs (e.g. password
	// reset/verify links). If empty and Token.Issuer is a well-formed URL,
	// New defaults it to the issuer.
	BaseURL string
	// OIDCReturnPath is the host SPA landing route AuthKit redirects to after it
	// finishes an OIDC/social login flow (the browser is sent to
	// BaseURL + OIDCReturnPath with the login result). This is NOT the backend
	// OAuth/OIDC provider callback URL — AuthKit owns that. Empty defaults to
	// "/login/callback".
	OIDCReturnPath string
	// VerifyPath is the host-owned frontend route that receives scanner-safe
	// verification link landings. Empty defaults to "/verify".
	VerifyPath string
	// PasswordResetPath is the host-owned frontend route that receives
	// scanner-safe password reset link landings. Empty defaults to "/reset".
	PasswordResetPath string
	// PasswordlessPath is the host-owned frontend route that receives
	// passwordless login magic links. Empty defaults to "/passwordless".
	PasswordlessPath string
	// InvitePath is the host-owned frontend route that receives permission-group
	// invite links (`?code=…`); the SPA reads the code and POSTs it to the redeem
	// endpoint. Empty defaults to "/accept-invite". (#134)
	InvitePath string
}

// DeviceKeysConfig controls the native-client device-key surface (#278).
type DeviceKeysConfig struct {
	// Enabled mounts RouteDeviceKeys and lets the engine run enrollment and
	// login ceremonies.
	Enabled bool
}

// RegistrationConfig controls verification policy and public self-registration.
type RegistrationConfig struct {
	// Verification controls registration verification: "none"|"optional"|
	// "required". Empty defaults to "none". Every policy stores the address
	// unverified until proven; "optional" also sends a code at registration.
	// Unproven accounts cannot add login methods (docs/security/contact-ownership.md).
	Verification iam.RegistrationVerificationPolicy
	// NativeUserMode controls public native-user self-registration. Empty
	// defaults to "open". Non-open modes disable every public user-creation path;
	// the system's CreateUser, bootstrap and import still work.
	NativeUserMode iam.RegistrationMode
	// PasswordlessLogin enables contact-based passwordless sessions. Off by
	// default; hosts must opt in before /passwordless/start sends challenges.
	PasswordlessLogin bool
	// PasswordlessAutoRegistration lets a verified unknown contact create a
	// no-password user during passwordless confirmation. Off by default.
	PasswordlessAutoRegistration bool
	// AllowMissingSenders lets verification, contact-change, password-reset and
	// login-code flows proceed when no email/SMS sender is wired: nothing is
	// delivered and the engine hands the code back to its caller (dev rigs read
	// it from there). The default (false) makes a missing sender an error.
	AllowMissingSenders bool
	// VerificationSendTimeout bounds each in-line email/SMS provider send
	// (registration/verification codes, password-reset links, passwordless login
	// codes) so a misconfigured/unreachable provider cannot hang the request that
	// triggered it. 0 (unset) defaults to 15 seconds.
	VerificationSendTimeout time.Duration
}

// KeysConfig controls signing-key resolution. AuthKit reads NO environment
// variables here (#231): key material and the dev opt-in come from the host's
// explicit configuration; binaries (cmd/authkit-server) read env once at their
// own boundary and set these fields.
type KeysConfig struct {
	// Source can be nil — if nil, authkit resolves keys from the filesystem:
	// <Path>/keys.json (default /vault/auth), hot-reloaded on rotation. When no
	// keys.json exists, construction FAILS unless AllowEphemeralDevKeys is set.
	// Hosts NEVER handle the private key — they delegate the signing OPERATION
	// to authkit; there is no API that returns a private key or PEM (a future
	// Vault-Transit backend, authkit future #72, drops in behind the same
	// Signer seam).
	Source jwtkit.KeySource
	// Path overrides the filesystem DIRECTORY the local key resolver scans for
	// keys.json (and totp.key, #148) when Source is nil. Empty defaults to
	// /vault/auth. There is no env fallback (#231; AUTHKIT_KEYS_PATH is read by
	// cmd/authkit-server only).
	Path string
	// AllowEphemeralDevKeys opts in to auto-generating an RSA dev signing
	// keypair when Source is nil and no <Path>/keys.json exists. It lives in
	// memory, unless Path is explicit — then it is written to <Path>/keys.json
	// so restarts reuse it. DEVELOPMENT ONLY — the default (false) is
	// fail-closed: with no keys configured, New returns a hard error
	// instead of silently minting dev keys (#231). This flag is deliberately
	// NOT derived from Environment.
	AllowEphemeralDevKeys bool
	// VerifyOnly constructs AuthKit with NO active signer (#87): token
	// MINTING returns ErrSigningNotConfigured, while VERIFICATION and all RBAC reads
	// work fully and the JWKS endpoint serves an empty key set. When true, key
	// resolution is SKIPPED. Ignored when Source is non-nil. Use it for a
	// pure resource-server / control-plane deployment that only verifies inbound
	// tokens.
	VerifyOnly bool
}

// IdentityConfig declares external OAuth2/OIDC identity providers.
type IdentityConfig struct {
	// Providers are the external identity providers: authprovider.Google/
	// Apple/Discord/GitHub for the built-ins, authprovider.OIDC/OAuth2 for any
	// other IdP. Each provider owns its quirks and carries its own Name.
	Providers []authprovider.Provider
}

// APIKeysConfig configures opaque permission-group-owned machine credentials.
type APIKeysConfig struct {
	// Prefix is the issuing application's brand prefix for generated API keys
	// (single value per deployment). Empty defaults to the bare `st_` marker.
	// Must be lowercase alphanumeric, 1-16 chars.
	Prefix string
	// MaxTTL caps how far in the future a minted API key may expire. 0 (default)
	// means no cap (keys may be non-expiring); when set, a requested expiry
	// beyond now+MaxTTL (incl. no-expiry) is capped at mint time.
	MaxTTL time.Duration
}

// TwoFactorConfig configures 2FA policy and key material (#148).
type TwoFactorConfig struct {
	// Mode is the account-wide 2FA policy: Disabled (no enroll/challenge/verify
	// routes usable), Optional (users may enroll), or Required (every user must
	// enroll before normal session use; existing un-enrolled users are challenged
	// on their next authenticated request). Empty defaults to Optional; other
	// values fail construction. Persona.RequireMFA enforces MFA per permission.
	Mode iam.TwoFactorMode

	// Methods is the set of second-factor channels the host enables
	// (Email/SMS/TOTP). Empty defaults to all three. A method whose dependency is
	// missing (e.g. SMS with no SMS sender) fails closed regardless of this list.
	Methods []iam.TwoFactorMethod

	// TOTPSecretKey encrypts persisted authenticator-app shared secrets. It must
	// be 16, 24, or 32 RAW bytes (not base64/hex). This is an OVERRIDE for
	// tests/custom key management; the normal path loads the key from
	// <Keys.Path>/totp.key (vault-mounted key material, same model as JWT
	// signing keys, #232). An override of any other
	// length is a hard construction error. Without either, TOTP enrollment
	// fails closed.
	TOTPSecretKey []byte
}

// PasskeyConfig configures WebAuthn relying-party identity and UV policy.
type PasskeyConfig struct {
	RPID             string
	RPDisplayName    string
	Origins          []string
	UserVerification string
}

// RiverConfig configures PostgreSQL maintenance. The default schema is public
// and cleanup runs hourly. Managed clients require a fleet with the same full
// worker/schedule set; unrelated libraries sharing a schema must compose one
// host-owned configuration so whichever replica leads has every schedule.
type RiverConfig struct {
	Schema          string
	CleanupInterval time.Duration
}

// HTTPConfig configures AuthKit's HTTP surface: one handler serving the JSON
// API, browser OIDC, JWKS and published documents. The engine's own policy
// lives in Config; this is only what the transport decides.
//
// Every route lives beneath BasePath:
//
//	{BasePath}{APIPath}/...                               JSON API
//	{BasePath}/oidc/{provider}/...                        browser OIDC
//	{BasePath}/.well-known/jwks.json                      JWKS
//	{BasePath}/.well-known/authkit/documents/{digest}     documents
type HTTPConfig struct {
	// Groups selects the mounted route groups. Nil mounts the default API
	// surface plus browser OIDC; non-nil mounts exactly the named groups.
	Groups []iam.RouteGroup
	// BasePath roots the whole surface. "" derives it from Token.Issuer's
	// path ("https://example.com/auth" gives "/auth"); when the issuer is a
	// URL a set value must equal that path, because verifiers and document
	// resolvers find JWKS and documents at the issuer plus these paths.
	// Serve the paths unchanged: no StripPrefix in front.
	BasePath string
	// APIPath anchors the JSON API beneath BasePath. "" means "/api/v1"; "/"
	// is BasePath itself.
	APIPath string
	// Exclude drops routes the host serves itself, named as Patterns reports
	// them ("GET /.well-known/jwks.json"). An entry matching no route is an
	// error.
	Exclude []string
	// Wrap decorates every API and browser-OIDC handler at mount time.
	Wrap func(iam.Route, http.Handler) http.Handler
	// RefreshCookie delivers the rotating refresh token as an HttpOnly cookie
	// (iam.RefreshCookieName) instead of a JSON body field. Browser mounts
	// only: the SPA and this handler must share an origin.
	RefreshCookie bool
	// DPoPRequestURL returns the externally visible delegation endpoint URL
	// when a proxy rewrites its path. Nil uses the issuer's origin and the
	// received path. Never derive it from untrusted forwarding headers.
	DPoPRequestURL func(*http.Request) string

	// Rate limiting is in-memory and per-process by default: each replica
	// counts separately. Set Redis when running more than one replica. At most
	// one of Redis, Limiter and DisableRateLimiting may be set.
	//
	// Redis shares rate-limit counters across replicas; it holds no other
	// AuthKit state.
	Redis redis.UniversalClient
	// RedisKeyPrefix namespaces the rate-limit keys so deployments can share
	// one Redis. Empty derives "authkit:<schema>:".
	RedisKeyPrefix string
	// RateLimits overlays bucket limits onto DefaultRateLimits; unknown
	// buckets are refused.
	RateLimits map[string]RateLimit
	// Limiter replaces AuthKit's limiter; RateLimits do not apply to it.
	Limiter RateLimiter
	// DisableRateLimiting turns rate limiting off. Tests only.
	DisableRateLimiting bool

	// Client-IP posture: exactly what sits in front of AuthKit must be
	// declared, or every client shares a proxy's one per-IP bucket.
	//
	// TrustedProxies are reverse proxies whose X-Forwarded-For is honoured.
	TrustedProxies []string
	// CloudflareProxies are Cloudflare's egress ranges: X-Forwarded-For plus
	// CF-Connecting-IP. Set only where Cloudflare fronts a locked-down origin.
	CloudflareProxies []string
	// DirectPeerIP asserts nothing sits in front: RemoteAddr is the client.
	DirectPeerIP bool
	// ClientIP replaces the proxy handling above entirely.
	ClientIP func(*http.Request) string

	// Languages declares the supported UI languages; the zero value is
	// English-only.
	Languages LanguageConfig
}

// RateLimit allows at most Limit requests per Window in one bucket, with an
// optional Cooldown between accepted requests.
type RateLimit struct {
	Limit    int
	Window   time.Duration
	Cooldown time.Duration
}

// RateLimiter is a host-supplied limiter keyed by bucket name and client key.
type RateLimiter interface {
	AllowNamed(bucket, key string) (bool, error)
}

// LanguageConfig declares the UI languages the HTTP surface negotiates.
type LanguageConfig struct {
	Supported []string
	Default   string
}

// DefaultRateLimits returns AuthKit's built-in per-endpoint limits, keyed by
// bucket name ("default" applies to unlisted buckets).
func DefaultRateLimits() map[string]RateLimit {
	out := map[string]RateLimit{}
	for bucket, l := range httpapi.DefaultRateLimits() {
		out[bucket] = RateLimit{Limit: l.Limit, Window: l.Window, Cooldown: l.Cooldown}
	}
	return out
}
