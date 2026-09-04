package authcore

import (
	"time"

	"github.com/open-rails/authkit/authprovider"
	"github.com/open-rails/authkit/jwtkit"
)

// Config is the host-provided configuration for an AuthKit Service. Fields are
// grouped by concern into typed sub-structs (#108). It carries DATA/POLICY only;
// runtime dependencies (Postgres, Redis, senders, loggers) are injected via the
// constructor's functional options, not here.
type Config struct {
	// Token is the JWT issuing/verification contract and session limits.
	Token TokenConfig
	// Frontend describes host-owned frontend routes used for absolute-URL and
	// full-page OIDC callback construction.
	Frontend FrontendConfig
	// Registration controls verification policy and public self-registration.
	Registration RegistrationConfig
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
	// RBAC declares the app's permission-group personas (#111): containment
	// schema plus per-persona role catalogs. Empty yields root-only.
	RBAC []PersonaDef

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

	// Documents configures the published signed-document surface (#260):
	// which remote-application reader slugs may fetch published documents from
	// GET|HEAD /.well-known/authkit/documents/{digest}. Publication is never
	// public — an empty list with a mounted documents surface refuses at
	// construction (authhttp.NewServer), fail-closed like the publisher itself.
	Documents DocumentsConfig

	// Environment is a host-provided runtime mode string used for dev/prod
	// behavior checks via IsDevEnvironment, the single classifier (#231): only
	// "dev", "development", "local", "test" (and empty, preserving zero-config
	// dev ergonomics) count as development; EVERYTHING else — including
	// "staging" — is treated as production-like (fail-closed). NOTE: ephemeral
	// signing-key generation is NOT tied to this field — it requires the
	// explicit Keys.AllowEphemeralDevKeys opt-in.
	Environment string

	// Schema is the Postgres schema AuthKit's tables live in. Empty defaults to
	// "profiles" (the historical hard-coded name). Set it when multiple apps
	// embed AuthKit against the same database and must not share auth tables
	// (authkit issue 69). The name must match ^[a-z_][a-z0-9_]*$ (max 63 bytes);
	// NewFromConfig rejects anything else. Hosts that set a non-default schema
	// must also run the migrations rendered for that schema — see
	// migrations/postgres.FSForSchema.
	Schema string

	// SolanaNetwork is the SIWS chain selector ("mainnet"/"testnet"/"devnet").
	// Empty derives a default from Environment. Solana Name Service (SNS)
	// resolution is AuthKit-owned: it uses the built-in keyless resolver, with a
	// fixed 3s lookup timeout and 24h cache TTL. There is no host override.
	SolanaNetwork string

	// SessionEventRetention is how long session-event history rows
	// (sign-ins/revocations, incl. IP + user-agent — personal data) are kept
	// before CleanupExpiredAuthState prunes them. 0 (unset) defaults to 365
	// days — the deliberate ceiling; any negative value keeps events forever.
	SessionEventRetention time.Duration
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
	// OrgPersona is the declared RBAC persona under which each self-registered
	// application's SERVICE-OWNED org is created (instance_slug = the
	// application slug; the application principal is seeded as its owner).
	// Required when SelfRegistration is set; must be a declared non-root
	// persona whose Parent is the root persona.
	OrgPersona string
}

// DelegatedConfig configures the delegated-token mint route (#261,
// POST /delegated/token under the API prefix). All four knobs are DATA: the
// mint mechanics (audience-subset clamp, TTL clamp, document stamping, KID
// reconciliation) live in AuthKit; the host contributes only an attribute
// provider (WithDelegatedAttributes) and optional document providers
// (authhttp.WithDocuments).
type DelegatedConfig struct {
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
// scheduling are HOST policy — host sweepers read RootVerifiedAt and call
// SetApplicationEnabled / DeletePermissionGroup; authkit ships no TTL
// machinery or background jobs of its own.

// TokenConfig is the JWT issuing/verification contract plus session limits.
type TokenConfig struct {
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
}

// FrontendConfig describes host-owned frontend routes.
type FrontendConfig struct {
	// BaseURL, if set, is used for building absolute URLs (e.g. password
	// reset/verify links). If empty and Token.Issuer is a well-formed URL,
	// NewFromConfig defaults it to the issuer.
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

// RegistrationConfig controls verification policy and public self-registration.
type RegistrationConfig struct {
	// Verification controls registration verification: "none"|"optional"|
	// "required". Empty defaults to "none".
	Verification RegistrationVerificationPolicy
	// NativeUserMode controls public native-user self-registration. Empty
	// defaults to "open". Non-open modes disable every public user-creation path
	// while leaving embedded admin/bootstrap core APIs available.
	NativeUserMode RegistrationMode
	// PasswordlessLogin enables contact-based passwordless sessions. Off by
	// default; hosts must opt in before /passwordless/start sends challenges.
	PasswordlessLogin bool
	// PasswordlessAutoRegistration lets a verified unknown contact create a
	// no-password user during passwordless confirmation. Off by default.
	PasswordlessAutoRegistration bool
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
	// keypair (persisted under .runtime/authkit/) when Source is nil and no
	// <Path>/keys.json exists. DEVELOPMENT ONLY — the default (false) is
	// fail-closed: with no keys configured, NewFromConfig returns a hard error
	// instead of silently minting dev keys (#231). This flag is deliberately
	// NOT derived from Environment.
	AllowEphemeralDevKeys bool
	// VerifyOnly constructs the Service with NO active signer (#87): token
	// MINTING returns ErrMissingSigner, while VERIFICATION and all RBAC reads
	// work fully and the JWKS endpoint serves an empty key set. When true, key
	// resolution is SKIPPED. Ignored when Source is non-nil. Use it for a
	// pure resource-server / control-plane deployment that only verifies inbound
	// tokens.
	VerifyOnly bool
}

// IdentityConfig declares external OAuth2/OIDC identity providers.
type IdentityConfig struct {
	// Providers is the list of external identity providers — a provider is a
	// provider, there is no built-in-vs-custom split (#143). Use a built-in
	// constructor for the common ones (authprovider.Google/Apple/Discord/GitHub,
	// which need only client id/secret and derive standard scopes/mapping) or a
	// full authprovider.Provider descriptor for any other OAuth2/OIDC provider.
	// Each provider carries its own Name.
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
	// on their next authenticated request). Empty defaults to Optional. Per-role
	// RoleDef.RequiresMFA remains available for narrower enforcement.
	Mode TwoFactorMode

	// Methods is the set of second-factor channels the host enables
	// (Email/SMS/TOTP). Empty defaults to all three. A method whose dependency is
	// missing (e.g. SMS with no SMS sender) fails closed regardless of this list.
	Methods []TwoFactorMethod

	// TOTPSecretKey encrypts persisted authenticator-app shared secrets. It must
	// be 16, 24, or 32 RAW bytes (not base64/hex). This is an OVERRIDE for
	// tests/custom key management; the normal path loads the key from
	// <Keys.Path>/totp.key (vault-mounted key material, same model as JWT
	// signing keys; wired in NewFromConfig, #232). An override of any other
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

// RegistrationVerificationPolicy and RegistrationMode are defined in authkit and
// re-exported in registration.go (#147).
