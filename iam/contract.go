package iam

import "time"

// Shared operation inputs and results, importable without the engine.

type DelegatedAccessParams struct {
	// Issuer becomes the `iss` claim: the AuthKit issuer that signed the token.
	// Must match a remote_application registered with the validating resource server.
	// Required when minting via the free function; the *Service mint method
	// defaults it to the Service's configured Issuer when empty.
	Issuer string
	// Audiences becomes the `aud` claim: the target resource API(s), e.g.
	// "openrails", "tensorhub", or "gen-orchestrator".
	Audiences []string
	// DelegatedSubject becomes `delegated_sub`: the issuer-side subject id.
	// Required. No local account is implied in the receiving service.
	DelegatedSubject string
	// Permissions becomes the `permissions` claim: an array of resource-defined
	// permission strings (NOT OAuth's space-delimited `scope`). Receiving
	// services validate these against their own permission set.
	Permissions []string
	// Documents becomes the top-level `documents` claim: versioned document
	// type -> canonical sha256 digest. AuthKit transports and validates these
	// references but does not resolve or interpret their payload schemas.
	Documents map[string]string
	// Attributes carries app-specific JSON inline. AuthKit transports values
	// without interpreting or resolving them; the consuming app owns their schema.
	// Reserved well-known keys: `tier` (opaque entitlement-tier string), `roles`
	// (a uuid array; prefer the typed Roles field below), and `documents` (use the
	// top-level Documents field above). Everything else is free-form per consuming
	// app. Values are arbitrary JSON.
	Attributes map[string]any
	// Roles is a convenience for emitting the delegated subject's role UUIDs into
	// `attributes.roles` (a JSON array of UUID strings). Equivalent to setting
	// Attributes["roles"] yourself; when both are set this typed field wins.
	Roles []string
	// TTL is the token lifetime. Defaults to 15m when zero.
	TTL time.Duration
	// JTI becomes the `jti` claim (token identifier). Optional to SET, but
	// always PRESENT on the minted token: when empty the minter generates a
	// fresh uuidv7, so a receiving service can revoke any delegated token by
	// id without a per-issuer "does this one have a jti" carve-out.
	JTI string
	// NotBefore, when set, becomes the `nbf` claim. Optional.
	NotBefore time.Time
	// ConfirmationCertificateSHA256, when set, binds the token to the delegate's
	// X.509 certificate as RFC 8705 `cnf.x5t#S256`; verification then requires
	// that exact leaf as the TLS peer. When both confirmation fields are nil,
	// the token is an unbound bearer.
	ConfirmationCertificateSHA256 *[32]byte
	// ConfirmationJWKThumbprintSHA256 binds the token to a DPoP key (RFC 9449).
	// Mutually exclusive with ConfirmationCertificateSHA256.
	ConfirmationJWKThumbprintSHA256 *[32]byte
}

// MaxBatch bounds the ids (users, groups, subjects) accepted by one batch call.
const MaxBatch = 500

type RemoteApplicationAccessParams struct {
	// Issuer becomes the `iss` claim: the remote_application's OIDC issuer,
	// registered with the validating resource server. Required when minting via
	// the free function; the *Service mint method defaults it to the Service's
	// configured Issuer when empty.
	Issuer string
	// Audiences becomes the `aud` claim: the target resource API(s).
	Audiences []string
	// TTL is the token lifetime. Defaults to 15m when zero.
	TTL time.Duration
	// JTI, when set, becomes the `jti` claim. Optional.
	JTI string
	// NotBefore, when set, becomes the `nbf` claim. Optional.
	NotBefore time.Time
	// Permissions, when non-nil, becomes the `permissions` claim: a DOWN-SCOPING
	// request for least-privilege (#76 amendment). The stored grant is the
	// ceiling; effective = this claim, but EVERY claimed perm must be within the
	// stored grant — an out-of-grant claimed perm REJECTS the token at verify (a
	// remote application access token can never widen). nil/absent => no claim
	// => full stored ceiling (backward-compatible with v0.28.0 tokens).
	Permissions []string
}

type AdminUser struct {
	ID              string     `json:"id"`
	Email           *string    `json:"email"` // Nullable for phone-only users
	PhoneNumber     *string    `json:"phone_number"`
	Username        *string    `json:"username"`
	DiscordUsername *string    `json:"discord_username"`
	EmailVerified   bool       `json:"email_verified"`
	PhoneVerified   bool       `json:"phone_verified"`
	BannedAt        *time.Time `json:"banned_at,omitempty"`
	BannedUntil     *time.Time `json:"banned_until,omitempty"`
	BanReason       *string    `json:"ban_reason,omitempty"`
	BannedBy        *string    `json:"banned_by,omitempty"`
	DeletedAt       *time.Time `json:"deleted_at"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
	LastLogin       *time.Time `json:"last_login"`
	Roles           []string   `json:"roles"`
	RemovedRoles    []string   `json:"removed_roles,omitempty"`
	Entitlements    []string   `json:"entitlements"`
	// PreferredLanguage carries the user's stored language preference through from
	// the loaded user row, so callers (e.g. GET /me) need not issue a separate
	// language read (#228). Omitted from JSON when unset.
	PreferredLanguage *string `json:"preferred_language,omitempty"`
	// AvatarURL is the host-supplied avatar URL/key string (#262).
	AvatarURL *string `json:"avatar_url,omitempty"`
}

type AdminListUsersResult struct {
	Users  []AdminUser `json:"users"`
	Total  int64       `json:"total"`
	Limit  int         `json:"limit"`
	Offset int         `json:"offset"`
}

type AdminUserStatus string

type AdminUserSort string

type AdminUserListOptions struct {
	Page        int
	PageSize    int
	Search      string          // ILIKE over username/email/phone_number
	Role        Role            // root_role slug (e.g. "admin"); empty = no role filter
	Status      AdminUserStatus // empty = non-deleted (historical default)
	Sort        AdminUserSort   // empty = created_at
	Desc        bool            // true = descending
	Entitlement string          // empty = no entitlement filter; else provider-backed
}

type ServiceJWTMintOptions struct {
	Subject     string
	Audiences   []string
	Permissions []string
	Lifetime    time.Duration
	NotBefore   time.Time
	IssuedAt    time.Time
	JTI         string
}

const (
	AdminUserStatusActive  AdminUserStatus = "active"     // not deleted, not banned
	AdminUserStatusBanned  AdminUserStatus = "banned"     // not deleted, currently banned
	AdminUserStatusDeleted AdminUserStatus = "deleted"    // soft-deleted
	AdminUserStatusAny     AdminUserStatus = "any"        // no deleted/banned predicate
	AdminUserSortCreatedAt AdminUserSort   = "created_at" // default
	AdminUserSortLastLogin AdminUserSort   = "last_login"
	AdminUserSortUsername  AdminUserSort   = "username"
	AdminUserSortEmail     AdminUserSort   = "email"
)
