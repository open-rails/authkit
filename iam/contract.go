package iam

import "time"

// Shared operation inputs and results, importable without the engine.

type BootstrapManifest struct {
	Users              []BootstrapManifestUser              `json:"users" yaml:"users"`
	RemoteApplications []BootstrapManifestRemoteApplication `json:"remote_applications" yaml:"remote_applications"`
	// Dev carries dev-only runtime fixtures (#266). NOT part of the apply-once
	// reconcile: hosts read it at every boot and honor it only in a dev
	// environment (fail-closed).
	Dev BootstrapManifestDev `json:"dev,omitempty" yaml:"dev,omitempty"`
}

// BootstrapManifestDev is the dev-only fixture section of a bootstrap manifest.
type BootstrapManifestDev struct {
	// StaticEntitlements are entitlement names seeded into every access token
	// via a static EntitlementsProvider — billing/entitlement E2E fixtures as
	// reviewable YAML (formerly the AUTHKIT_STATIC_ENTITLEMENTS env CSV, #266).
	StaticEntitlements []string `json:"static_entitlements,omitempty" yaml:"static_entitlements,omitempty"`
}

type BootstrapManifestUser struct {
	Email         string                 `json:"email" yaml:"email"`
	PhoneNumber   string                 `json:"phone_number" yaml:"phone_number"`
	Username      string                 `json:"username" yaml:"username"`
	EmailVerified bool                   `json:"email_verified" yaml:"email_verified"`
	PhoneVerified bool                   `json:"phone_verified" yaml:"phone_verified"`
	Banned        bool                   `json:"banned" yaml:"banned"`
	BannedAt      *time.Time             `json:"banned_at" yaml:"banned_at"`
	BannedUntil   *time.Time             `json:"banned_until" yaml:"banned_until"`
	BanReason     *string                `json:"ban_reason" yaml:"ban_reason"`
	BannedBy      *string                `json:"banned_by" yaml:"banned_by"`
	Metadata      map[string]any         `json:"metadata" yaml:"metadata"`
	Password      *BootstrapUserPassword `json:"password" yaml:"password"`
	// RootRole assigns one root permission-group role to this user by name.
	// "owner" (the built-in apex, root:*) is seeded SEED-IF-ABSENT; any other
	// name is assigned as a same-named catalog role of the root persona.
	RootRole string `json:"root_role" yaml:"root_role"`
}

type BootstrapManifestRemoteApplication struct {
	Slug       string                 `json:"slug" yaml:"slug"`
	Issuer     string                 `json:"issuer" yaml:"issuer"`
	JWKSURI    string                 `json:"jwks_uri" yaml:"jwks_uri"`
	PublicKeys []RemoteApplicationKey `json:"public_keys" yaml:"public_keys"`
	Enabled    *bool                  `json:"enabled" yaml:"enabled"`
	RootRole   string                 `json:"root_role" yaml:"root_role"`
}

type BootstrapUserPassword struct {
	Plaintext     string `json:"plaintext" yaml:"plaintext"`
	Hash          string `json:"hash" yaml:"hash"`
	HashAlgo      string `json:"hash_algo" yaml:"hash_algo"`
	ResetRequired bool   `json:"reset_required" yaml:"reset_required"`
	// Enforce makes the password DESIRED-STATE (#89): re-asserted on every
	// reconcile. Default false = SEED-ONCE — the password is applied only when
	// the user is first created, so a password rotated out of band (via the
	// admin API) is never reverted to the manifest value on a later reconcile.
	// Must not be combined with ResetRequired (forcing a reset every run is
	// nonsensical).
	Enforce bool `json:"enforce" yaml:"enforce"`
}

type BootstrapReconcileOptions struct {
	DryRun bool
	// StartupOnly applies initial seed data at most once per database schema.
	// Leave false for ordinary operator/CLI applies.
	StartupOnly bool
	// Name labels its completion receipt; another name does not rerun genesis.
	// Empty means "default".
	Name string
}

type BootstrapManifestResult struct {
	DryRun              bool `json:"dry_run"`
	AlreadyApplied      bool `json:"already_applied"`
	UsersCreated        int  `json:"users_created"`
	UsersUpdated        int  `json:"users_updated"`
	PasswordsSet        int  `json:"passwords_set"`
	PasswordsKept       int  `json:"passwords_kept"`
	RootRoleAssignments int  `json:"root_role_assignments"`
	RemoteApplications  int  `json:"remote_applications"`
	RemoteAppRootRoles  int  `json:"remote_application_root_roles"`
}

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

type ImportUserStatus string

type ImportUserResult struct {
	Index  int
	UserID string // set when Status == inserted
	Status ImportUserStatus
	Reason string // set for skipped/rejected (machine-ish: "duplicate_in_batch", "already_exists", or a validation code)
}

type ImportUsersResult struct {
	Results  []ImportUserResult
	Inserted int
	Skipped  int
	Rejected int
}

// ImportUnverifiedSolanaLinkStatus is the per-row outcome of a legacy Solana
// identity import.
type ImportUnverifiedSolanaLinkStatus string

// ImportUnverifiedSolanaLinkInput is a migration-only Solana identity claim.
// Importing reserves the address but does not make it a login method; the user
// must prove ownership through the normal SIWS flow before AuthKit trusts it.
type ImportUnverifiedSolanaLinkInput struct {
	UserID          string
	Address         string
	Source          string
	SourceID        string
	SourceCreatedAt *time.Time
}

// ImportUnverifiedSolanaLinkResult is the outcome for one input row.
type ImportUnverifiedSolanaLinkResult struct {
	Index   int
	UserID  string
	Address string
	Status  ImportUnverifiedSolanaLinkStatus
	Reason  string
}

// ImportUnverifiedSolanaLinksResult aggregates per-row wallet import outcomes.
type ImportUnverifiedSolanaLinksResult struct {
	Results  []ImportUnverifiedSolanaLinkResult
	Inserted int
	Skipped  int
	Rejected int
}

type CreatePermissionGroupRequest struct {
	Persona        Persona
	InstanceSlug   string
	OwnerSubjectID string
	// OwnerSubjectKind selects the owner principal kind: "user" (default) or
	// "remote_application" (#264 service-owned orgs — an application principal
	// owning its own permission group).
	OwnerSubjectKind SubjectKind
	// DisplayName is free-form, non-unique group metadata (#264 naming
	// doctrine: vanity naming lives here, never on the slug).
	DisplayName string
}

// DeletePermissionGroupOptions controls the delete-time naming rule (#264):
// by DEFAULT a deleted group's slug is TOMBSTONED to its uuid forever
// (fail-safe — published references can never be re-claimed by someone else).
// ReleaseSlug frees the name (and drops the group's own tombstones) instead;
// that is safe ONLY for names nothing ever referenced, and the judgment is
// the host's: a released name re-created by a different owner is live and
// "live slugs win" in slug resolution, so any dangling published reference
// to the old group now resolves to the new owner (#308). authkit never
// deletes a group on its own.
type DeletePermissionGroupOptions struct {
	// ReleaseSlug applies to every canonical name of the deleted group;
	// prior aliases retain their original expiry.
	ReleaseSlug bool
}

type GroupMember struct {
	SubjectID   string
	SubjectKind SubjectKind
	Role        Role
}

type SubjectGroupMembership struct {
	// GroupID is the instance's internal uuid (#269). It is a JOIN KEY, not an
	// address — every route stays slug-addressed — and it is reported only for
	// the caller's OWN memberships.
	GroupID      string
	Persona      Persona
	InstanceSlug string
	DisplayName  string
	Role         Role
}

// MaxBatch bounds the ids (users, groups, subjects) accepted by one batch call.
const MaxBatch = 500

// GroupInstance is one persona instance's own identity (#269): the addressing
// pair a caller already holds, plus the uuid a HOST needs to own rows about the
// group in its own (or a sibling service's) ledger — openrails' `customer_id`
// being the case that forced it. Group ids never appear in a PATH; this type is
// how a caller who already has authority over an instance LEARNS its id.
type GroupInstance struct {
	// DeletedAt marks retained inactive state; only trusted ID reads include it.
	DeletedAt    *time.Time
	ID           string
	Persona      Persona
	InstanceSlug string
	DisplayName  string
}

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

// HashAlgoLegacyResetRequired marks user_passwords rows migrated from
// legacy systems whose stored hashes can never verify (DES crypt, md5-crypt,
// corrupted values). The raw legacy hash is preserved in password_hash for
// forensics only; the sole way forward for these accounts is a password reset.
const HashAlgoLegacyResetRequired = "legacy-reset-required"

type ImportUserInput struct {
	Email         string
	PhoneNumber   string
	Username      string
	EmailVerified bool
	PhoneVerified bool
	BannedAt      *time.Time
	BannedUntil   *time.Time
	BanReason     *string
	BannedBy      *string
	Metadata      map[string]any
	CreatedAt     *time.Time
	UpdatedAt     *time.Time

	// Optional pre-hashed credential to import alongside the user (bulk legacy
	// migration). When PasswordHash is non-empty and the user row is inserted,
	// ImportUsers stores it verbatim. The verify-time whitelist (argon2id/bcrypt,
	// else legacy-reset-required) still governs login; bulk import does not
	// re-validate the hash, matching single-row UpsertPasswordHash.
	PasswordHash string
	HashAlgo     string
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
	ImportUnverifiedSolanaLinkInserted ImportUnverifiedSolanaLinkStatus = "inserted"
	ImportUnverifiedSolanaLinkSkipped  ImportUnverifiedSolanaLinkStatus = "skipped"
	ImportUnverifiedSolanaLinkRejected ImportUnverifiedSolanaLinkStatus = "rejected"
)

const (
	ImportStatusInserted   ImportUserStatus = "inserted"
	ImportStatusSkipped    ImportUserStatus = "skipped"
	ImportStatusRejected   ImportUserStatus = "rejected"
	AdminUserStatusActive  AdminUserStatus  = "active"     // not deleted, not banned
	AdminUserStatusBanned  AdminUserStatus  = "banned"     // not deleted, currently banned
	AdminUserStatusDeleted AdminUserStatus  = "deleted"    // soft-deleted
	AdminUserStatusAny     AdminUserStatus  = "any"        // no deleted/banned predicate
	AdminUserSortCreatedAt AdminUserSort    = "created_at" // default
	AdminUserSortLastLogin AdminUserSort    = "last_login"
	AdminUserSortUsername  AdminUserSort    = "username"
	AdminUserSortEmail     AdminUserSort    = "email"
)
