package authkit

import "time"

// Contract DTOs relocated from internal/authcore (#138 inversion): plain data,
// stdlib-only. The engine aliases these back. var _ = time.Second // keep import

type APIKey struct {
	ID          string
	KeyID       string
	Name        string
	Role        string
	Permissions []string
	CreatedBy   string
	CreatedAt   time.Time
	LastUsedAt  *time.Time
	ExpiresAt   *time.Time
	RevokedAt   *time.Time
}

type APIKeyMintOptions struct {
	Name      string
	Role      string
	CreatedBy string
	ExpiresAt *time.Time
}

type BootstrapManifest struct {
	Users              []BootstrapManifestUser              `json:"users" yaml:"users"`
	RemoteApplications []BootstrapManifestRemoteApplication `json:"remote_applications" yaml:"remote_applications"`
	GroupRoles         []BootstrapManifestGroupRole         `json:"group_roles" yaml:"group_roles"`
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
	Slug       string         `json:"slug" yaml:"slug"`
	Issuer     string         `json:"issuer" yaml:"issuer"`
	JWKSURI    string         `json:"jwks_uri" yaml:"jwks_uri"`
	PublicKeys []RemoteAppKey `json:"public_keys" yaml:"public_keys"`
	Enabled    *bool          `json:"enabled" yaml:"enabled"`
	RootRole   string         `json:"root_role" yaml:"root_role"`
}

type BootstrapManifestGroupRole struct {
	Username              string `json:"username" yaml:"username"`
	RemoteApplicationSlug string `json:"remote_application_slug" yaml:"remote_application_slug"`
	Persona               string `json:"persona" yaml:"persona"`
	InstanceSlug          string `json:"instance_slug" yaml:"instance_slug"`
	Role                  string `json:"role" yaml:"role"`
}

type BootstrapUserPassword struct {
	Plaintext     string         `json:"plaintext" yaml:"plaintext"`
	Hash          string         `json:"hash" yaml:"hash"`
	HashAlgo      string         `json:"hash_algo" yaml:"hash_algo"`
	HashParams    map[string]any `json:"hash_params" yaml:"hash_params"`
	ResetRequired bool           `json:"reset_required" yaml:"reset_required"`
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
	// StartupOnly applies the manifest at most once, using Name as the marker.
	// Leave false for ordinary operator/CLI applies.
	StartupOnly bool
	// Name scopes the startup apply-once marker. Empty means "default".
	Name string
}

type BootstrapManifestResult struct {
	DryRun               bool `json:"dry_run"`
	AlreadyApplied       bool `json:"already_applied"`
	UsersCreated         int  `json:"users_created"`
	UsersUpdated         int  `json:"users_updated"`
	PasswordsSet         int  `json:"passwords_set"`
	PasswordsKept        int  `json:"passwords_kept"`
	RootRoleAssignments  int  `json:"root_role_assignments"`
	GroupRoleAssignments int  `json:"group_role_assignments"`
	RemoteApplications   int  `json:"remote_applications"`
	RemoteAppRootRoles   int  `json:"remote_application_root_roles"`
}

type CustomJWTMintOptions struct {
	// Claims is the host's claim set, e.g. {"cap_kind": "...", "grants": [...],
	// "release_id": "..."}. Required and non-empty. It may carry `sub`/`aud`
	// (unless overridden by the Subject/Audiences options) but may NOT carry the
	// AuthKit-owned registered claims `iss`/`iat`/`exp`.
	Claims map[string]any
	// TTL is the token lifetime. Required (must be > 0); capped at
	// MaxCustomJWTLifetime.
	TTL time.Duration
	// Type is the JOSE `typ` header (e.g. "worker-capability+jwt"). When empty the
	// header is left unset — unlike the opinionated minters, MintCustomJWT does
	// not impose a default `typ`; the host owns the token shape. It may NOT be one
	// of AuthKit's own first-party classes (access / delegated-access /
	// remote-application-access / service `+jwt`) — doing so returns
	// ErrCustomJWTReservedType (AK2-AUTH-02).
	Type string
	// Subject, when set, becomes the `sub` claim and wins over any `sub` in Claims.
	Subject string
	// Audiences, when set, becomes the `aud` claim and wins over any `aud` in Claims.
	Audiences []string
	// Issuer, when set, becomes the `iss` claim; otherwise `iss` defaults to the
	// Service's configured Issuer. This is the ONLY way to override `iss`.
	Issuer string
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
	// Attributes becomes the `attributes` claim: the canonical app-specific
	// ESCAPE HATCH (#75). An object of issuer-asserted, NAMESPACED, OPAQUE
	// key/values that AuthKit transports + optionally shape-validates but NEVER
	// interprets — the semantics belong to the consuming app (tensorhub etc.).
	// Each value is set in ONE of two modes, per key:
	//   INLINE    — the value carries the full definition, e.g.
	//               {"tier":{"endpoints":[...],"caps":[...]}}. No lookup.
	//   REFERENCE — the value is a short string key, e.g. {"tier":"tier-1"},
	//               resolved by the consumer against a definition the
	//               remote_application registered ahead of time (see the
	//               attribute-def registry: Service.RegisterRemoteAppAttributeDef
	//               / ResolveRemoteAppAttributeDef). Keeps tokens small.
	// Reserved well-known keys: `tier` (opaque entitlement-tier string) and
	// `roles` (a uuid array; prefer the typed Roles field below). Everything
	// else is free-form per consuming app. Values are arbitrary JSON.
	Attributes map[string]any
	// Roles is a convenience for emitting the delegated subject's role UUIDs into
	// `attributes.roles` (a JSON array of UUID strings). Equivalent to setting
	// Attributes["roles"] yourself; when both are set this typed field wins.
	Roles []string
	// TTL is the token lifetime. Defaults to 15m when zero.
	TTL time.Duration
	// JTI, when set, becomes the `jti` claim (token identifier). Optional.
	JTI string
	// NotBefore, when set, becomes the `nbf` claim. Optional.
	NotBefore time.Time
}

type GroupInviteLink struct {
	ID                string
	PermissionGroupID string
	Role              string
	InvitedBy         string
	Uses              int
	ExpiresAt         *time.Time
	RevokedAt         *time.Time
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

type CreateGroupInviteLinkRequest struct {
	Persona      string
	InstanceSlug string
	Role         string
	ExpiresIn    time.Duration
	InvitedBy    string
}

type GroupInviteLinkCreated struct {
	ID   string
	Code string
	URL  string
}

type RedeemGroupInviteLinkResult struct {
	Persona      string
	InstanceSlug string
	Role         string
}

type AccountRegistrationInvite struct {
	ID         string
	Email      string
	InvitedBy  string
	ExpiresAt  time.Time
	RevokedAt  *time.Time
	ConsumedAt *time.Time
	ConsumedBy *string
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

type CreateAccountRegistrationInviteRequest struct {
	Email     string
	InvitedBy string
	ExpiresIn time.Duration
	// Optional permission-group grant (#147): when set, consuming the code ALSO
	// adds the (new or signed-in) user to this group/role — one unbound link that
	// registers a stranger AND joins them. GroupPersona+GroupRole are required
	// together (GroupInstanceSlug may be "" for the singleton root group).
	GroupPersona      string
	GroupInstanceSlug string
	GroupRole         string
}

type AccountRegistrationInviteCreated struct {
	ID        string
	Code      string
	URL       string
	Email     string
	ExpiresAt time.Time
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

type MFAStatus struct {
	Enabled        bool
	Satisfied      bool
	AllowedMethods []string
}

type PasswordlessStartRequest struct {
	Identifier         string
	Mode               string
	ReturnTo           string
	PreferredLanguage  string
	AccountInviteToken string
}

type PasswordlessStartResult struct {
	Sent    bool
	Channel string
	Code    string
	LinkURL string
}

type PasswordlessConfirmResult struct {
	UserID   string
	Method   string
	ReturnTo string
}

type CreatePermissionGroupRequest struct {
	Persona            string
	InstanceSlug       string
	ParentPersona      string
	ParentInstanceSlug string
	OwnerSubjectID     string
}

type GroupMember struct {
	SubjectID   string
	SubjectKind string
	Role        string
}

type SubjectGroupMembership struct {
	Persona      string
	InstanceSlug string
	Role         string
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

type PreferredLanguage struct {
	Language string
}

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
	HashParams   []byte
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
	Biography       *string    `json:"biography"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
	LastLogin       *time.Time `json:"last_login"`
	Roles           []string   `json:"roles"`
	RemovedRoles    []string   `json:"removed_roles,omitempty"`
	Entitlements    []string   `json:"entitlements"`
}

type AdminListUsersResult struct {
	Users  []AdminUser `json:"users"`
	Total  int64       `json:"total"`
	Limit  int         `json:"limit"`
	Offset int         `json:"offset"`
}

type RBACDriftReport struct {
	GroupUserRoles int `json:"group_user_roles"`
	CustomRoles    int `json:"group_custom_roles"`
	APIKeys        int `json:"api_keys"`
}

func (r RBACDriftReport) Total() int {
	return r.GroupUserRoles + r.CustomRoles + r.APIKeys
}

type AdminUserStatus string

type AdminUserSort string

type AdminUserListOptions struct {
	Page        int
	PageSize    int
	Search      string          // ILIKE over username/email/phone_number
	Role        string          // root_role slug (e.g. "admin"); empty = no role filter
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
