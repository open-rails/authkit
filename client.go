package authkit

import (
	"context"
	"time"
)

// Client is composed from the small topic interfaces below (#143). Each one is a
// cohesive slice a host can depend on instead of the whole surface: a login
// service needs Users + Passwords, a token layer needs Tokens, an authorization
// layer needs Groups.

// Users is account create/read/update/delete, identity lookups, and bulk
// import/read.
type Users interface {
	CreateUser(ctx context.Context, email, username string) (*User, error)
	GetUserByEmail(ctx context.Context, email string) (*User, error)
	GetUserByPhone(ctx context.Context, phone string) (*User, error)
	GetUserByUsername(ctx context.Context, username string) (*User, error)
	// {Hard,Soft}DeleteUsers are batch-native admin bulk mutations (#219/#222):
	// per-item BEST-EFFORT — deleting 99 of 100 succeeds item-by-item
	// and the returned OpResults pinpoint the failures. Single-item = one-element
	// slice. The outer error is a whole-call failure only (e.g. no store).
	// Mark/ClearEmailVerified / UpdateEmail / UpdateUsername stay single by decision:
	// they are per-subject correctness flows, not bulk admin operations.
	HardDeleteUsers(ctx context.Context, userIDs []string) ([]OpResult, error)
	SoftDeleteUsers(ctx context.Context, userIDs []string) ([]OpResult, error)
	MarkEmailVerified(ctx context.Context, id string) error
	ClearEmailVerified(ctx context.Context, id string) error
	// UpdateAvatarURL sets (or clears, with nil) the user's avatar URL/key
	// string (#262). Blob storage/validation is the host's job — authkit stores
	// the string and serves it on GET /me.
	UpdateAvatarURL(ctx context.Context, id string, avatarURL *string) error
	UpdateEmail(ctx context.Context, id, email string) error
	UpdateUsername(ctx context.Context, id, username string) error
	UpdateImportedUser(ctx context.Context, userID string, input ImportUserInput) (*User, error)
	ImportUsers(ctx context.Context, inputs []ImportUserInput) (ImportUsersResult, error)
	ListUsersDeletedBefore(ctx context.Context, cutoff time.Time, limit int) ([]string, error)
	// UsersByIDs resolves many user IDs to slim display projections (id +
	// username/email) in ONE query: the batch read for "render N authors"
	// without N+1. Missing IDs are simply absent from the result. (Replaces the
	// removed authkit/identity store; writes go through UpdateUsername/UpdateEmail,
	// which enforce the rename cooldown + validation raw table writes skip.)
	// Returns map[id]UserRef (#219/#220): O(1) single-item access, missing IDs absent.
	//
	// PRIVILEGED — the projection carries Email. Render other users with
	// PublicUsersByIDs.
	UsersByIDs(ctx context.Context, ids []string) (map[string]UserRef, error)
	// PublicUsersByIDs is the PUBLIC-SAFE twin of UsersByIDs (#268): the same
	// one-query batch shape, projected to PublicUserRef — which has NO email
	// field — so a resolved author can be nested straight into a response body.
	// Soft-deleted users come back as tombstones (display fields blanked,
	// Deleted set); banned users come back normally, because a ban is an access
	// decision, not a visibility one; unknown ids are absent, and
	// PublicDisplayName covers them.
	PublicUsersByIDs(ctx context.Context, ids []string) (map[string]PublicUserRef, error)
	// UserLivenessByIDs is the batch account-liveness read behind verify's
	// per-request liveness gate (#267): the same ban/deleted/reserved verdict
	// that guards token mint, plus the identity fields (username, email,
	// email_verified, avatar) fresh as of that lookup — so a host has no reason
	// to call the admin directory to refresh display claims on a hot path.
	// Errors PROPAGATE so authorization callers fail closed; unknown ids are
	// absent from the map and a gate must treat that as a denial.
	UserLivenessByIDs(ctx context.Context, ids []string) (map[string]UserLiveness, error)
}

// Passwords is the password credential import surface.
type Passwords interface {
	UpsertPasswordHash(ctx context.Context, userID, hash, algo string, params []byte) error
}

// Admin is the intrinsic admin view of the user directory: list, inspect, ban,
// and admin-side session/password control.
type Admin interface {
	AdminGetUser(ctx context.Context, id string) (*AdminUser, error)
	AdminListUsers(ctx context.Context, opts AdminUserListOptions) (*AdminListUsersResult, error)
	AdminRevokeUserSessions(ctx context.Context, userID string) error
	AdminSetPassword(ctx context.Context, userID, new string) error
	BanUser(ctx context.Context, userID string, reason *string, until *time.Time, bannedBy string) error
	UnbanUser(ctx context.Context, userID string) error
}

// Roles is global root-role assignment, actor-checked (no-escalation) only. The
// unchecked bootstrap/genesis equivalents (AssignRoleBySlug, RemoveRoleBySlug)
// are NOT part of this in-process/RPC-swappable interface (#241) — they live on
// embedded.Client.Genesis(), an explicitly-dangerous seam reached only by the
// concrete embedded client, never through authkit.Client.
type Roles interface {
	// Assign/RemoveRolesBySlugAs are batch-native (#219/#222): the actor-checked
	// no-escalation authority check (#136) runs PER ITEM inside the batch — an
	// actor may hold authority over some targets and not others, and each item's
	// OpResult carries its own ErrInsufficientRoleAuthority/ErrRoleAssignmentEscalation.
	// Per-item best-effort; single-item = one-element slice.
	AssignRolesBySlugAs(ctx context.Context, actorUserID string, userIDs []string, role Role) ([]OpResult, error)
	RemoveRolesBySlugAs(ctx context.Context, actorUserID string, userIDs []string, role Role) ([]OpResult, error)
	UpsertRoleBySlug(ctx context.Context, name string, role Role, description *string) error
	// RoleSlugsByUsers returns each user's LIVE configured root permission-group
	// role slugs in ONE call — batch-native per the operation-shape rule (#219,
	// #220; replaces ListRoleSlugsByUser + ListRoleSlugsByUserErr). The map is
	// keyed by user id; users with no roles are absent. Errors PROPAGATE so authz
	// callers fail closed (#136) instead of reading an outage as "no roles".
	// Single-user = one-element slice + m[id].
	RoleSlugsByUsers(ctx context.Context, userIDs []string) (map[string][]string, error)
}

// Groups is the permission-group surface: lifecycle, membership, role
// assignment, authorization checks, and invite links. Role/subject mutation
// here is actor-checked (no-escalation) only; the unchecked bootstrap/genesis
// equivalent (AssignGroupRole) lives on embedded.Client.Genesis() (#241), not
// on this interface.
type Groups interface {
	CreatePermissionGroup(ctx context.Context, req CreatePermissionGroupRequest) (string, error)
	EnsureRootGroup(ctx context.Context) (string, error)
	SeedPermissionGroupContainment(ctx context.Context) error
	ResolveGroupIDForSlug(ctx context.Context, group GroupRef) (string, error)
	GroupInstanceForSlug(ctx context.Context, group GroupRef) (GroupInstance, error)
	GroupInstanceByID(ctx context.Context, groupID string) (GroupInstance, error)
	AssignGroupRoleAs(ctx context.Context, actorUserID string, group GroupRef, subject Subject, role Role) error
	UnassignGroupRoleAs(ctx context.Context, actorUserID string, group GroupRef, subject Subject, role Role) error
	RemoveGroupSubjectAs(ctx context.Context, actorUserID string, group GroupRef, subject Subject) error
	ListGroupMembers(ctx context.Context, group GroupRef) ([]GroupMember, error)
	ListSubjectGroups(ctx context.Context, subject Subject) ([]SubjectGroupMembership, error)
	Can(ctx context.Context, subject Subject, group GroupRef, perm Perm) (bool, error)
	CanOnGroup(ctx context.Context, subject Subject, groupID string, perm Perm) (bool, error)
	ListEffectivePermissions(ctx context.Context, subject Subject, group GroupRef) ([]string, error)
	CreateGroupInviteLink(ctx context.Context, req CreateGroupInviteLinkRequest) (GroupInviteLinkCreated, error)
	ListGroupInviteLinks(ctx context.Context, group GroupRef) ([]GroupInviteLink, error)
	RevokeGroupInviteLink(ctx context.Context, group GroupRef, linkID string) error
	ExternalInvitesEnabled() bool
}

// Tokens issues the app's JWTs: access, service, and remote-application.
type Tokens interface {
	// MintAccessToken signs a user access JWT (#214: Mint* = signing a JWT;
	// session creation — IssueRefreshSession* on the engine — is not a Mint).
	MintAccessToken(ctx context.Context, userID string, extra map[string]any) (string, time.Time, error)
	MintRemoteApplicationAccessToken(ctx context.Context, p RemoteApplicationAccessParams) (string, error)
	MintServiceJWT(ctx context.Context, opts ServiceJWTMintOptions) (string, ServiceJWTClaims, error)
}

// Documents signs immutable opaque JSON envelopes with the service's current
// AuthKit key. Verification and resolution live in documents + verify.
type Documents interface {
	SignDocument(ctx context.Context, envelope DocumentEnvelope) (SignedDocument, error)
}

// APIKeys mints, lists, revokes, and resolves opaque API keys.
type APIKeys interface {
	MintAPIKeyWithOptions(ctx context.Context, group GroupRef, opts APIKeyMintOptions) (APIKey, string, error)
	ListAPIKeys(ctx context.Context, group GroupRef) ([]APIKey, error)
	RevokeAPIKey(ctx context.Context, group GroupRef, tokenID string) (bool, error)
	ResolveAPIKey(ctx context.Context, keyID, secret string) (string, []string, error)
	ResolveAPIKeyDetailed(ctx context.Context, keyID, secret string) (ResolvedAPIKey, error)
}

// Providers links external identity providers to an account.
type Providers interface {
	// ImportUnverifiedSolanaLinks preserves host migration associations without
	// turning them into credentials. Only a subsequent SIWS proof verifies a link.
	ImportUnverifiedSolanaLinks(ctx context.Context, inputs []ImportUnverifiedSolanaLinkInput) (ImportUnverifiedSolanaLinksResult, error)
	LinkProviderByIssuer(ctx context.Context, userID, issuer, providerSlug, subject string, email *string) error
}

// RemoteApps manages trusted remote applications (federation issuers) and
// resolves their stored authority.
type RemoteApps interface {
	UpsertRemoteApplication(ctx context.Context, in RemoteApplication) (*RemoteApplication, error)
	GetRemoteApplication(ctx context.Context, issuer string) (*RemoteApplication, error)
	ListRemoteApplications(ctx context.Context) ([]RemoteApplication, error)
	ListEnabledRemoteApplications(ctx context.Context) ([]RemoteApplication, error)
	ResolveRemoteApplicationAuthority(ctx context.Context, appID string) (RemoteApplicationAuthority, error)
	ResolveRemoteAppAttributeDef(ctx context.Context, appID, key string, version int32) (*RemoteAppAttributeDef, error)
}

// Passwordless (email/SMS code/link login) is deliberately NOT on the Client
// contract: the end user completes it in a browser via the /passwordless/* routes,
// so it is an HTTP-layer flow (layer test, SEMVER §4.2), not a backend embedder
// capability. The engine impl stays on *authcore.Service; the routes call it there.
// The Passwordless{Start,Confirm}* DTOs remain public for the HTTP request/response.

// Bootstrap applies a parsed bootstrap manifest (operator/deploy seeding).
type Bootstrap interface {
	// ApplyBootstrapManifest applies a parsed manifest. There is deliberately no
	// ApplyBootstrapManifestFile on the contract: hosts with a file load it
	// themselves (e.g. embedded.LoadBootstrapManifestFile) then call this.
	ApplyBootstrapManifest(ctx context.Context, manifest BootstrapManifest, opts BootstrapReconcileOptions) (BootstrapManifestResult, error)
}

// Senders reports whether the configured message senders are available and
// healthy.
type Senders interface {
	HasEmailSender() bool
	HasSMSSender() bool
	SMSAvailable() bool
	CheckSMSHealth(ctx context.Context) error
}

// Entitlements reads a user's active entitlement names from the host-provided
// EntitlementsProvider.
type Entitlements interface {
	ListEntitlements(ctx context.Context, userID string) []string
}

// Maintenance is operational upkeep run outside a request: expire stale auth
// state, validate the verification configuration.
type Maintenance interface {
	CleanupExpiredAuthState(ctx context.Context) error
	ValidateVerificationConfiguration() error
}

// Client is the contract hosts hold: the in-process operations composed from
// the topic interfaces above. Infra accessors (Postgres, JWKS, raw
// Options/Schema) are deliberately OFF this interface; they stay on the
// concrete *embedded.Client.
//
//	c, err := embedded.New(cfg, pg)
//	var _ authkit.Client = c
type Client interface {
	Users
	Passwords
	Admin
	Roles
	Groups
	Tokens
	Documents
	APIKeys
	Providers
	RemoteApps
	Bootstrap
	Senders
	Entitlements
	Maintenance
}
