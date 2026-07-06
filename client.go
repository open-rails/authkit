package authkit

// The remote SDK (authkit/remote) and the management-API registry (authkit/server)
// are GENERATED from the Client interface below; regenerate after changing it:
//
//go:generate go run ./internal/genremote

import (
	"context"
	"time"
)

// Client is composed from the small topic interfaces below (#143). Each one is a
// cohesive slice a host can depend on instead of the whole surface: a login
// service needs Users + Passwords, a token layer needs Tokens, an authorization
// layer needs Groups. Client embeds all of them for the full swap seam, and the
// generator flattens the embedded set, so the remote/server transport is
// generated method-for-method exactly as if Client were one flat interface.

// Users is account create/read/update/delete, identity lookups, metadata, and
// bulk import/read.
type Users interface {
	CreateUser(ctx context.Context, email, username string) (*User, error)
	GetUserByEmail(ctx context.Context, email string) (*User, error)
	GetUserByPhone(ctx context.Context, phone string) (*User, error)
	GetUserBySolanaAddress(ctx context.Context, address string) (*User, error)
	GetUserByUsername(ctx context.Context, username string) (*User, error)
	GetUserMetadata(ctx context.Context, userID string) (map[string]any, error)
	PatchUserMetadata(ctx context.Context, userID string, patch map[string]any) error
	// {Hard,Soft}DeleteUsers / RestoreUsers are batch-native admin bulk mutations
	// (#219/#222): per-item BEST-EFFORT — deleting 99 of 100 succeeds item-by-item
	// and the returned OpResults pinpoint the failures. Single-item = one-element
	// slice. The outer error is a whole-call failure only (e.g. no store).
	// SetEmailVerified / UpdateEmail / UpdateUsername stay single by decision:
	// they are per-subject correctness flows, not bulk admin operations.
	HardDeleteUsers(ctx context.Context, userIDs []string) ([]OpResult, error)
	SoftDeleteUsers(ctx context.Context, userIDs []string) ([]OpResult, error)
	RestoreUsers(ctx context.Context, userIDs []string) ([]OpResult, error)
	SetEmailVerified(ctx context.Context, id string, v bool) error
	UpdateBiography(ctx context.Context, id string, bio *string) error
	UpdateEmail(ctx context.Context, id, email string) error
	UpdateUsername(ctx context.Context, id, username string) error
	UpdateImportedUser(ctx context.Context, userID string, input ImportUserInput) (*User, error)
	ImportUsers(ctx context.Context, inputs []ImportUserInput) (ImportUsersResult, error)
	ListUsersDeletedBefore(ctx context.Context, cutoff time.Time, limit int) ([]string, error)
	TimeUntilUsernameRenameAvailable(ctx context.Context, userID string, now time.Time) (int64, error)
	IsUserAllowed(ctx context.Context, userID string) (bool, error)
	// UsersByIDs resolves many user IDs to slim display projections (id +
	// username/email) in ONE query: the batch read for "render N authors"
	// without N+1. Missing IDs are simply absent from the result. (Replaces the
	// removed authkit/identity store; writes go through UpdateUsername/UpdateEmail,
	// which enforce the rename cooldown + validation raw table writes skip.)
	// Returns map[id]UserRef (#219/#220): O(1) single-item access, missing IDs absent.
	UsersByIDs(ctx context.Context, ids []string) (map[string]UserRef, error)
}

// Passwords is the password credential surface: change, import, verify.
type Passwords interface {
	ChangePassword(ctx context.Context, userID, current, new string, keepSessionID *string) error
	UpsertPasswordHash(ctx context.Context, userID, hash, algo string, params []byte) error
	VerifyUserPassword(ctx context.Context, userID, pass string) bool
}

// Admin is the intrinsic admin view of the user directory: list, inspect, ban,
// and admin-side session/password control.
type Admin interface {
	AdminCountUsers(ctx context.Context, opts AdminUserListOptions) (int64, error)
	AdminGetUser(ctx context.Context, id string) (*AdminUser, error)
	AdminListUserSessions(ctx context.Context, userID string) ([]Session, error)
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
// concrete embedded client, never through authkit.Client or the remote transport.
type Roles interface {
	// Assign/RemoveRolesBySlugAs are batch-native (#219/#222): the actor-checked
	// no-escalation authority check (#136) runs PER ITEM inside the batch — an
	// actor may hold authority over some targets and not others, and each item's
	// OpResult carries its own ErrInsufficientRoleAuthority/ErrRoleAssignmentEscalation.
	// Per-item best-effort; single-item = one-element slice.
	AssignRolesBySlugAs(ctx context.Context, actorUserID string, userIDs []string, slug string) ([]OpResult, error)
	RemoveRolesBySlugAs(ctx context.Context, actorUserID string, userIDs []string, slug string) ([]OpResult, error)
	UpsertRoleBySlug(ctx context.Context, name, slug string, description *string) error
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
	ResolveGroupIDForSlug(ctx context.Context, persona, instanceSlug string) (string, error)
	CreateAccountRegistrationInvite(ctx context.Context, req CreateAccountRegistrationInviteRequest) (AccountRegistrationInviteCreated, error)
	RevokeAccountRegistrationInvite(ctx context.Context, inviteID, actorUserID string) error
	AssignGroupRoleAs(ctx context.Context, actorUserID, persona, instanceSlug, subjectID, subjectKind, role string) error
	UnassignGroupRoleAs(ctx context.Context, actorUserID, persona, instanceSlug, subjectID, subjectKind, role string) error
	RemoveGroupSubjectAs(ctx context.Context, actorUserID, persona, instanceSlug, subjectID, subjectKind string) error
	LeaveGroup(ctx context.Context, userID, persona, instanceSlug string) error
	ListGroupMembers(ctx context.Context, persona, instanceSlug string) ([]GroupMember, error)
	ListSubjectGroups(ctx context.Context, subjectID, subjectKind string) ([]SubjectGroupMembership, error)
	Can(ctx context.Context, subjectID, subjectKind, persona, instanceSlug, perm string) (bool, error)
	ListEffectivePermissions(ctx context.Context, subjectID, subjectKind, persona, instanceSlug string) ([]string, error)
	CreateGroupInviteLink(ctx context.Context, req CreateGroupInviteLinkRequest) (GroupInviteLinkCreated, error)
	ListGroupInviteLinks(ctx context.Context, persona, instanceSlug string) ([]GroupInviteLink, error)
	RevokeGroupInviteLink(ctx context.Context, persona, instanceSlug, linkID string) error
	RedeemGroupInviteLink(ctx context.Context, code, redeemerUserID string) (RedeemGroupInviteLinkResult, error)
	ExternalInvitesEnabled() bool
}

// Tokens issues the app's JWTs: access, service, delegated, remote-application,
// and custom.
type Tokens interface {
	// MintAccessToken signs a user access JWT (#214: Mint* = signing a JWT;
	// session creation — IssueRefreshSession* on the engine — is not a Mint).
	MintAccessToken(ctx context.Context, userID string, extra map[string]any) (string, time.Time, error)
	MintCustomJWT(ctx context.Context, opts CustomJWTMintOptions) (string, error)
	MintDelegatedAccessToken(ctx context.Context, p DelegatedAccessParams) (string, error)
	MintRemoteApplicationAccessToken(ctx context.Context, p RemoteApplicationAccessParams) (string, error)
	MintServiceJWT(ctx context.Context, opts ServiceJWTMintOptions) (string, ServiceJWTClaims, error)
}

// APIKeys mints, lists, revokes, and resolves opaque API keys.
type APIKeys interface {
	MintAPIKey(ctx context.Context, persona, instanceSlug, name, role, createdBy string, expiresAt *time.Time) (APIKey, string, error)
	MintAPIKeyWithOptions(ctx context.Context, persona, instanceSlug string, opts APIKeyMintOptions) (APIKey, string, error)
	ListAPIKeys(ctx context.Context, persona, instanceSlug string) ([]APIKey, error)
	RevokeAPIKey(ctx context.Context, persona, instanceSlug, tokenID string) (bool, error)
	ResolveAPIKey(ctx context.Context, keyID, secret string) (string, []string, error)
	ResolveAPIKeyDetailed(ctx context.Context, keyID, secret string) (ResolvedAPIKey, error)
}

// Sessions is the backend session surface: list and revoke-all. Refresh-token
// EXCHANGE is deliberately NOT here — it is a browser/end-user request flow served
// by the /token endpoint, so it lives on the HTTP layer only (layer test, SEMVER
// §4.2). The engine impl stays on *authcore.Service; authkit's own /token handler
// calls it there via embedded.Unwrap.
type Sessions interface {
	ListUserSessions(ctx context.Context, userID string) ([]Session, error)
	RevokeAllSessions(ctx context.Context, userID string, keepSessionID *string) error
}

// Providers links and unlinks external identity providers on an account.
type Providers interface {
	LinkProvider(ctx context.Context, userID, provider, subject string, email *string) error
	LinkProviderByIssuer(ctx context.Context, userID, issuer, providerSlug, subject string, email *string) error
	UnlinkProvider(ctx context.Context, userID, provider string) error
	// ProviderUsernames returns each user's stored username for the given
	// provider in ONE call (#219/#220; replaces the single GetProviderUsername).
	// Map keyed by user id; users without a stored username are absent.
	ProviderUsernames(ctx context.Context, userIDs []string, provider string) (map[string]string, error)
}

// RemoteApps manages trusted remote applications (federation issuers) and
// resolves their stored authority.
type RemoteApps interface {
	UpsertRemoteApplication(ctx context.Context, in RemoteApplication) (*RemoteApplication, error)
	GetRemoteApplication(ctx context.Context, issuer string) (*RemoteApplication, error)
	DeleteRemoteApplication(ctx context.Context, issuer string) error
	ListRemoteApplications(ctx context.Context, activeOnly bool) ([]RemoteApplication, error)
	ResolveRemoteApplicationAuthority(ctx context.Context, appID string) ([]string, error)
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
	// ApplyBootstrapManifestFile on the contract: a file path is the SERVER's
	// filesystem, meaningless over a remote transport (#142). Hosts with a file
	// load it themselves (e.g. embedded.LoadBootstrapManifestFile) then call this.
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

// Client is the portable AuthKit contract: the full set of operations meaningful
// across both the in-process (embedded) and the Phase-2 remote transports (issue
// #138), composed from the topic interfaces above. Infra accessors (Postgres,
// Keyfunc, JWKS, raw Options/Schema) are deliberately OFF this interface; they
// stay on the concrete *embedded.Client. Code against authkit.Client (or one of
// the topic interfaces) so swapping backends is construction-only:
//
//	c, err := embedded.New(cfg, pg) // today (in-process)
//	var _ authkit.Client = c
//	// c, err := remote.New(url, creds) // Phase 2 (standalone)
type Client interface {
	Users
	Passwords
	Admin
	Roles
	Groups
	Tokens
	APIKeys
	Sessions
	Providers
	RemoteApps
	Bootstrap
	Senders
	Entitlements
	Maintenance
}
