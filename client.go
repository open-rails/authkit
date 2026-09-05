package authkit

import (
	"context"
	"time"
)

// Client is the contract hosts hold: the in-process operations a host calls
// on the engine, one flat interface grounded in what the consumers actually
// use (ak#289). *embedded.Client implements it. Infra accessors (Postgres,
// JWKS, Config, Schema), the browser-flow methods the authhttp transport
// drives, the passkey ceremonies and the unchecked Genesis() seam are
// deliberately OFF this interface — they stay on the concrete *embedded.Client.
// Adding a method is MAJOR: consumers implement it in fakes.
//
//	c, err := embedded.New(cfg, deps)
//	var _ authkit.Client = c
type Client interface {
	// --- users ---
	CreateUser(ctx context.Context, email, username string) (*User, error)
	GetUserByEmail(ctx context.Context, email string) (*User, error)
	GetUserByPhone(ctx context.Context, phone string) (*User, error)
	GetUserByUsername(ctx context.Context, username string) (*User, error)
	// {Hard,Soft}DeleteUsers are batch-native admin bulk mutations (#219/#222):
	// per-item BEST-EFFORT — the returned OpResults pinpoint the failures; the
	// outer error is a whole-call failure only (e.g. no store).
	HardDeleteUsers(ctx context.Context, userIDs []string) ([]OpResult, error)
	SoftDeleteUsers(ctx context.Context, userIDs []string) ([]OpResult, error)
	MarkEmailVerified(ctx context.Context, id string) error
	// UpdateAvatarURL sets (or clears, with nil) the user's avatar URL/key
	// string (#262). Blob storage/validation is the host's job.
	UpdateAvatarURL(ctx context.Context, id string, avatarURL *string) error
	UpdateEmail(ctx context.Context, id, email string) error
	UpdateUsername(ctx context.Context, id, username string) error
	UpdateImportedUser(ctx context.Context, userID string, input ImportUserInput) (*User, error)
	ImportUsers(ctx context.Context, inputs []ImportUserInput) (ImportUsersResult, error)
	ListUsersDeletedBefore(ctx context.Context, cutoff time.Time, limit int) ([]string, error)
	// UsersByIDs resolves many user IDs to slim display projections in ONE
	// query; missing IDs are absent. PRIVILEGED — the projection carries Email;
	// render other users with PublicUsersByIDs.
	UsersByIDs(ctx context.Context, ids []string) (map[string]UserRef, error)
	// PublicUsersByIDs is the PUBLIC-SAFE twin (#268): no email; soft-deleted
	// users come back as tombstones, banned users normally, unknown ids absent.
	PublicUsersByIDs(ctx context.Context, ids []string) (map[string]PublicUserRef, error)
	// UserLivenessByIDs is the batch account-liveness read behind verify's
	// per-request liveness gate (#267). Errors PROPAGATE so authorization
	// callers fail closed; unknown ids are absent and a gate treats that as a
	// denial.
	UserLivenessByIDs(ctx context.Context, ids []string) (map[string]UserLiveness, error)
	UpsertPasswordHash(ctx context.Context, userID, hash, algo string, params []byte) error

	// --- admin directory ---
	AdminGetUser(ctx context.Context, id string) (*AdminUser, error)
	AdminListUsers(ctx context.Context, opts AdminUserListOptions) (*AdminListUsersResult, error)
	AdminRevokeUserSessions(ctx context.Context, userID string) error
	AdminSetPassword(ctx context.Context, userID, new string) error
	BanUser(ctx context.Context, userID string, reason *string, until *time.Time, bannedBy string) error
	UnbanUser(ctx context.Context, userID string) error

	// --- root roles (actor-checked; the unchecked genesis forms live on
	// embedded.Client.Genesis(), #241) ---
	// Assign/RemoveRolesBySlugAs are batch-native (#219/#222): the no-escalation
	// check (#136) runs PER ITEM and each OpResult carries its own authority error.
	AssignRolesBySlugAs(ctx context.Context, actorUserID string, userIDs []string, role Role) ([]OpResult, error)
	RemoveRolesBySlugAs(ctx context.Context, actorUserID string, userIDs []string, role Role) ([]OpResult, error)
	UpsertRoleBySlug(ctx context.Context, name string, role Role, description *string) error
	// RoleSlugsByUsers returns each user's LIVE configured root role slugs in
	// ONE call (#220); users with no roles are absent; errors PROPAGATE (#136).
	RoleSlugsByUsers(ctx context.Context, userIDs []string) (map[string][]string, error)

	// --- permission groups ---
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

	// --- tokens (#214: Mint* = signing a JWT; session creation is not a Mint) ---
	MintAccessToken(ctx context.Context, userID string, extra map[string]any) (string, time.Time, error)
	MintRemoteApplicationAccessToken(ctx context.Context, p RemoteApplicationAccessParams) (string, error)
	MintServiceJWT(ctx context.Context, opts ServiceJWTMintOptions) (string, ServiceJWTClaims, error)

	// --- API keys ---
	MintAPIKeyWithOptions(ctx context.Context, group GroupRef, opts APIKeyMintOptions) (APIKey, string, error)
	ListAPIKeys(ctx context.Context, group GroupRef) ([]APIKey, error)
	RevokeAPIKey(ctx context.Context, group GroupRef, tokenID string) (bool, error)
	ResolveAPIKey(ctx context.Context, keyID, secret string) (string, []string, error)

	// --- identity providers ---
	// ImportUnverifiedSolanaLinks preserves host migration associations without
	// turning them into credentials; only a subsequent SIWS proof verifies a link.
	ImportUnverifiedSolanaLinks(ctx context.Context, inputs []ImportUnverifiedSolanaLinkInput) (ImportUnverifiedSolanaLinksResult, error)
	LinkProviderByIssuer(ctx context.Context, userID, issuer, providerSlug, subject string, email *string) error

	// --- remote applications (federation issuers) ---
	UpsertRemoteApplication(ctx context.Context, in RemoteApplication) (*RemoteApplication, error)
	GetRemoteApplication(ctx context.Context, issuer string) (*RemoteApplication, error)
	ResolveRemoteApplicationAuthority(ctx context.Context, appID string) (RemoteApplicationAuthority, error)

	// --- bootstrap: hosts with a file load it themselves
	// (embedded.LoadBootstrapManifestFile) then apply it ---
	ApplyBootstrapManifest(ctx context.Context, manifest BootstrapManifest, opts BootstrapReconcileOptions) (BootstrapManifestResult, error)

	// --- senders + upkeep ---
	HasEmailSender() bool
	HasSMSSender() bool
	SMSAvailable() bool
	CheckSMSHealth(ctx context.Context) error
	CleanupExpiredAuthState(ctx context.Context) error
	ValidateVerificationConfiguration() error
}
