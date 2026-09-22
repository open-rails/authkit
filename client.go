package authkit

import (
	"context"
	"time"
)

// Client is the portable application operation contract returned by
// embedded.Runtime.Client. The local implementation calls the private engine
// directly; a future remote implementation can preserve these typed operations.
// Inputs and results carry no process resources. Privileged operations require
// trusted host authority; this contract does not expose them over HTTP.
// Adding methods changes the contract implemented by consumer fakes.
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
	// ListUsersDeletedBefore lists accounts deleted before cutoff whose
	// erasure obligation EVERY required site acknowledged (see the erasure
	// section) — the purge-ready set, not every soft-deleted account. An
	// unacknowledged account is retained and never listed, so the page
	// advances whatever the backlog size. To discover deletions this site
	// must act on, use ListErasureObligations.
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
	UpsertPasswordHash(ctx context.Context, userID, hash, algo string) error

	// --- cross-site erasure (one obligation per deleted account, one
	// acknowledgement per TokenConfig.AccountIssuers entry) ---
	// ListErasureObligations pages, oldest first, the deleted accounts site
	// (normally this deployment's Token.Issuer) has not acknowledged. after is
	// "" for the first page; next is "" on the last one.
	ListErasureObligations(ctx context.Context, site, after string, limit int) (page []ErasureObligation, next string, err error)
	// AcknowledgeErasure records that site durably accepted the obligation
	// into its own ledger — not that it erased anything. Idempotent; a site
	// the obligation does not require is a no-op. Once every required issuer
	// acknowledged, purge may remove the identity and the obligation closes.
	AcknowledgeErasure(ctx context.Context, site, userID string) error
	// ErasureBacklog reports unacknowledged obligations per site with the
	// oldest pending creation time (the age bound).
	ErasureBacklog(ctx context.Context) ([]ErasureSiteBacklog, error)

	// --- admin directory ---
	AdminGetUser(ctx context.Context, id string) (*AdminUser, error)
	AdminListUsers(ctx context.Context, opts AdminUserListOptions) (*AdminListUsersResult, error)
	// AdminRevokeAccountSessions revokes the user's refresh sessions on every
	// account issuer plus device keys. Unchecked: the host authorizes the actor.
	AdminRevokeAccountSessions(ctx context.Context, userID string) (AccountSessionRevocation, error)
	AdminSetPassword(ctx context.Context, userID, new string) error
	// AdminAssignGroupRole and AdminUnassignGroupRole use trusted host-operator
	// authority, like AdminSetPassword. Hosts authorize the operator; request
	// actors use the corresponding actor-checked *As methods. Subject MFA and
	// final-owner invariants still apply. These methods add no HTTP exposure.
	AdminAssignGroupRole(ctx context.Context, group GroupRef, subject Subject, role Role) error
	AdminUnassignGroupRole(ctx context.Context, group GroupRef, subject Subject, role Role) error
	BanUser(ctx context.Context, userID string, reason *string, until *time.Time, bannedBy string) error
	UnbanUser(ctx context.Context, userID string) error

	// --- root roles (actor-checked) ---
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
	ResolveGroupIDForSlug(ctx context.Context, group GroupRef) (string, error)
	GroupInstanceForSlug(ctx context.Context, group GroupRef) (GroupInstance, error)
	UpdateGroupInstanceAs(ctx context.Context, actorUserID, groupID string, update GroupInstanceUpdate) (GroupInstance, error)
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
}
