package authkit

// The remote SDK (authkit/remote) and the management-API registry (authkit/server)
// are GENERATED from the Client interface below — regenerate after changing it:
//
//go:generate go run ./internal/genremote

import (
	"context"
	"net"
	"time"
)

// Client is the portable AuthKit contract — the curated subset of operations
// meaningful across both the in-process (embedded) and the Phase-2 remote
// transports (issue #138). Infra accessors (Postgres, Keyfunc, JWKS, raw
// Options/Schema) are deliberately OFF this interface; they stay on the concrete
// *embedded.Client. Code against authkit.Client so swapping backends is
// construction-only:
//
//	var c authkit.Client = embedded.New(cfg, pg)     // today (in-process)
//	// var c authkit.Client = remote.New(url, creds) // Phase 2 (standalone)
type Client interface {
	AdminCountUsers(ctx context.Context, opts AdminUserListOptions) (int64, error)
	AdminGetUser(ctx context.Context, id string) (*AdminUser, error)
	AdminListUserSessions(ctx context.Context, userID string) ([]Session, error)
	AdminListUsers(ctx context.Context, opts AdminUserListOptions) (*AdminListUsersResult, error)
	AdminRevokeUserSessions(ctx context.Context, userID string) error
	AdminSetPassword(ctx context.Context, userID, new string) error
	AssignRoleBySlug(ctx context.Context, userID, slug string) error
	AssignGroupRole(ctx context.Context, persona, instanceSlug, subjectID, subjectKind, role string) error
	AssignRoleBySlugAs(ctx context.Context, actorUserID, userID, slug string) error
	RemoveRoleBySlugAs(ctx context.Context, actorUserID, userID, slug string) error
	AssignGroupRoleAs(ctx context.Context, actorUserID, persona, instanceSlug, subjectID, subjectKind, role string) error
	UnassignGroupRoleAs(ctx context.Context, actorUserID, persona, instanceSlug, subjectID, subjectKind, role string) error
	RemoveGroupSubjectAs(ctx context.Context, actorUserID, persona, instanceSlug, subjectID, subjectKind string) error
	ListRoleSlugsByUserErr(ctx context.Context, userID string) ([]string, error)
	CreateGroupInviteLink(ctx context.Context, req CreateGroupInviteLinkRequest) (GroupInviteLinkCreated, error)
	ListGroupInviteLinks(ctx context.Context, persona, instanceSlug string) ([]GroupInviteLink, error)
	RevokeGroupInviteLink(ctx context.Context, persona, instanceSlug, linkID string) error
	RedeemGroupInviteLink(ctx context.Context, code, redeemerUserID string) (RedeemGroupInviteLinkResult, error)
	ExternalInvitesEnabled() bool
	BanUser(ctx context.Context, userID string, reason *string, until *time.Time, bannedBy string) error
	Can(ctx context.Context, subjectID, subjectKind, persona, instanceSlug, perm string) (bool, error)
	ListEffectivePermissions(ctx context.Context, subjectID, subjectKind, persona, instanceSlug string) ([]string, error)
	ChangePassword(ctx context.Context, userID, current, new string, keepSessionID *string) error
	CheckSMSHealth(ctx context.Context) error
	CleanupExpiredAuthState(ctx context.Context) error
	CreatePermissionGroup(ctx context.Context, req CreatePermissionGroupRequest) (string, error)
	CreateUser(ctx context.Context, email, username string) (*User, error)
	DeleteRemoteApplication(ctx context.Context, issuer string) error
	EnsureRootGroup(ctx context.Context) (string, error)
	ExchangeRefreshToken(ctx context.Context, refreshToken string, ua string, ip net.IP) (string, time.Time, string, error)
	GetEmailByUserID(ctx context.Context, id string) (string, error)
	GetProviderUsername(ctx context.Context, userID, provider string) (string, error)
	GetUserMetadata(ctx context.Context, userID string) (map[string]any, error)
	GetRemoteApplication(ctx context.Context, issuer string) (*RemoteApplication, error)
	GetUserByEmail(ctx context.Context, email string) (*User, error)
	GetUserByPhone(ctx context.Context, phone string) (*User, error)
	GetUserBySolanaAddress(ctx context.Context, address string) (*User, error)
	GetUserByUsername(ctx context.Context, username string) (*User, error)
	HardDeleteUser(ctx context.Context, userID string) error
	HasEmailSender() bool
	HasSMSSender() bool
	ImportUsers(ctx context.Context, inputs []ImportUserInput) (ImportUsersResult, error)
	IsUserAllowed(ctx context.Context, userID string) (bool, error)
	IssueAccessToken(ctx context.Context, userID, email string, extra map[string]any) (string, time.Time, error)
	LinkProvider(ctx context.Context, userID, provider, subject string, email *string) error
	LinkProviderByIssuer(ctx context.Context, userID, issuer, providerSlug, subject string, email *string) error
	ListAPIKeys(ctx context.Context, persona, instanceSlug string) ([]APIKey, error)
	ListEntitlements(ctx context.Context, userID string) []string
	ListGroupMembers(ctx context.Context, persona, instanceSlug string) ([]GroupMember, error)
	ListSubjectGroups(ctx context.Context, subjectID, subjectKind string) ([]SubjectGroupMembership, error)
	ListRemoteApplications(ctx context.Context, activeOnly bool) ([]RemoteApplication, error)
	ListRoleSlugsByUser(ctx context.Context, userID string) []string
	ListUserSessions(ctx context.Context, userID string) ([]Session, error)
	ListUsersDeletedBefore(ctx context.Context, cutoff time.Time, limit int) ([]string, error)
	MintAPIKey(ctx context.Context, persona, instanceSlug, name, role, createdBy string, expiresAt *time.Time) (APIKey, string, error)
	MintAPIKeyWithOptions(ctx context.Context, persona, instanceSlug string, opts APIKeyMintOptions) (APIKey, string, error)
	MintCustomJWT(ctx context.Context, opts CustomJWTMintOptions) (string, error)
	MintDelegatedAccessToken(ctx context.Context, p DelegatedAccessParams) (string, error)
	MintRemoteApplicationAccessToken(ctx context.Context, p RemoteApplicationAccessParams) (string, error)
	MintServiceJWT(ctx context.Context, opts ServiceJWTMintOptions) (string, ServiceJWTClaims, error)
	PatchUserMetadata(ctx context.Context, userID string, patch map[string]any) error
	StartPasswordless(ctx context.Context, req PasswordlessStartRequest) (PasswordlessStartResult, error)
	ConfirmPasswordlessCode(ctx context.Context, identifier, code string) (PasswordlessConfirmResult, error)
	ConfirmPasswordlessToken(ctx context.Context, token string) (PasswordlessConfirmResult, error)
	RecordFailedPasswordlessCode(ctx context.Context, identifier string)
	ClearPasswordlessCodeAttempts(ctx context.Context, identifier string)
	// ApplyBootstrapManifest applies a parsed manifest. There is deliberately no
	// ApplyBootstrapManifestFile on the contract: a file path is the SERVER's
	// filesystem, meaningless over a remote transport (#142). Hosts with a file
	// load it themselves (e.g. embedded.LoadBootstrapManifestFile) then call this.
	ApplyBootstrapManifest(ctx context.Context, manifest BootstrapManifest, opts BootstrapReconcileOptions) (BootstrapManifestResult, error)
	RemoveRoleBySlug(ctx context.Context, userID, slug string) error
	ResolveAPIKey(ctx context.Context, keyID, secret string) (string, []string, error)
	ResolveAPIKeyWithResources(ctx context.Context, keyID, secret string) (ResolvedAPIKey, error)
	ResolveGroupIDForSlug(ctx context.Context, persona, instanceSlug string) (string, error)
	ResolveRemoteAppAttributeDef(ctx context.Context, appID, key string, version int32) (*RemoteAppAttributeDef, error)
	ResolveRemoteApplicationAuthority(ctx context.Context, appID string) ([]string, error)
	RestoreUser(ctx context.Context, id string) error
	RevokeAPIKey(ctx context.Context, persona, instanceSlug, tokenID string) (bool, error)
	RevokeAllSessions(ctx context.Context, userID string, keepSessionID *string) error
	SMSAvailable() bool
	SeedPermissionGroupContainment(ctx context.Context) error
	SetEmailVerified(ctx context.Context, id string, v bool) error
	SoftDeleteUser(ctx context.Context, id string) error
	TimeUntilUsernameRenameAvailable(ctx context.Context, userID string, now time.Time) (int64, error)
	UnbanUser(ctx context.Context, userID string) error
	UnlinkProvider(ctx context.Context, userID, provider string) error
	UpdateBiography(ctx context.Context, id string, bio *string) error
	UpdateEmail(ctx context.Context, id, email string) error
	UpdateImportedUser(ctx context.Context, userID string, input ImportUserInput) (*User, error)
	UpdateUsername(ctx context.Context, id, username string) error
	UpsertPasswordHash(ctx context.Context, userID, hash, algo string, params []byte) error
	UpsertRemoteApplication(ctx context.Context, in RemoteApplication) (*RemoteApplication, error)
	UpsertRoleBySlug(ctx context.Context, name, slug string, description *string) error
	ValidateVerificationConfiguration() error
	VerifyUserPassword(ctx context.Context, userID, pass string) bool

	// UsersByIDs resolves many user IDs to slim display projections (id +
	// username/email) in ONE query — the batch read for "render N authors"
	// without N+1. Missing IDs are simply absent from the result. (Replaces the
	// removed authkit/identity store; writes go through UpdateUsername/UpdateEmail,
	// which enforce the rename cooldown + validation raw table writes skip.)
	UsersByIDs(ctx context.Context, ids []string) ([]UserRef, error)
}
