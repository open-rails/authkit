// Package ops declares AuthKit's operations once, with the signatures of the
// root Client's methods. The engine implements Operations; the Client and the
// HTTP layer drive it through this interface, and a remote Client would be a
// second implementation.
package ops

import (
	"context"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/verify"
)

// Operations is every operation of the Client that a remote deployment could
// serve: everything but the embedding-only methods (New, Start, Close,
// Handler, Routes, Mount, verifiers, River).
type Operations interface {
	// Accounts.
	User(ctx context.Context, ref iam.UserRef, opts ...Option) (iam.User, error)
	Users(ctx context.Context, ids []string) (map[string]iam.User, error)
	PublicUsers(ctx context.Context, ids []string) (map[string]iam.PublicUser, error)
	ListUsers(ctx context.Context, q iam.UserQuery) (iam.ListPage[iam.UserEntry], error)
	ResolveUsername(ctx context.Context, name string) (iam.NameResolution, error)
	CheckUsername(ctx context.Context, name string) error
	UserMetadata(ctx context.Context, userID string) (map[string]any, error)
	DeviceKeys(ctx context.Context, userID string) ([]iam.DeviceKey, error)
	CreateUser(ctx context.Context, u iam.NewUser, opts ...Option) (iam.User, error)
	UpdateUser(ctx context.Context, actor iam.Actor, userID string, u iam.UserUpdate, opts ...Option) (iam.User, error)
	PatchUserMetadata(ctx context.Context, actor iam.Actor, userID string, patch map[string]any, opts ...Option) error
	Ban(ctx context.Context, actor iam.Actor, userID string, b iam.Ban, opts ...Option) error
	Unban(ctx context.Context, actor iam.Actor, userID string, opts ...Option) error
	DeleteUsers(ctx context.Context, actor iam.Actor, ids []string, opts ...Option) ([]iam.OpResult, error)
	RestoreUsers(ctx context.Context, actor iam.Actor, ids []string, opts ...Option) ([]iam.OpResult, error)
	PurgeUsers(ctx context.Context, ids []string, opts ...Option) ([]iam.OpResult, error)
	ResetAccountMFA(ctx context.Context, userID string, opts ...Option) error

	// Sessions and tokens.
	Sessions(ctx context.Context, userID string) ([]iam.Session, error)
	ListSessionEvents(ctx context.Context, userID string, q iam.SessionEventQuery) (iam.ListPage[iam.SessionEvent], error)
	RevokeSession(ctx context.Context, actor iam.Actor, userID, sessionID string, opts ...Option) error
	RevokeAccountSessions(ctx context.Context, actor iam.Actor, userID string, opts ...Option) (iam.AccountSessionRevocation, error)
	MintAccessToken(ctx context.Context, userID string, o iam.AccessTokenOptions, opts ...Option) (iam.Token, error)
	CheckSession(ctx context.Context, cl verify.Claims) error
	CheckRecentSignIn(ctx context.Context, cl verify.Claims) error

	// Groups, roles and permissions.
	Group(ctx context.Context, ref iam.GroupRef) (iam.Group, error)
	Groups(ctx context.Context, ids []string) (map[string]iam.Group, error)
	ListGroups(ctx context.Context, q iam.GroupQuery) (iam.ListPage[iam.Group], error)
	ListGroupMembers(ctx context.Context, ref iam.GroupRef, q iam.MemberQuery) (iam.ListPage[iam.GroupMember], error)
	ListMemberships(ctx context.Context, s iam.Subject, p iam.PageRequest) (iam.ListPage[iam.Membership], error)
	GroupRoles(ctx context.Context, ref iam.GroupRef, subjects []iam.Subject) (map[iam.Subject]iam.Role, error)
	CreateGroup(ctx context.Context, g iam.NewGroup, opts ...Option) (iam.Group, error)
	DeleteGroup(ctx context.Context, ref iam.GroupRef, opts ...Option) error
	PurgeGroup(ctx context.Context, ref iam.GroupRef, opts ...Option) error
	SetGroupRole(ctx context.Context, actor iam.Actor, ref iam.GroupRef, subject iam.Subject, role iam.Role, opts ...Option) (iam.GroupMember, error)
	RemoveGroupMember(ctx context.Context, actor iam.Actor, ref iam.GroupRef, subject iam.Subject, opts ...Option) error
	Can(ctx context.Context, actor iam.Actor, ref iam.GroupRef, perm iam.Perm) (bool, error)
	EffectivePermissions(ctx context.Context, actor iam.Actor, refs []iam.GroupRef) (map[string][]iam.Perm, error)
	KnownPermission(perm iam.Perm) bool
	Persona(name string) (iam.Persona, error)
	Permission(text string) (iam.Perm, error)
	Role(text string) (iam.Role, error)

	// API keys.
	CreateAPIKey(ctx context.Context, actor iam.Actor, ref iam.GroupRef, k iam.NewAPIKey, opts ...Option) (iam.APIKeyCreated, error)
	ListAPIKeys(ctx context.Context, ref iam.GroupRef, p iam.PageRequest) (iam.ListPage[iam.APIKey], error)
	RevokeAPIKey(ctx context.Context, actor iam.Actor, ref iam.GroupRef, id string, opts ...Option) error
	ResolveAPIKey(ctx context.Context, token string) (iam.APIKeyPrincipal, error)

	// Invitations.
	CreateInvitation(ctx context.Context, actor iam.Actor, ref iam.GroupRef, n iam.NewInvitation, opts ...Option) (iam.InvitationCreated, error)
	ListInvitations(ctx context.Context, ref iam.GroupRef, p iam.PageRequest) (iam.ListPage[iam.Invitation], error)
	RevokeInvitation(ctx context.Context, actor iam.Actor, ref iam.GroupRef, id string, opts ...Option) error

	// Remote applications, delegation and service JWTs.
	UpsertRemoteApplication(ctx context.Context, actor iam.Actor, ref iam.GroupRef, app iam.RemoteApplication, opts ...Option) (iam.RemoteApplication, error)
	DeleteRemoteApplication(ctx context.Context, actor iam.Actor, ref iam.GroupRef, id string, opts ...Option) error
	RemoteApplication(ctx context.Context, ref iam.AppRef) (iam.RemoteApplication, error)
	ListRemoteApplications(ctx context.Context, ref iam.GroupRef, p iam.PageRequest) (iam.ListPage[iam.RemoteApplication], error)
	MintDelegatedAccessToken(ctx context.Context, actor iam.Actor, d iam.DelegatedAccess, opts ...Option) (iam.Token, error)
	MintServiceJWT(ctx context.Context, s iam.ServiceJWT, opts ...Option) (iam.Token, iam.ServiceJWTClaims, error)

	// Bootstrap, import and provider links.
	ApplyBootstrapManifest(ctx context.Context, m iam.BootstrapManifest, o iam.BootstrapOptions, opts ...Option) (iam.BootstrapResult, error)
	ParseBootstrapManifestYAML(raw []byte) (iam.BootstrapManifest, error)
	EnsureUserRole(ctx context.Context, group iam.GroupRef, u iam.UserRef, role iam.Role, opts ...Option) (iam.User, error)
	ImportUsers(ctx context.Context, rows []iam.ImportUser, o iam.ImportOptions, opts ...Option) (iam.ImportResult, error)
	ImportSolanaLinks(ctx context.Context, rows []iam.ImportSolanaLink, opts ...Option) (iam.ImportSolanaLinksResult, error)
	LinkProvider(ctx context.Context, userID string, l iam.ProviderLink, opts ...Option) error
}
