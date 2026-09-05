// Curated embedder-facing methods of the public embedded.Client facade. Each one
// delegates to the internal engine (s.impl, *authcore.Service). Driven by real
// consumer usage, kept minimal (see SEMVER.md, #126/#130).
package embedded

import (
	"context"
	"crypto"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/jackc/pgx/v5/pgxpool"
	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/documents"
	"github.com/open-rails/authkit/jwtkit"
)

// Passkey ceremonies for hosts that drive WebAuthn in-process (ak#279). Every
// finish consumes its ceremony exactly once and only for the purpose it was
// begun with. The verification pair proves identity without minting a session;
// the account pair creates a passkey-only user; BeginPasskeyRegistration is
// finished by either FinishPasskeyRegistration (add) or
// FinishPasskeyReplacement (register then tombstone every prior passkey, atomically).

func (s *Client) BeginDiscoverablePasskeyVerification(ctx context.Context) (*protocol.CredentialAssertion, error) {
	return s.impl.BeginDiscoverablePasskeyVerification(ctx)
}

func (s *Client) FinishDiscoverablePasskeyVerification(ctx context.Context, response []byte) (VerifiedPasskey, error) {
	return s.impl.FinishDiscoverablePasskeyVerification(ctx, response)
}

func (s *Client) BeginPasskeyAccount(ctx context.Context) (PendingPasskeyAccount, error) {
	return s.impl.BeginPasskeyAccount(ctx)
}

func (s *Client) FinishPasskeyAccount(ctx context.Context, response []byte) (*authkit.User, Passkey, error) {
	return s.impl.FinishPasskeyAccount(ctx, response)
}

func (s *Client) BeginPasskeyRegistration(ctx context.Context, userID string) (*protocol.CredentialCreation, error) {
	return s.impl.BeginPasskeyRegistration(ctx, userID)
}

func (s *Client) FinishPasskeyRegistration(ctx context.Context, userID string, response []byte) (Passkey, error) {
	return s.impl.FinishPasskeyRegistration(ctx, userID, response)
}

func (s *Client) FinishPasskeyReplacement(ctx context.Context, userID string, response []byte) (Passkey, error) {
	return s.impl.FinishPasskeyReplacement(ctx, userID, response)
}

func (s *Client) AdminGetUser(ctx context.Context, id string) (*authkit.AdminUser, error) {
	return s.impl.AdminGetUser(ctx, id)
}

func (s *Client) AdminListUsers(ctx context.Context, opts authkit.AdminUserListOptions) (*authkit.AdminListUsersResult, error) {
	return s.impl.AdminListUsers(ctx, opts)
}

func (s *Client) AdminRevokeUserSessions(ctx context.Context, userID string) error {
	return s.impl.AdminRevokeUserSessions(ctx, userID)
}

func (s *Client) AdminSetPassword(ctx context.Context, userID, new string) error {
	return s.impl.AdminSetPassword(ctx, userID, new)
}

// AssignRoleBySlugAs / RemoveRoleBySlugAs / AssignGroupRoleAs / UnassignGroupRoleAs
// are the actor-aware role-change methods (#136): they enforce the actor's
// <persona>:members:manage capability + no-escalation (perms(role) ⊆ perms(actor))
// in embedded. Runtime/admin endpoints MUST use these; the unchecked bootstrap/
// migration equivalents live on the explicitly-dangerous Client.Genesis() (#241).
func (s *Client) AssignRolesBySlugAs(ctx context.Context, actorUserID string, userIDs []string, role authkit.Role) ([]authkit.OpResult, error) {
	return s.impl.AssignRolesBySlugAs(ctx, actorUserID, userIDs, role)
}

func (s *Client) RemoveRolesBySlugAs(ctx context.Context, actorUserID string, userIDs []string, role authkit.Role) ([]authkit.OpResult, error) {
	return s.impl.RemoveRolesBySlugAs(ctx, actorUserID, userIDs, role)
}

func (s *Client) AssignGroupRoleAs(ctx context.Context, actorUserID string, group authkit.GroupRef, subject authkit.Subject, role authkit.Role) error {
	return s.impl.AssignGroupRoleAs(ctx, actorUserID, group, subject, role)
}

func (s *Client) UnassignGroupRoleAs(ctx context.Context, actorUserID string, group authkit.GroupRef, subject authkit.Subject, role authkit.Role) error {
	return s.impl.UnassignGroupRoleAs(ctx, actorUserID, group, subject, role)
}

// RemoveGroupSubjectAs is the actor-aware whole-subject revoke (#136): it enforces
// no-escalation across every role the subject holds before stripping them. HTTP
// member-removal MUST use this; the unchecked equivalent is Client.Genesis()
// .RemoveGroupSubject (#241).
func (s *Client) RemoveGroupSubjectAs(ctx context.Context, actorUserID string, group authkit.GroupRef, subject authkit.Subject) error {
	return s.impl.RemoveGroupSubjectAs(ctx, actorUserID, group, subject)
}

// AssignRemoteApplicationRoleAs grants a remote application (by slug, scoped
// to the addressed group) a role on behalf of actorUserID: the actor must hold
// <persona>:credentials:manage plus every permission the role confers
// (no-escalation, #136/#308). The unchecked equivalent is
// Client.Genesis().AssignRemoteApplicationRole.
func (s *Client) AssignRemoteApplicationRoleAs(ctx context.Context, actorUserID string, group authkit.GroupRef, appSlug string, role authkit.Role) error {
	return s.impl.AssignRemoteApplicationRoleAs(ctx, actorUserID, group, appSlug, role)
}

// RoleSlugsByUsers returns each user's live root-group role slugs in one call
// (#220; error-propagating so authz callers fail closed, #136).
func (s *Client) RoleSlugsByUsers(ctx context.Context, userIDs []string) (map[string][]string, error) {
	return s.impl.RoleSlugsByUsers(ctx, userIDs)
}

// CreateGroupInviteLink mints a permission-group invite link (#134); the returned
// Code is the plaintext shown ONCE. Gated on the registration mode permitting
// invited self-registration (authkit.ErrExternalInvitesDisabled otherwise).
func (s *Client) CreateGroupInviteLink(ctx context.Context, req authkit.CreateGroupInviteLinkRequest) (authkit.GroupInviteLinkCreated, error) {
	return s.impl.CreateGroupInviteLink(ctx, req)
}

// ListGroupInviteLinks lists a group's invite links (never returns the code).
func (s *Client) ListGroupInviteLinks(ctx context.Context, group authkit.GroupRef) ([]authkit.GroupInviteLink, error) {
	return s.impl.ListGroupInviteLinks(ctx, group)
}

// RevokeGroupInviteLink revokes a group's invite link by id.
func (s *Client) RevokeGroupInviteLink(ctx context.Context, group authkit.GroupRef, linkID string) error {
	return s.impl.RevokeGroupInviteLink(ctx, group, linkID)
}

// ExternalInvitesEnabled reports whether invite-link minting is permitted by the
// configured registration mode.
func (s *Client) ExternalInvitesEnabled() bool {
	return s.impl.ExternalInvitesEnabled()
}

func (s *Client) BanUser(ctx context.Context, userID string, reason *string, until *time.Time, bannedBy string) error {
	return s.impl.BanUser(ctx, userID, reason, until, bannedBy)
}

func (s *Client) Can(ctx context.Context, subject authkit.Subject, group authkit.GroupRef, perm authkit.Perm) (bool, error) {
	return s.impl.Can(ctx, subject, group, perm)
}

// ListEffectivePermissions returns the subject's effective grant PATTERNS in the
// group addressed by (persona, instanceSlug) — the introspection primitive behind
// a "what can I do here" endpoint (#421). Globs (e.g. `root:*`) are returned
// verbatim; an unknown group yields an empty set (fail-closed on real errors).
func (s *Client) ListEffectivePermissions(ctx context.Context, subject authkit.Subject, group authkit.GroupRef) ([]string, error) {
	return s.impl.ListEffectivePermissions(ctx, subject, group)
}

func (s *Client) CheckSMSHealth(ctx context.Context) error {
	return s.impl.CheckSMSHealth(ctx)
}

func (s *Client) CleanupExpiredAuthState(ctx context.Context) error {
	return s.impl.CleanupExpiredAuthState(ctx)
}

// CreatePermissionGroup creates a group instance, optionally seeding an owner.
// #247: deliberately UNCHECKED — no actor-aware *As variant. Authorizing WHO
// may create a group instance is the HOST's job in the embedded trust model
// (calling this at all IS the authority); every RUNTIME mutation to an
// existing instance (role assign/unassign, custom-role define/delete, invite
// and API-key minting) goes through an actor-aware *As path instead.
func (s *Client) CreatePermissionGroup(ctx context.Context, req authkit.CreatePermissionGroupRequest) (string, error) {
	return s.impl.CreatePermissionGroup(ctx, req)
}

func (s *Client) CreateUser(ctx context.Context, email, username string) (*authkit.User, error) {
	return s.impl.CreateUser(ctx, email, username)
}

func (s *Client) EnsureRootGroup(ctx context.Context) (string, error) {
	return s.impl.EnsureRootGroup(ctx)
}

func (s *Client) EntitlementsProvider() EntitlementsProvider {
	return s.impl.EntitlementsProvider()
}

func (s *Client) UsersByIDs(ctx context.Context, ids []string) (map[string]authkit.UserRef, error) {
	return s.impl.UsersByIDs(ctx, ids)
}

func (s *Client) PublicUsersByIDs(ctx context.Context, ids []string) (map[string]authkit.PublicUserRef, error) {
	return s.impl.PublicUsersByIDs(ctx, ids)
}

func (s *Client) UserLivenessByIDs(ctx context.Context, ids []string) (map[string]authkit.UserLiveness, error) {
	return s.impl.UserLivenessByIDs(ctx, ids)
}

func (s *Client) UpdateAvatarURL(ctx context.Context, id string, avatarURL *string) error {
	return s.impl.UpdateAvatarURL(ctx, id, avatarURL)
}

func (s *Client) GetRemoteApplication(ctx context.Context, issuer string) (*authkit.RemoteApplication, error) {
	return s.impl.GetRemoteApplication(ctx, issuer)
}

func (s *Client) GetUserByEmail(ctx context.Context, email string) (*authkit.User, error) {
	return s.impl.GetUserByEmail(ctx, email)
}

func (s *Client) GetUserByPhone(ctx context.Context, phone string) (*authkit.User, error) {
	return s.impl.GetUserByPhone(ctx, phone)
}

func (s *Client) GetUserByUsername(ctx context.Context, username string) (*authkit.User, error) {
	return s.impl.GetUserByUsername(ctx, username)
}

func (s *Client) HardDeleteUsers(ctx context.Context, userIDs []string) ([]authkit.OpResult, error) {
	return s.impl.HardDeleteUsers(ctx, userIDs)
}

func (s *Client) HasEmailSender() bool {
	return s.impl.HasEmailSender()
}

func (s *Client) HasSMSSender() bool {
	return s.impl.HasSMSSender()
}

func (s *Client) ImportUsers(ctx context.Context, inputs []authkit.ImportUserInput) (authkit.ImportUsersResult, error) {
	return s.impl.ImportUsers(ctx, inputs)
}

func (s *Client) MintAccessToken(ctx context.Context, userID string, extra map[string]any) (string, time.Time, error) {
	return s.impl.MintAccessToken(ctx, userID, extra)
}

func (s *Client) JWKS() jwtkit.JWKS {
	return s.impl.JWKS()
}

func (s *Client) LinkProviderByIssuer(ctx context.Context, userID, issuer, providerSlug, subject string, email *string) error {
	return s.impl.LinkProviderByIssuer(ctx, userID, issuer, providerSlug, subject, email)
}

func (s *Client) ListAPIKeys(ctx context.Context, group authkit.GroupRef) ([]authkit.APIKey, error) {
	return s.impl.ListAPIKeys(ctx, group)
}

func (s *Client) ListEntitlements(ctx context.Context, userID string) []string {
	return s.impl.ListEntitlements(ctx, userID)
}

func (s *Client) ListGroupMembers(ctx context.Context, group authkit.GroupRef) ([]authkit.GroupMember, error) {
	return s.impl.ListGroupMembers(ctx, group)
}

func (s *Client) ListSubjectGroups(ctx context.Context, subject authkit.Subject) ([]authkit.SubjectGroupMembership, error) {
	return s.impl.ListSubjectGroups(ctx, subject)
}

func (s *Client) ListRemoteApplications(ctx context.Context) ([]authkit.RemoteApplication, error) {
	return s.impl.ListRemoteApplications(ctx)
}

func (s *Client) ListEnabledRemoteApplications(ctx context.Context) ([]authkit.RemoteApplication, error) {
	return s.impl.ListEnabledRemoteApplications(ctx)
}

func (s *Client) ListUsersDeletedBefore(ctx context.Context, cutoff time.Time, limit int) ([]string, error) {
	return s.impl.ListUsersDeletedBefore(ctx, cutoff, limit)
}

func (s *Client) MintAPIKeyWithOptions(ctx context.Context, group authkit.GroupRef, opts authkit.APIKeyMintOptions) (authkit.APIKey, string, error) {
	return s.impl.MintAPIKeyWithOptions(ctx, group, opts)
}

func (s *Client) MintRemoteApplicationAccessToken(ctx context.Context, p authkit.RemoteApplicationAccessParams) (string, error) {
	return s.impl.MintRemoteApplicationAccessToken(ctx, p)
}

func (s *Client) MintServiceJWT(ctx context.Context, opts authkit.ServiceJWTMintOptions) (string, authkit.ServiceJWTClaims, error) {
	return s.impl.MintServiceJWT(ctx, opts)
}

func (s *Client) SignDocument(ctx context.Context, envelope authkit.DocumentEnvelope) (authkit.SignedDocument, error) {
	return s.impl.SignDocument(ctx, envelope)
}

// DocumentStore returns the engine-owned signed-document store for
// documents.ServiceConfig.Store.
func (s *Client) DocumentStore() documents.Store {
	return s.impl.DocumentStore()
}

// Config returns the normalized host Config the engine was built from (#237).
func (s *Client) Config() Config {
	return s.impl.Config()
}

func (s *Client) Postgres() *pgxpool.Pool {
	return s.impl.Postgres()
}

func (s *Client) PublicKeysByKID() map[string]crypto.PublicKey {
	return s.impl.PublicKeysByKID()
}

func (s *Client) ApplyBootstrapManifest(ctx context.Context, manifest authkit.BootstrapManifest, opts authkit.BootstrapReconcileOptions) (authkit.BootstrapManifestResult, error) {
	return s.impl.ApplyBootstrapManifest(ctx, manifest, opts)
}

func (s *Client) ResolveAPIKey(ctx context.Context, keyID, secret string) (string, []string, error) {
	return s.impl.ResolveAPIKey(ctx, keyID, secret)
}

func (s *Client) ResolveAPIKeyDetailed(ctx context.Context, keyID, secret string) (authkit.ResolvedAPIKey, error) {
	return s.impl.ResolveAPIKeyDetailed(ctx, keyID, secret)
}

func (s *Client) ResolveGroupIDForSlug(ctx context.Context, group authkit.GroupRef) (string, error) {
	return s.impl.ResolveGroupIDForSlug(ctx, group)
}

func (s *Client) GroupInstanceForSlug(ctx context.Context, group authkit.GroupRef) (authkit.GroupInstance, error) {
	return s.impl.GroupInstanceForSlug(ctx, group)
}

func (s *Client) ResolveRemoteAppAttributeDef(ctx context.Context, appID, key string, version int32) (*authkit.RemoteAppAttributeDef, error) {
	return s.impl.ResolveRemoteAppAttributeDef(ctx, appID, key, version)
}

func (s *Client) ResolveRemoteApplicationAuthority(ctx context.Context, appID string) (authkit.RemoteApplicationAuthority, error) {
	return s.impl.ResolveRemoteApplicationAuthority(ctx, appID)
}

func (s *Client) RevokeAPIKey(ctx context.Context, group authkit.GroupRef, tokenID string) (bool, error) {
	return s.impl.RevokeAPIKey(ctx, group, tokenID)
}

func (s *Client) SMSAvailable() bool {
	return s.impl.SMSAvailable()
}

func (s *Client) Schema() string {
	return s.impl.Schema()
}

func (s *Client) SeedPermissionGroupContainment(ctx context.Context) error {
	return s.impl.SeedPermissionGroupContainment(ctx)
}

func (s *Client) MarkEmailVerified(ctx context.Context, id string) error {
	return s.impl.MarkEmailVerified(ctx, id)
}

func (s *Client) ClearEmailVerified(ctx context.Context, id string) error {
	return s.impl.ClearEmailVerified(ctx, id)
}

func (s *Client) SetEntitlementsProvider(p EntitlementsProvider) {
	s.impl.SetEntitlementsProvider(p)
}

func (s *Client) SoftDeleteUsers(ctx context.Context, userIDs []string) ([]authkit.OpResult, error) {
	return s.impl.SoftDeleteUsers(ctx, userIDs)
}

func (s *Client) UnbanUser(ctx context.Context, userID string) error {
	return s.impl.UnbanUser(ctx, userID)
}

func (s *Client) UpdateEmail(ctx context.Context, id, email string) error {
	return s.impl.UpdateEmail(ctx, id, email)
}

func (s *Client) UpdateImportedUser(ctx context.Context, userID string, input authkit.ImportUserInput) (*authkit.User, error) {
	return s.impl.UpdateImportedUser(ctx, userID, input)
}

func (s *Client) UpdateUsername(ctx context.Context, id, username string) error {
	return s.impl.UpdateUsername(ctx, id, username)
}

func (s *Client) UpsertPasswordHash(ctx context.Context, userID, hash, algo string, params []byte) error {
	return s.impl.UpsertPasswordHash(ctx, userID, hash, algo, params)
}

func (s *Client) UpsertRemoteApplication(ctx context.Context, in authkit.RemoteApplication) (*authkit.RemoteApplication, error) {
	return s.impl.UpsertRemoteApplication(ctx, in)
}

func (s *Client) UpsertRoleBySlug(ctx context.Context, name string, role authkit.Role, description *string) error {
	return s.impl.UpsertRoleBySlug(ctx, name, role, description)
}

func (s *Client) ValidateVerificationConfiguration() error {
	return s.impl.ValidateVerificationConfiguration()
}

// Application self-registration (#264).

// RegisterApplicationFromDomain runs the domain-proof registration flow:
// fetch + validate https://<domain>/.well-known/authkit/application.json,
// then create (or idempotently refresh) the application and its service-owned
// org. See authhttp's POST /applications/register for the wire surface.
func (s *Client) RegisterApplicationFromDomain(ctx context.Context, domain string) (*authkit.RegisteredApplication, error) {
	return s.impl.RegisterApplicationFromDomain(ctx, domain)
}

// RotateApplicationSigned applies an old-key-signs-new trust-source rotation
// from a compact JWS signed by a currently-trusted application key. The trust
// root (domain / owning user) always remains able to rotate without it.
func (s *Client) RotateApplicationSigned(ctx context.Context, slug, compactJWS string) (*authkit.RemoteApplication, error) {
	return s.impl.RotateApplicationSigned(ctx, slug, compactJWS)
}

// RepointApplicationSigned moves a domain-rooted application to a new domain:
// signed request + fresh domain proof of the new location.
func (s *Client) RepointApplicationSigned(ctx context.Context, slug, compactJWS string) (*authkit.RegisteredApplication, error) {
	return s.impl.RepointApplicationSigned(ctx, slug, compactJWS)
}

// SetApplicationTier sets an application's capability tier
// (registered|approved). Approval is an admin act on the host.
func (s *Client) SetApplicationTier(ctx context.Context, slug, tier string) (*authkit.RemoteApplication, error) {
	return s.impl.SetApplicationTier(ctx, slug, tier)
}

// SetPermissionGroupDisplayName updates a group's free-form, non-unique
// display name (#264 naming doctrine). Authorization is the caller's job.
func (s *Client) SetPermissionGroupDisplayName(ctx context.Context, group authkit.GroupRef, displayName string) error {
	return s.impl.SetPermissionGroupDisplayName(ctx, group, displayName)
}

// UpdateGroupInstanceAs changes settings atomically after authorizing the captured UUID.
func (s *Client) UpdateGroupInstanceAs(ctx context.Context, actorUserID, groupID string, update authkit.GroupInstanceUpdate) (authkit.GroupInstance, error) {
	return s.impl.UpdateGroupInstanceAs(ctx, actorUserID, groupID, update)
}

// DeletePermissionGroup deletes a group instance. By default the slug is
// TOMBSTONED to the group uuid forever (fail-safe); opts.ReleaseSlug frees it
// instead — safe ONLY for names nothing ever referenced, and that judgment is
// the host's. authkit never deletes a group on its own.
func (s *Client) DeletePermissionGroup(ctx context.Context, group authkit.GroupRef, opts authkit.DeletePermissionGroupOptions) error {
	return s.impl.DeletePermissionGroup(ctx, group, opts)
}

// NamingPolicy returns the normalized deployment-wide user/group naming policy.
func (s *Client) NamingPolicy() authkit.NamingPolicy { return s.impl.NamingPolicy() }

func (s *Client) ResolveUsername(ctx context.Context, name string) (authkit.NameResolution, error) {
	return s.impl.ResolveUsername(ctx, name)
}

// CanOnGroup checks live authority on an already resolved immutable group.
func (s *Client) CanOnGroup(ctx context.Context, subject authkit.Subject, groupID string, perm authkit.Perm) (bool, error) {
	return s.impl.CanOnGroup(ctx, subject, groupID, perm)
}

func (s *Client) GroupInstanceByID(ctx context.Context, groupID string) (authkit.GroupInstance, error) {
	return s.impl.GroupInstanceByID(ctx, groupID)
}

// DeleteGroupInstanceByID is a trusted host lifecycle operation, addressed by
// captured UUID so retries cannot delete a new owner of a reused name.
func (s *Client) DeleteGroupInstanceByID(ctx context.Context, groupID string, opts authkit.DeletePermissionGroupOptions) error {
	return s.impl.DeleteGroupInstanceByID(ctx, groupID, opts)
}

func (s *Client) ImportUnverifiedSolanaLinks(ctx context.Context, inputs []authkit.ImportUnverifiedSolanaLinkInput) (authkit.ImportUnverifiedSolanaLinksResult, error) {
	return s.impl.ImportUnverifiedSolanaLinks(ctx, inputs)
}

// GroupNamingState describes effective policy and still-reserved former names.
// The host authorizes access to the captured UUID before calling this read.
func (s *Client) GroupNamingState(ctx context.Context, groupID string) (authkit.NamingState, error) {
	return s.impl.GroupNamingState(ctx, groupID)
}
func (s *Client) UserNamingState(ctx context.Context, userID string) (authkit.NamingState, error) {
	return s.impl.UserNamingState(ctx, userID)
}
