// Curated embedder-facing methods of the public embedded.Client facade. Each one
// delegates to the internal engine (s.impl, *authcore.Service). Driven by real
// consumer usage, kept minimal (see SEMVER.md, #126/#130).
package embedded

import (
	"context"
	"crypto"
	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/jwtkit"
	"time"
)

func (s *Client) AdminCountUsers(ctx context.Context, opts authkit.AdminUserListOptions) (int64, error) {
	return s.impl.AdminCountUsers(ctx, opts)
}

func (s *Client) AdminGetUser(ctx context.Context, id string) (*authkit.AdminUser, error) {
	return s.impl.AdminGetUser(ctx, id)
}

func (s *Client) AdminListUserSessions(ctx context.Context, userID string) ([]authkit.Session, error) {
	return s.impl.AdminListUserSessions(ctx, userID)
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
func (s *Client) AssignRolesBySlugAs(ctx context.Context, actorUserID string, userIDs []string, slug string) ([]authkit.OpResult, error) {
	return s.impl.AssignRolesBySlugAs(ctx, actorUserID, userIDs, slug)
}

func (s *Client) RemoveRolesBySlugAs(ctx context.Context, actorUserID string, userIDs []string, slug string) ([]authkit.OpResult, error) {
	return s.impl.RemoveRolesBySlugAs(ctx, actorUserID, userIDs, slug)
}

func (s *Client) AssignGroupRoleAs(ctx context.Context, actorUserID, persona, instanceSlug, subjectID, subjectKind, role string) error {
	return s.impl.AssignGroupRoleAs(ctx, actorUserID, persona, instanceSlug, subjectID, subjectKind, role)
}

func (s *Client) UnassignGroupRoleAs(ctx context.Context, actorUserID, persona, instanceSlug, subjectID, subjectKind, role string) error {
	return s.impl.UnassignGroupRoleAs(ctx, actorUserID, persona, instanceSlug, subjectID, subjectKind, role)
}

// RemoveGroupSubjectAs is the actor-aware whole-subject revoke (#136): it enforces
// no-escalation across every role the subject holds before stripping them. HTTP
// member-removal MUST use this; the unchecked equivalent is Client.Genesis()
// .RemoveGroupSubject (#241).
func (s *Client) RemoveGroupSubjectAs(ctx context.Context, actorUserID, persona, instanceSlug, subjectID, subjectKind string) error {
	return s.impl.RemoveGroupSubjectAs(ctx, actorUserID, persona, instanceSlug, subjectID, subjectKind)
}

func (s *Client) LeaveGroup(ctx context.Context, userID, persona, instanceSlug string) error {
	return s.impl.LeaveGroup(ctx, userID, persona, instanceSlug)
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

func (s *Client) CreateAccountRegistrationInvite(ctx context.Context, req authkit.CreateAccountRegistrationInviteRequest) (authkit.AccountRegistrationInviteCreated, error) {
	return s.impl.CreateAccountRegistrationInvite(ctx, req)
}

func (s *Client) RevokeAccountRegistrationInvite(ctx context.Context, inviteID, actorUserID string) error {
	return s.impl.RevokeAccountRegistrationInvite(ctx, inviteID, actorUserID)
}

// ListGroupInviteLinks lists a group's invite links (never returns the code).
func (s *Client) ListGroupInviteLinks(ctx context.Context, persona, instanceSlug string) ([]authkit.GroupInviteLink, error) {
	return s.impl.ListGroupInviteLinks(ctx, persona, instanceSlug)
}

// RevokeGroupInviteLink revokes a group's invite link by id.
func (s *Client) RevokeGroupInviteLink(ctx context.Context, persona, instanceSlug, linkID string) error {
	return s.impl.RevokeGroupInviteLink(ctx, persona, instanceSlug, linkID)
}

// RedeemGroupInviteLink redeems code for the authenticated redeemer, assigning the
// link's role and returning where it applied.
func (s *Client) RedeemGroupInviteLink(ctx context.Context, code, redeemerUserID string) (authkit.RedeemGroupInviteLinkResult, error) {
	return s.impl.RedeemGroupInviteLink(ctx, code, redeemerUserID)
}

// ExternalInvitesEnabled reports whether invite-link minting is permitted by the
// configured registration mode.
func (s *Client) ExternalInvitesEnabled() bool {
	return s.impl.ExternalInvitesEnabled()
}

func (s *Client) BanUser(ctx context.Context, userID string, reason *string, until *time.Time, bannedBy string) error {
	return s.impl.BanUser(ctx, userID, reason, until, bannedBy)
}

func (s *Client) Can(ctx context.Context, subjectID, subjectKind, persona, instanceSlug, perm string) (bool, error) {
	return s.impl.Can(ctx, subjectID, subjectKind, persona, instanceSlug, perm)
}

// ListEffectivePermissions returns the subject's effective grant PATTERNS in the
// group addressed by (persona, instanceSlug) — the introspection primitive behind
// a "what can I do here" endpoint (#421). Globs (e.g. `root:*`) are returned
// verbatim; an unknown group yields an empty set (fail-closed on real errors).
func (s *Client) ListEffectivePermissions(ctx context.Context, subjectID, subjectKind, persona, instanceSlug string) ([]string, error) {
	return s.impl.ListEffectivePermissions(ctx, subjectID, subjectKind, persona, instanceSlug)
}

func (s *Client) ChangePassword(ctx context.Context, userID, current, new string, keepSessionID *string) error {
	return s.impl.ChangePassword(ctx, userID, current, new, keepSessionID)
}

func (s *Client) CheckSMSHealth(ctx context.Context) error {
	return s.impl.CheckSMSHealth(ctx)
}

func (s *Client) CleanupExpiredAuthState(ctx context.Context) error {
	return s.impl.CleanupExpiredAuthState(ctx)
}

func (s *Client) CreatePermissionGroup(ctx context.Context, req authkit.CreatePermissionGroupRequest) (string, error) {
	return s.impl.CreatePermissionGroup(ctx, req)
}

func (s *Client) CreateUser(ctx context.Context, email, username string) (*authkit.User, error) {
	return s.impl.CreateUser(ctx, email, username)
}

func (s *Client) DeleteRemoteApplication(ctx context.Context, issuer string) error {
	return s.impl.DeleteRemoteApplication(ctx, issuer)
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

func (s *Client) ProviderUsernames(ctx context.Context, userIDs []string, provider string) (map[string]string, error) {
	return s.impl.ProviderUsernames(ctx, userIDs, provider)
}

func (s *Client) GetUserMetadata(ctx context.Context, userID string) (map[string]any, error) {
	return s.impl.GetUserMetadata(ctx, userID)
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

func (s *Client) GetUserBySolanaAddress(ctx context.Context, address string) (*authkit.User, error) {
	return s.impl.GetUserBySolanaAddress(ctx, address)
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

func (s *Client) IsUserAllowed(ctx context.Context, userID string) (bool, error) {
	return s.impl.IsUserAllowed(ctx, userID)
}

func (s *Client) MintAccessToken(ctx context.Context, userID string, extra map[string]any) (string, time.Time, error) {
	return s.impl.MintAccessToken(ctx, userID, extra)
}

func (s *Client) JWKS() jwtkit.JWKS {
	return s.impl.JWKS()
}

func (s *Client) Keyfunc() func(token *jwt.Token) (any, error) {
	return s.impl.Keyfunc()
}

func (s *Client) LinkProvider(ctx context.Context, userID, provider, subject string, email *string) error {
	return s.impl.LinkProvider(ctx, userID, provider, subject, email)
}

func (s *Client) LinkProviderByIssuer(ctx context.Context, userID, issuer, providerSlug, subject string, email *string) error {
	return s.impl.LinkProviderByIssuer(ctx, userID, issuer, providerSlug, subject, email)
}

func (s *Client) ListAPIKeys(ctx context.Context, persona, instanceSlug string) ([]authkit.APIKey, error) {
	return s.impl.ListAPIKeys(ctx, persona, instanceSlug)
}

func (s *Client) ListEntitlements(ctx context.Context, userID string) []string {
	return s.impl.ListEntitlements(ctx, userID)
}

func (s *Client) ListGroupMembers(ctx context.Context, persona, instanceSlug string) ([]authkit.GroupMember, error) {
	return s.impl.ListGroupMembers(ctx, persona, instanceSlug)
}

func (s *Client) ListSubjectGroups(ctx context.Context, subjectID, subjectKind string) ([]authkit.SubjectGroupMembership, error) {
	return s.impl.ListSubjectGroups(ctx, subjectID, subjectKind)
}

func (s *Client) ListRemoteApplications(ctx context.Context, activeOnly bool) ([]authkit.RemoteApplication, error) {
	return s.impl.ListRemoteApplications(ctx, activeOnly)
}

func (s *Client) ListUserSessions(ctx context.Context, userID string) ([]authkit.Session, error) {
	return s.impl.ListUserSessions(ctx, userID)
}

func (s *Client) ListUsersDeletedBefore(ctx context.Context, cutoff time.Time, limit int) ([]string, error) {
	return s.impl.ListUsersDeletedBefore(ctx, cutoff, limit)
}

func (s *Client) MintAPIKey(ctx context.Context, persona, instanceSlug, name, role, createdBy string, expiresAt *time.Time) (authkit.APIKey, string, error) {
	return s.impl.MintAPIKey(ctx, persona, instanceSlug, name, role, createdBy, expiresAt)
}

func (s *Client) MintAPIKeyWithOptions(ctx context.Context, persona, instanceSlug string, opts authkit.APIKeyMintOptions) (authkit.APIKey, string, error) {
	return s.impl.MintAPIKeyWithOptions(ctx, persona, instanceSlug, opts)
}

func (s *Client) MintCustomJWT(ctx context.Context, opts authkit.CustomJWTMintOptions) (string, error) {
	return s.impl.MintCustomJWT(ctx, opts)
}

func (s *Client) MintDelegatedAccessToken(ctx context.Context, p authkit.DelegatedAccessParams) (string, error) {
	return s.impl.MintDelegatedAccessToken(ctx, p)
}

func (s *Client) MintRemoteApplicationAccessToken(ctx context.Context, p authkit.RemoteApplicationAccessParams) (string, error) {
	return s.impl.MintRemoteApplicationAccessToken(ctx, p)
}

func (s *Client) MintServiceJWT(ctx context.Context, opts authkit.ServiceJWTMintOptions) (string, authkit.ServiceJWTClaims, error) {
	return s.impl.MintServiceJWT(ctx, opts)
}

// Config returns the normalized host Config the engine was built from (#237).
func (s *Client) Config() Config {
	return s.impl.Config()
}

func (s *Client) Postgres() *pgxpool.Pool {
	return s.impl.Postgres()
}

func (s *Client) PatchUserMetadata(ctx context.Context, userID string, patch map[string]any) error {
	return s.impl.PatchUserMetadata(ctx, userID, patch)
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

func (s *Client) ResolveGroupIDForSlug(ctx context.Context, persona, instanceSlug string) (string, error) {
	return s.impl.ResolveGroupIDForSlug(ctx, persona, instanceSlug)
}

func (s *Client) ResolveRemoteAppAttributeDef(ctx context.Context, appID, key string, version int32) (*authkit.RemoteAppAttributeDef, error) {
	return s.impl.ResolveRemoteAppAttributeDef(ctx, appID, key, version)
}

func (s *Client) ResolveRemoteApplicationAuthority(ctx context.Context, appID string) ([]string, error) {
	return s.impl.ResolveRemoteApplicationAuthority(ctx, appID)
}

func (s *Client) RestoreUsers(ctx context.Context, userIDs []string) ([]authkit.OpResult, error) {
	return s.impl.RestoreUsers(ctx, userIDs)
}

func (s *Client) RevokeAPIKey(ctx context.Context, persona, instanceSlug, tokenID string) (bool, error) {
	return s.impl.RevokeAPIKey(ctx, persona, instanceSlug, tokenID)
}

func (s *Client) RevokeAllSessions(ctx context.Context, userID string, keepSessionID *string) error {
	return s.impl.RevokeAllSessions(ctx, userID, keepSessionID)
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

func (s *Client) SetEmailVerified(ctx context.Context, id string, v bool) error {
	return s.impl.SetEmailVerified(ctx, id, v)
}

func (s *Client) SetEntitlementsProvider(p EntitlementsProvider) {
	s.impl.SetEntitlementsProvider(p)
}

func (s *Client) SoftDeleteUsers(ctx context.Context, userIDs []string) ([]authkit.OpResult, error) {
	return s.impl.SoftDeleteUsers(ctx, userIDs)
}

func (s *Client) TimeUntilUsernameRenameAvailable(ctx context.Context, userID string, now time.Time) (int64, error) {
	return s.impl.TimeUntilUsernameRenameAvailable(ctx, userID, now)
}

func (s *Client) UnbanUser(ctx context.Context, userID string) error {
	return s.impl.UnbanUser(ctx, userID)
}

func (s *Client) UnlinkProvider(ctx context.Context, userID, provider string) error {
	return s.impl.UnlinkProvider(ctx, userID, provider)
}

func (s *Client) UpdateBiography(ctx context.Context, id string, bio *string) error {
	return s.impl.UpdateBiography(ctx, id, bio)
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

func (s *Client) UpsertRoleBySlug(ctx context.Context, name, slug string, description *string) error {
	return s.impl.UpsertRoleBySlug(ctx, name, slug, description)
}

func (s *Client) ValidateVerificationConfiguration() error {
	return s.impl.ValidateVerificationConfiguration()
}

func (s *Client) VerifyUserPassword(ctx context.Context, userID, pass string) bool {
	return s.impl.VerifyUserPassword(ctx, userID, pass)
}
