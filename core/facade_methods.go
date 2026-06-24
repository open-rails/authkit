// Curated embedder-facing methods of the public core.Service facade. Each one
// delegates to the internal engine (s.impl, *authcore.Service). Driven by real
// consumer usage, kept minimal (see SEMVER.md, #126/#130).
package core

import (
	"context"
	"crypto"
	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	jwtkit "github.com/open-rails/authkit/jwt"
	"net"
	"time"
)

func (s *Service) AdminCountUsers(ctx context.Context, opts AdminUserListOptions) (int64, error) {
	return s.impl.AdminCountUsers(ctx, opts)
}

func (s *Service) AdminGetUser(ctx context.Context, id string) (*AdminUser, error) {
	return s.impl.AdminGetUser(ctx, id)
}

func (s *Service) AdminListUserSessions(ctx context.Context, userID string) ([]Session, error) {
	return s.impl.AdminListUserSessions(ctx, userID)
}

func (s *Service) AdminListUsers(ctx context.Context, opts AdminUserListOptions) (*AdminListUsersResult, error) {
	return s.impl.AdminListUsers(ctx, opts)
}

func (s *Service) AdminRevokeUserSessions(ctx context.Context, userID string) error {
	return s.impl.AdminRevokeUserSessions(ctx, userID)
}

func (s *Service) AdminSetPassword(ctx context.Context, userID, new string) error {
	return s.impl.AdminSetPassword(ctx, userID, new)
}

func (s *Service) AssignRoleBySlug(ctx context.Context, userID, slug string) error {
	return s.impl.AssignRoleBySlug(ctx, userID, slug)
}

func (s *Service) AssignGroupRole(ctx context.Context, persona, instanceSlug, subjectID, subjectKind, role string) error {
	return s.impl.AssignGroupRole(ctx, persona, instanceSlug, subjectID, subjectKind, role)
}

// AssignRoleBySlugAs / RemoveRoleBySlugAs / AssignGroupRoleAs / UnassignGroupRoleAs
// are the actor-aware role-change methods (#136): they enforce the actor's
// <persona>:roles:manage capability + no-escalation (perms(role) ⊆ perms(actor))
// in core. Runtime/admin endpoints MUST use these; the non-As methods are the
// unchecked genesis path (bootstrap/migration).
func (s *Service) AssignRoleBySlugAs(ctx context.Context, actorUserID, userID, slug string) error {
	return s.impl.AssignRoleBySlugAs(ctx, actorUserID, userID, slug)
}

func (s *Service) RemoveRoleBySlugAs(ctx context.Context, actorUserID, userID, slug string) error {
	return s.impl.RemoveRoleBySlugAs(ctx, actorUserID, userID, slug)
}

func (s *Service) AssignGroupRoleAs(ctx context.Context, actorUserID, persona, instanceSlug, subjectID, subjectKind, role string) error {
	return s.impl.AssignGroupRoleAs(ctx, actorUserID, persona, instanceSlug, subjectID, subjectKind, role)
}

func (s *Service) UnassignGroupRoleAs(ctx context.Context, actorUserID, persona, instanceSlug, subjectID, subjectKind, role string) error {
	return s.impl.UnassignGroupRoleAs(ctx, actorUserID, persona, instanceSlug, subjectID, subjectKind, role)
}

// RemoveGroupSubjectAs is the actor-aware whole-subject revoke (#136): it enforces
// no-escalation across every role the subject holds before stripping them. HTTP
// member-removal MUST use this; the unchecked RemoveGroupSubject is genesis-only.
func (s *Service) RemoveGroupSubjectAs(ctx context.Context, actorUserID, persona, instanceSlug, subjectID, subjectKind string) error {
	return s.impl.RemoveGroupSubjectAs(ctx, actorUserID, persona, instanceSlug, subjectID, subjectKind)
}

// ListRoleSlugsByUserErr is the error-propagating ListRoleSlugsByUser (#136):
// role-resolution failures are returned (not swallowed into an empty slice) so
// authz callers can fail closed.
func (s *Service) ListRoleSlugsByUserErr(ctx context.Context, userID string) ([]string, error) {
	return s.impl.ListRoleSlugsByUserErr(ctx, userID)
}

// CreateGroupInviteLink mints a permission-group invite link (#134); the returned
// Code is the plaintext shown ONCE. Gated on the registration mode permitting
// invited self-registration (ErrExternalInvitesDisabled otherwise).
func (s *Service) CreateGroupInviteLink(ctx context.Context, req CreateGroupInviteLinkRequest) (GroupInviteLinkCreated, error) {
	return s.impl.CreateGroupInviteLink(ctx, req)
}

// ListGroupInviteLinks lists a group's invite links (never returns the code).
func (s *Service) ListGroupInviteLinks(ctx context.Context, persona, instanceSlug string) ([]GroupInviteLink, error) {
	return s.impl.ListGroupInviteLinks(ctx, persona, instanceSlug)
}

// RevokeGroupInviteLink revokes a group's invite link by id.
func (s *Service) RevokeGroupInviteLink(ctx context.Context, persona, instanceSlug, linkID string) error {
	return s.impl.RevokeGroupInviteLink(ctx, persona, instanceSlug, linkID)
}

// RedeemGroupInviteLink redeems code for the authenticated redeemer, assigning the
// link's role and returning where it applied.
func (s *Service) RedeemGroupInviteLink(ctx context.Context, code, redeemerUserID string) (RedeemGroupInviteLinkResult, error) {
	return s.impl.RedeemGroupInviteLink(ctx, code, redeemerUserID)
}

// ExternalInvitesEnabled reports whether invite-link minting is permitted by the
// configured registration mode.
func (s *Service) ExternalInvitesEnabled() bool {
	return s.impl.ExternalInvitesEnabled()
}

func (s *Service) BanUser(ctx context.Context, userID string, reason *string, until *time.Time, bannedBy string) error {
	return s.impl.BanUser(ctx, userID, reason, until, bannedBy)
}

func (s *Service) Can(ctx context.Context, subjectID, subjectKind, persona, instanceSlug, perm string) (bool, error) {
	return s.impl.Can(ctx, subjectID, subjectKind, persona, instanceSlug, perm)
}

// ListEffectivePermissions returns the subject's effective grant PATTERNS in the
// group addressed by (persona, instanceSlug) — the introspection primitive behind
// a "what can I do here" endpoint (#421). Globs (e.g. `root:*`) are returned
// verbatim; an unknown group yields an empty set (fail-closed on real errors).
func (s *Service) ListEffectivePermissions(ctx context.Context, subjectID, subjectKind, persona, instanceSlug string) ([]string, error) {
	return s.impl.ListEffectivePermissions(ctx, subjectID, subjectKind, persona, instanceSlug)
}

func (s *Service) ChangePassword(ctx context.Context, userID, current, new string, keepSessionID *string) error {
	return s.impl.ChangePassword(ctx, userID, current, new, keepSessionID)
}

func (s *Service) CheckSMSHealth(ctx context.Context) error {
	return s.impl.CheckSMSHealth(ctx)
}

func (s *Service) CleanupExpiredAuthState(ctx context.Context) error {
	return s.impl.CleanupExpiredAuthState(ctx)
}

func (s *Service) CreatePermissionGroup(ctx context.Context, req CreatePermissionGroupRequest) (string, error) {
	return s.impl.CreatePermissionGroup(ctx, req)
}

func (s *Service) CreateUser(ctx context.Context, email, username string) (*User, error) {
	return s.impl.CreateUser(ctx, email, username)
}

func (s *Service) DeleteRemoteApplication(ctx context.Context, issuer string) error {
	return s.impl.DeleteRemoteApplication(ctx, issuer)
}

func (s *Service) EnsureRootGroup(ctx context.Context) (string, error) {
	return s.impl.EnsureRootGroup(ctx)
}

func (s *Service) EntitlementsProvider() EntitlementsProvider {
	return s.impl.EntitlementsProvider()
}

func (s *Service) EphemeralMode() EphemeralMode {
	return s.impl.EphemeralMode()
}

func (s *Service) ExchangeRefreshToken(ctx context.Context, refreshToken string, ua string, ip net.IP) (string, time.Time, string, error) {
	return s.impl.ExchangeRefreshToken(ctx, refreshToken, ua, ip)
}

func (s *Service) GetEmailByUserID(ctx context.Context, id string) (string, error) {
	return s.impl.GetEmailByUserID(ctx, id)
}

func (s *Service) GetProviderUsername(ctx context.Context, userID, provider string) (string, error) {
	return s.impl.GetProviderUsername(ctx, userID, provider)
}

func (s *Service) GetUserMetadata(ctx context.Context, userID string) (map[string]any, error) {
	return s.impl.GetUserMetadata(ctx, userID)
}

func (s *Service) GetRemoteApplication(ctx context.Context, issuer string) (*RemoteApplication, error) {
	return s.impl.GetRemoteApplication(ctx, issuer)
}

func (s *Service) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	return s.impl.GetUserByEmail(ctx, email)
}

func (s *Service) GetUserByPhone(ctx context.Context, phone string) (*User, error) {
	return s.impl.GetUserByPhone(ctx, phone)
}

func (s *Service) GetUserBySolanaAddress(ctx context.Context, address string) (*User, error) {
	return s.impl.GetUserBySolanaAddress(ctx, address)
}

func (s *Service) GetUserByUsername(ctx context.Context, username string) (*User, error) {
	return s.impl.GetUserByUsername(ctx, username)
}

func (s *Service) HardDeleteUser(ctx context.Context, userID string) error {
	return s.impl.HardDeleteUser(ctx, userID)
}

func (s *Service) HasEmailSender() bool {
	return s.impl.HasEmailSender()
}

func (s *Service) HasSMSSender() bool {
	return s.impl.HasSMSSender()
}

func (s *Service) ImportUsers(ctx context.Context, inputs []ImportUserInput) (ImportUsersResult, error) {
	return s.impl.ImportUsers(ctx, inputs)
}

func (s *Service) IsUserAllowed(ctx context.Context, userID string) (bool, error) {
	return s.impl.IsUserAllowed(ctx, userID)
}

func (s *Service) IssueAccessToken(ctx context.Context, userID, email string, extra map[string]any) (string, time.Time, error) {
	return s.impl.IssueAccessToken(ctx, userID, email, extra)
}

func (s *Service) JWKS() jwtkit.JWKS {
	return s.impl.JWKS()
}

func (s *Service) Keyfunc() func(token *jwt.Token) (any, error) {
	return s.impl.Keyfunc()
}

func (s *Service) LinkProvider(ctx context.Context, userID, provider, subject string, email *string) error {
	return s.impl.LinkProvider(ctx, userID, provider, subject, email)
}

func (s *Service) LinkProviderByIssuer(ctx context.Context, userID, issuer, providerSlug, subject string, email *string) error {
	return s.impl.LinkProviderByIssuer(ctx, userID, issuer, providerSlug, subject, email)
}

func (s *Service) ListAPIKeys(ctx context.Context, persona, instanceSlug string) ([]APIKey, error) {
	return s.impl.ListAPIKeys(ctx, persona, instanceSlug)
}

func (s *Service) ListEntitlements(ctx context.Context, userID string) []string {
	return s.impl.ListEntitlements(ctx, userID)
}

func (s *Service) ListGroupMembers(ctx context.Context, persona, instanceSlug string) ([]GroupMember, error) {
	return s.impl.ListGroupMembers(ctx, persona, instanceSlug)
}

func (s *Service) ListSubjectGroups(ctx context.Context, subjectID, subjectKind string) ([]SubjectGroupMembership, error) {
	return s.impl.ListSubjectGroups(ctx, subjectID, subjectKind)
}

func (s *Service) ListRemoteApplications(ctx context.Context, activeOnly bool) ([]RemoteApplication, error) {
	return s.impl.ListRemoteApplications(ctx, activeOnly)
}

func (s *Service) ListRoleSlugsByUser(ctx context.Context, userID string) []string {
	return s.impl.ListRoleSlugsByUser(ctx, userID)
}

func (s *Service) ListUserSessions(ctx context.Context, userID string) ([]Session, error) {
	return s.impl.ListUserSessions(ctx, userID)
}

func (s *Service) ListUsersDeletedBefore(ctx context.Context, cutoff time.Time, limit int) ([]string, error) {
	return s.impl.ListUsersDeletedBefore(ctx, cutoff, limit)
}

func (s *Service) MintAPIKey(ctx context.Context, persona, instanceSlug, name, role, createdBy string, expiresAt *time.Time) (APIKey, string, error) {
	return s.impl.MintAPIKey(ctx, persona, instanceSlug, name, role, createdBy, expiresAt)
}

func (s *Service) MintAPIKeyWithOptions(ctx context.Context, persona, instanceSlug string, opts APIKeyMintOptions) (APIKey, string, error) {
	return s.impl.MintAPIKeyWithOptions(ctx, persona, instanceSlug, opts)
}

func (s *Service) MintCustomJWT(ctx context.Context, opts CustomJWTMintOptions) (string, error) {
	return s.impl.MintCustomJWT(ctx, opts)
}

func (s *Service) MintDelegatedAccessToken(ctx context.Context, p DelegatedAccessParams) (string, error) {
	return s.impl.MintDelegatedAccessToken(ctx, p)
}

func (s *Service) MintRemoteApplicationAccessToken(ctx context.Context, p RemoteApplicationAccessParams) (string, error) {
	return s.impl.MintRemoteApplicationAccessToken(ctx, p)
}

func (s *Service) MintServiceJWT(ctx context.Context, opts ServiceJWTMintOptions) (string, ServiceJWTClaims, error) {
	return s.impl.MintServiceJWT(ctx, opts)
}

func (s *Service) Options() Options {
	return s.impl.Options()
}

func (s *Service) Postgres() *pgxpool.Pool {
	return s.impl.Postgres()
}

func (s *Service) PatchUserMetadata(ctx context.Context, userID string, patch map[string]any) error {
	return s.impl.PatchUserMetadata(ctx, userID, patch)
}

func (s *Service) PublicKeysByKID() map[string]crypto.PublicKey {
	return s.impl.PublicKeysByKID()
}

func (s *Service) ReconcileBootstrapManifest(ctx context.Context, manifest BootstrapManifest, opts BootstrapReconcileOptions) (BootstrapManifestResult, error) {
	return s.impl.ReconcileBootstrapManifest(ctx, manifest, opts)
}

func (s *Service) RemoveRoleBySlug(ctx context.Context, userID, slug string) error {
	return s.impl.RemoveRoleBySlug(ctx, userID, slug)
}

func (s *Service) ResolveAPIKey(ctx context.Context, keyID, secret string) (string, []string, error) {
	return s.impl.ResolveAPIKey(ctx, keyID, secret)
}

func (s *Service) ResolveAPIKeyWithResources(ctx context.Context, keyID, secret string) (ResolvedAPIKey, error) {
	return s.impl.ResolveAPIKeyWithResources(ctx, keyID, secret)
}

func (s *Service) ResolveGroupIDForSlug(ctx context.Context, persona, instanceSlug string) (string, error) {
	return s.impl.ResolveGroupIDForSlug(ctx, persona, instanceSlug)
}

func (s *Service) ResolveRemoteAppAttributeDef(ctx context.Context, appID, key string, version int32) (*RemoteAppAttributeDef, error) {
	return s.impl.ResolveRemoteAppAttributeDef(ctx, appID, key, version)
}

func (s *Service) ResolveRemoteApplicationAuthority(ctx context.Context, appID string) ([]string, error) {
	return s.impl.ResolveRemoteApplicationAuthority(ctx, appID)
}

func (s *Service) RestoreUser(ctx context.Context, id string) error {
	return s.impl.RestoreUser(ctx, id)
}

func (s *Service) RevokeAPIKey(ctx context.Context, persona, instanceSlug, tokenID string) (bool, error) {
	return s.impl.RevokeAPIKey(ctx, persona, instanceSlug, tokenID)
}

func (s *Service) RevokeAllSessions(ctx context.Context, userID string, keepSessionID *string) error {
	return s.impl.RevokeAllSessions(ctx, userID, keepSessionID)
}

func (s *Service) SMSAvailable() bool {
	return s.impl.SMSAvailable()
}

func (s *Service) Schema() string {
	return s.impl.Schema()
}

func (s *Service) SeedPermissionGroupContainment(ctx context.Context) error {
	return s.impl.SeedPermissionGroupContainment(ctx)
}

func (s *Service) SetEmailVerified(ctx context.Context, id string, v bool) error {
	return s.impl.SetEmailVerified(ctx, id, v)
}

func (s *Service) SetEntitlementsProvider(p EntitlementsProvider) {
	s.impl.SetEntitlementsProvider(p)
}

func (s *Service) SoftDeleteUser(ctx context.Context, id string) error {
	return s.impl.SoftDeleteUser(ctx, id)
}

func (s *Service) TimeUntilUsernameRenameAvailable(ctx context.Context, userID string, now time.Time) (int64, error) {
	return s.impl.TimeUntilUsernameRenameAvailable(ctx, userID, now)
}

func (s *Service) UnbanUser(ctx context.Context, userID string) error {
	return s.impl.UnbanUser(ctx, userID)
}

func (s *Service) UnlinkProvider(ctx context.Context, userID, provider string) error {
	return s.impl.UnlinkProvider(ctx, userID, provider)
}

func (s *Service) UpdateBiography(ctx context.Context, id string, bio *string) error {
	return s.impl.UpdateBiography(ctx, id, bio)
}

func (s *Service) UpdateEmail(ctx context.Context, id, email string) error {
	return s.impl.UpdateEmail(ctx, id, email)
}

func (s *Service) UpdateImportedUser(ctx context.Context, userID string, input ImportUserInput) (*User, error) {
	return s.impl.UpdateImportedUser(ctx, userID, input)
}

func (s *Service) UpdateUsername(ctx context.Context, id, username string) error {
	return s.impl.UpdateUsername(ctx, id, username)
}

func (s *Service) UpsertPasswordHash(ctx context.Context, userID, hash, algo string, params []byte) error {
	return s.impl.UpsertPasswordHash(ctx, userID, hash, algo, params)
}

func (s *Service) UpsertRemoteApplication(ctx context.Context, in RemoteApplication) (*RemoteApplication, error) {
	return s.impl.UpsertRemoteApplication(ctx, in)
}

func (s *Service) UpsertRoleBySlug(ctx context.Context, name, slug string, description *string) error {
	return s.impl.UpsertRoleBySlug(ctx, name, slug, description)
}

func (s *Service) ValidateVerificationConfiguration() error {
	return s.impl.ValidateVerificationConfiguration()
}

func (s *Service) VerifyUserPassword(ctx context.Context, userID, pass string) bool {
	return s.impl.VerifyUserPassword(ctx, userID, pass)
}
