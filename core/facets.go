package core

import (
	"context"
	"encoding/json"
	"net"
	"time"

	"github.com/open-rails/authkit/siws"
)

// UsersFacet is the user/account view of Service.
type UsersFacet struct{ svc *Service }


// RolesFacet is the role and permission view of Service.
type RolesFacet struct{ svc *Service }

// APIKeysFacet is the org API-key view of Service.
type APIKeysFacet struct{ svc *Service }

// TokensFacet is the token minting/issuing view of Service.
type TokensFacet struct{ svc *Service }

// TwoFactorFacet is the 2FA view of Service.
type TwoFactorFacet struct{ svc *Service }

// SessionsFacet is the refresh-session and step-up auth view of Service.
type SessionsFacet struct{ svc *Service }

// IdentityFacet is the identity-linking view of Service.
type IdentityFacet struct{ svc *Service }

// BootstrapFacet is the manifest/provisioning view of Service.
type BootstrapFacet struct{ svc *Service }

// Users returns the user/account facet.
func (s *Service) Users() UsersFacet { return UsersFacet{svc: s} }

// Roles returns the role and permission facet.
func (s *Service) Roles() RolesFacet { return RolesFacet{svc: s} }

// APIKeys returns the org API-key facet.
func (s *Service) APIKeys() APIKeysFacet { return APIKeysFacet{svc: s} }

// Tokens returns the token minting/issuing facet.
func (s *Service) Tokens() TokensFacet { return TokensFacet{svc: s} }

// TwoFactor returns the 2FA facet.
func (s *Service) TwoFactor() TwoFactorFacet { return TwoFactorFacet{svc: s} }

// Sessions returns the refresh-session and step-up auth facet.
func (s *Service) Sessions() SessionsFacet { return SessionsFacet{svc: s} }

// Identity returns the identity-linking facet.
func (s *Service) Identity() IdentityFacet { return IdentityFacet{svc: s} }

// Bootstrap returns the manifest/provisioning facet.
func (s *Service) Bootstrap() BootstrapFacet { return BootstrapFacet{svc: s} }

// AdminCountUsers calls Service.AdminCountUsers.
func (f UsersFacet) AdminCountUsers(ctx context.Context, opts AdminUserListOptions) (int64, error) {
	return f.svc.AdminCountUsers(ctx, opts)
}

// AdminDeleteUser calls Service.AdminDeleteUser.
func (f UsersFacet) AdminDeleteUser(ctx context.Context, id string) error {
	return f.svc.AdminDeleteUser(ctx, id)
}

// AdminGetUser calls Service.AdminGetUser.
func (f UsersFacet) AdminGetUser(ctx context.Context, id string) (*AdminUser, error) {
	return f.svc.AdminGetUser(ctx, id)
}

// AdminListUsers calls Service.AdminListUsers.
func (f UsersFacet) AdminListUsers(ctx context.Context, opts AdminUserListOptions) (*AdminListUsersResult, error) {
	return f.svc.AdminListUsers(ctx, opts)
}

// AdminSetPassword calls Service.AdminSetPassword.
func (f UsersFacet) AdminSetPassword(ctx context.Context, userID, new string) error {
	return f.svc.AdminSetPassword(ctx, userID, new)
}

// BanUser calls Service.BanUser.
func (f UsersFacet) BanUser(ctx context.Context, userID string, reason *string, until *time.Time, bannedBy string) error {
	return f.svc.BanUser(ctx, userID, reason, until, bannedBy)
}

// BeginPasswordReset calls Service.BeginPasswordReset.
func (f UsersFacet) BeginPasswordReset(ctx context.Context, token string, sessionTTL time.Duration) (string, error) {
	return f.svc.BeginPasswordReset(ctx, token, sessionTTL)
}

// CancelEmailChange calls Service.CancelEmailChange.
func (f UsersFacet) CancelEmailChange(ctx context.Context, userID string) error {
	return f.svc.CancelEmailChange(ctx, userID)
}

// CancelPhoneChange calls Service.CancelPhoneChange.
func (f UsersFacet) CancelPhoneChange(ctx context.Context, userID, phone string) error {
	return f.svc.CancelPhoneChange(ctx, userID, phone)
}

// ChangePassword calls Service.ChangePassword.
func (f UsersFacet) ChangePassword(ctx context.Context, userID, current, new string, keepSessionID *string) error {
	return f.svc.ChangePassword(ctx, userID, current, new, keepSessionID)
}

// CheckPendingRegistrationConflict calls Service.CheckPendingRegistrationConflict.
func (f UsersFacet) CheckPendingRegistrationConflict(ctx context.Context, email, username string) (bool, bool, error) {
	return f.svc.CheckPendingRegistrationConflict(ctx, email, username)
}

// CheckPhoneRegistrationConflict calls Service.CheckPhoneRegistrationConflict.
func (f UsersFacet) CheckPhoneRegistrationConflict(ctx context.Context, phone, username string) (bool, bool, error) {
	return f.svc.CheckPhoneRegistrationConflict(ctx, phone, username)
}

// CheckUserPassword calls Service.CheckUserPassword.
func (f UsersFacet) CheckUserPassword(ctx context.Context, userID, pass string) error {
	return f.svc.CheckUserPassword(ctx, userID, pass)
}

// ConfirmEmailChange calls Service.ConfirmEmailChange.
func (f UsersFacet) ConfirmEmailChange(ctx context.Context, userID, code string) error {
	return f.svc.ConfirmEmailChange(ctx, userID, code)
}

// ConfirmEmailVerification calls Service.ConfirmEmailVerification.
func (f UsersFacet) ConfirmEmailVerification(ctx context.Context, token string) (userID string, err error) {
	return f.svc.ConfirmEmailVerification(ctx, token)
}

// ConfirmPasswordReset calls Service.ConfirmPasswordReset.
func (f UsersFacet) ConfirmPasswordReset(ctx context.Context, token, newPassword string) (string, error) {
	return f.svc.ConfirmPasswordReset(ctx, token, newPassword)
}

// ConfirmPasswordResetWithSession calls Service.ConfirmPasswordResetWithSession.
func (f UsersFacet) ConfirmPasswordResetWithSession(ctx context.Context, resetSession, newPassword string) (string, error) {
	return f.svc.ConfirmPasswordResetWithSession(ctx, resetSession, newPassword)
}

// ConfirmPendingPhoneRegistration calls Service.ConfirmPendingPhoneRegistration.
func (f UsersFacet) ConfirmPendingPhoneRegistration(ctx context.Context, phone, code string) (userID string, err error) {
	return f.svc.ConfirmPendingPhoneRegistration(ctx, phone, code)
}

// ConfirmPendingPhoneRegistrationByToken calls Service.ConfirmPendingPhoneRegistrationByToken.
func (f UsersFacet) ConfirmPendingPhoneRegistrationByToken(ctx context.Context, token string) (string, error) {
	return f.svc.ConfirmPendingPhoneRegistrationByToken(ctx, token)
}

// ConfirmPendingRegistration calls Service.ConfirmPendingRegistration.
func (f UsersFacet) ConfirmPendingRegistration(ctx context.Context, token string) (userID string, err error) {
	return f.svc.ConfirmPendingRegistration(ctx, token)
}

// ConfirmPhoneChange calls Service.ConfirmPhoneChange.
func (f UsersFacet) ConfirmPhoneChange(ctx context.Context, userID, phone, code string) error {
	return f.svc.ConfirmPhoneChange(ctx, userID, phone, code)
}

// ConfirmPhoneVerification calls Service.ConfirmPhoneVerification.
func (f UsersFacet) ConfirmPhoneVerification(ctx context.Context, phone, code string) error {
	return f.svc.ConfirmPhoneVerification(ctx, phone, code)
}

// ConfirmPhoneVerificationByToken calls Service.ConfirmPhoneVerificationByToken.
func (f UsersFacet) ConfirmPhoneVerificationByToken(ctx context.Context, token string) error {
	return f.svc.ConfirmPhoneVerificationByToken(ctx, token)
}

// ConfirmPhoneVerificationByTokenUserID calls Service.ConfirmPhoneVerificationByTokenUserID.
func (f UsersFacet) ConfirmPhoneVerificationByTokenUserID(ctx context.Context, token string) (string, error) {
	return f.svc.ConfirmPhoneVerificationByTokenUserID(ctx, token)
}

// ConfirmPhoneVerificationUserID calls Service.ConfirmPhoneVerificationUserID.
func (f UsersFacet) ConfirmPhoneVerificationUserID(ctx context.Context, phone, code string) (string, error) {
	return f.svc.ConfirmPhoneVerificationUserID(ctx, phone, code)
}

// CreatePendingPhoneRegistration calls Service.CreatePendingPhoneRegistration.
func (f UsersFacet) CreatePendingPhoneRegistration(ctx context.Context, phone, username, passwordHash string) (string, error) {
	return f.svc.CreatePendingPhoneRegistration(ctx, phone, username, passwordHash)
}

// CreatePendingPhoneRegistrationWithLocale calls Service.CreatePendingPhoneRegistrationWithLocale.
func (f UsersFacet) CreatePendingPhoneRegistrationWithLocale(ctx context.Context, phone, username, passwordHash, preferredLocale string) (string, error) {
	return f.svc.CreatePendingPhoneRegistrationWithLocale(ctx, phone, username, passwordHash, preferredLocale)
}

// CreatePendingRegistration calls Service.CreatePendingRegistration.
func (f UsersFacet) CreatePendingRegistration(ctx context.Context, email, username, passwordHash string, ttl time.Duration) (string, error) {
	return f.svc.CreatePendingRegistration(ctx, email, username, passwordHash, ttl)
}

// CreatePendingRegistrationWithLocale calls Service.CreatePendingRegistrationWithLocale.
func (f UsersFacet) CreatePendingRegistrationWithLocale(ctx context.Context, email, username, passwordHash string, ttl time.Duration, preferredLocale string) (string, error) {
	return f.svc.CreatePendingRegistrationWithLocale(ctx, email, username, passwordHash, ttl, preferredLocale)
}

// CreateUser calls Service.CreateUser.
func (f UsersFacet) CreateUser(ctx context.Context, email, username string) (*User, error) {
	return f.svc.CreateUser(ctx, email, username)
}

// DeletePendingPhoneRegistrationByPhone calls Service.DeletePendingPhoneRegistrationByPhone.
func (f UsersFacet) DeletePendingPhoneRegistrationByPhone(ctx context.Context, phone string) error {
	return f.svc.DeletePendingPhoneRegistrationByPhone(ctx, phone)
}

// DeletePendingRegistrationByEmail calls Service.DeletePendingRegistrationByEmail.
func (f UsersFacet) DeletePendingRegistrationByEmail(ctx context.Context, email string) error {
	return f.svc.DeletePendingRegistrationByEmail(ctx, email)
}

// DeriveUsername calls Service.DeriveUsername.
func (f UsersFacet) DeriveUsername(email string) string {
	return f.svc.DeriveUsername(email)
}

// DeriveUsernameForOAuth calls Service.DeriveUsernameForOAuth.
func (f UsersFacet) DeriveUsernameForOAuth(ctx context.Context, provider, preferred, email, displayName string) string {
	return f.svc.DeriveUsernameForOAuth(ctx, provider, preferred, email, displayName)
}

// GenerateAvailableUsername calls Service.GenerateAvailableUsername.
func (f UsersFacet) GenerateAvailableUsername(ctx context.Context, base string) string {
	return f.svc.GenerateAvailableUsername(ctx, base)
}

// GetEmailByUserID calls Service.GetEmailByUserID.
func (f UsersFacet) GetEmailByUserID(ctx context.Context, id string) (string, error) {
	return f.svc.GetEmailByUserID(ctx, id)
}

// GetPendingEmailChange calls Service.GetPendingEmailChange.
func (f UsersFacet) GetPendingEmailChange(ctx context.Context, userID string) (string, error) {
	return f.svc.GetPendingEmailChange(ctx, userID)
}

// GetPendingPhoneRegistrationByPhone calls Service.GetPendingPhoneRegistrationByPhone.
func (f UsersFacet) GetPendingPhoneRegistrationByPhone(ctx context.Context, phone string) (*PendingRegistration, error) {
	return f.svc.GetPendingPhoneRegistrationByPhone(ctx, phone)
}

// GetPendingRegistrationByEmail calls Service.GetPendingRegistrationByEmail.
func (f UsersFacet) GetPendingRegistrationByEmail(ctx context.Context, email string) (*PendingRegistration, error) {
	return f.svc.GetPendingRegistrationByEmail(ctx, email)
}

// GetPreferredLocale calls Service.GetPreferredLocale.
func (f UsersFacet) GetPreferredLocale(ctx context.Context, userID string) (PreferredLocale, error) {
	return f.svc.GetPreferredLocale(ctx, userID)
}

// GetUserByPhone calls Service.GetUserByPhone.
func (f UsersFacet) GetUserByPhone(ctx context.Context, phone string) (*User, error) {
	return f.svc.GetUserByPhone(ctx, phone)
}

// GetUserMetadata calls Service.GetUserMetadata.
func (f UsersFacet) GetUserMetadata(ctx context.Context, userID string) (map[string]any, error) {
	return f.svc.GetUserMetadata(ctx, userID)
}

// HardDeleteUser calls Service.HardDeleteUser.
func (f UsersFacet) HardDeleteUser(ctx context.Context, userID string) error {
	return f.svc.HardDeleteUser(ctx, userID)
}

// HostDeleteUser calls Service.HostDeleteUser.
func (f UsersFacet) HostDeleteUser(ctx context.Context, id string, soft bool) error {
	return f.svc.HostDeleteUser(ctx, id, soft)
}

// ImportUser calls Service.ImportUser.
func (f UsersFacet) ImportUser(ctx context.Context, input ImportUserInput) (*User, error) {
	return f.svc.ImportUser(ctx, input)
}

// IsUserAllowed calls Service.IsUserAllowed.
func (f UsersFacet) IsUserAllowed(ctx context.Context, userID string) (bool, error) {
	return f.svc.IsUserAllowed(ctx, userID)
}

// ListEntitlements calls Service.ListEntitlements.
func (f UsersFacet) ListEntitlements(ctx context.Context, userID string) []string {
	return f.svc.ListEntitlements(ctx, userID)
}

// ListUsersDeletedBefore calls Service.ListUsersDeletedBefore.
func (f UsersFacet) ListUsersDeletedBefore(ctx context.Context, cutoff time.Time, limit int) ([]string, error) {
	return f.svc.ListUsersDeletedBefore(ctx, cutoff, limit)
}

// PasswordLogin calls Service.PasswordLogin.
func (f UsersFacet) PasswordLogin(ctx context.Context, email, pass string, extra map[string]any) (string, time.Time, error) {
	return f.svc.PasswordLogin(ctx, email, pass, extra)
}

// PasswordLoginByUserID calls Service.PasswordLoginByUserID.
func (f UsersFacet) PasswordLoginByUserID(ctx context.Context, userID, pass string, extra map[string]any) (string, time.Time, error) {
	return f.svc.PasswordLoginByUserID(ctx, userID, pass, extra)
}

// PatchUserMetadata calls Service.PatchUserMetadata.
func (f UsersFacet) PatchUserMetadata(ctx context.Context, userID string, patch map[string]any) error {
	return f.svc.PatchUserMetadata(ctx, userID, patch)
}

// RequestEmailChange calls Service.RequestEmailChange.
func (f UsersFacet) RequestEmailChange(ctx context.Context, userID, newEmail string) error {
	return f.svc.RequestEmailChange(ctx, userID, newEmail)
}

// RequestEmailVerification calls Service.RequestEmailVerification.
func (f UsersFacet) RequestEmailVerification(ctx context.Context, email string, ttl time.Duration) error {
	return f.svc.RequestEmailVerification(ctx, email, ttl)
}

// RequestPasswordReset calls Service.RequestPasswordReset.
func (f UsersFacet) RequestPasswordReset(ctx context.Context, email string, ttl time.Duration, ip *string, ua *string) error {
	return f.svc.RequestPasswordReset(ctx, email, ttl, ip, ua)
}

// RequestPhoneChange calls Service.RequestPhoneChange.
func (f UsersFacet) RequestPhoneChange(ctx context.Context, userID, newPhone string) error {
	return f.svc.RequestPhoneChange(ctx, userID, newPhone)
}

// RequestPhonePasswordReset calls Service.RequestPhonePasswordReset.
func (f UsersFacet) RequestPhonePasswordReset(ctx context.Context, phone string, ttl time.Duration, ip *string, ua *string) error {
	return f.svc.RequestPhonePasswordReset(ctx, phone, ttl, ip, ua)
}

// RequestPhoneVerification calls Service.RequestPhoneVerification.
func (f UsersFacet) RequestPhoneVerification(ctx context.Context, phone string, ttl time.Duration) error {
	return f.svc.RequestPhoneVerification(ctx, phone, ttl)
}

// ResendEmailChangeCode calls Service.ResendEmailChangeCode.
func (f UsersFacet) ResendEmailChangeCode(ctx context.Context, userID string) error {
	return f.svc.ResendEmailChangeCode(ctx, userID)
}

// ResendPhoneChangeCode calls Service.ResendPhoneChangeCode.
func (f UsersFacet) ResendPhoneChangeCode(ctx context.Context, userID, phone string) error {
	return f.svc.ResendPhoneChangeCode(ctx, userID, phone)
}

// RestoreUser calls Service.RestoreUser.
func (f UsersFacet) RestoreUser(ctx context.Context, id string) error {
	return f.svc.RestoreUser(ctx, id)
}

// SendPhoneVerificationToUser calls Service.SendPhoneVerificationToUser.
func (f UsersFacet) SendPhoneVerificationToUser(ctx context.Context, phone, userID string, ttl time.Duration) error {
	return f.svc.SendPhoneVerificationToUser(ctx, phone, userID, ttl)
}

// SendWelcome calls Service.SendWelcome.
func (f UsersFacet) SendWelcome(ctx context.Context, userID string) {
	f.svc.SendWelcome(ctx, userID)
}

// SetEmailVerified calls Service.SetEmailVerified.
func (f UsersFacet) SetEmailVerified(ctx context.Context, id string, v bool) error {
	return f.svc.SetEmailVerified(ctx, id, v)
}

// SetPasswordAfterFreshAuth calls Service.SetPasswordAfterFreshAuth.
func (f UsersFacet) SetPasswordAfterFreshAuth(ctx context.Context, userID, new string, keepSessionID *string) error {
	return f.svc.SetPasswordAfterFreshAuth(ctx, userID, new, keepSessionID)
}

// SetPreferredLocale calls Service.SetPreferredLocale.
func (f UsersFacet) SetPreferredLocale(ctx context.Context, userID, locale, source string) error {
	return f.svc.SetPreferredLocale(ctx, userID, locale, source)
}

// SoftDeleteUser calls Service.SoftDeleteUser.
func (f UsersFacet) SoftDeleteUser(ctx context.Context, id string) error {
	return f.svc.SoftDeleteUser(ctx, id)
}

// TimeUntilUsernameRenameAvailable calls Service.TimeUntilUsernameRenameAvailable.
func (f UsersFacet) TimeUntilUsernameRenameAvailable(ctx context.Context, userID string, now time.Time) (int64, error) {
	return f.svc.TimeUntilUsernameRenameAvailable(ctx, userID, now)
}

// UnbanUser calls Service.UnbanUser.
func (f UsersFacet) UnbanUser(ctx context.Context, userID string) error {
	return f.svc.UnbanUser(ctx, userID)
}

// UpdateBiography calls Service.UpdateBiography.
func (f UsersFacet) UpdateBiography(ctx context.Context, id string, bio *string) error {
	return f.svc.UpdateBiography(ctx, id, bio)
}

// UpdateEmail calls Service.UpdateEmail.
func (f UsersFacet) UpdateEmail(ctx context.Context, id, email string) error {
	return f.svc.UpdateEmail(ctx, id, email)
}

// UpdateImportedUser calls Service.UpdateImportedUser.
func (f UsersFacet) UpdateImportedUser(ctx context.Context, userID string, input ImportUserInput) (*User, error) {
	return f.svc.UpdateImportedUser(ctx, userID, input)
}

// UpdateUsername calls Service.UpdateUsername.
func (f UsersFacet) UpdateUsername(ctx context.Context, id, username string) error {
	return f.svc.UpdateUsername(ctx, id, username)
}

// UpdateUsernameForce calls Service.UpdateUsernameForce.
func (f UsersFacet) UpdateUsernameForce(ctx context.Context, id, username string) error {
	return f.svc.UpdateUsernameForce(ctx, id, username)
}

// UpsertPasswordHash calls Service.UpsertPasswordHash.
func (f UsersFacet) UpsertPasswordHash(ctx context.Context, userID, hash, algo string, params []byte) error {
	return f.svc.UpsertPasswordHash(ctx, userID, hash, algo, params)
}

// ValidateUsernameForRegistration calls Service.ValidateUsernameForRegistration.
func (f UsersFacet) ValidateUsernameForRegistration(ctx context.Context, username string) (string, error) {
	return f.svc.ValidateUsernameForRegistration(ctx, username)
}

// ValidateUsernameForUser calls Service.ValidateUsernameForUser.
func (f UsersFacet) ValidateUsernameForUser(ctx context.Context, username, userID string) (slug, excludeOrgID string, err error) {
	return f.svc.ValidateUsernameForUser(ctx, username, userID)
}

// VerifyPendingPassword calls Service.VerifyPendingPassword.
func (f UsersFacet) VerifyPendingPassword(ctx context.Context, email, pass string) bool {
	return f.svc.VerifyPendingPassword(ctx, email, pass)
}

// VerifyPendingPhonePassword calls Service.VerifyPendingPhonePassword.
func (f UsersFacet) VerifyPendingPhonePassword(ctx context.Context, phone, pass string) bool {
	return f.svc.VerifyPendingPhonePassword(ctx, phone, pass)
}

// VerifyUserPassword calls Service.VerifyUserPassword.
func (f UsersFacet) VerifyUserPassword(ctx context.Context, userID, pass string) bool {
	return f.svc.VerifyUserPassword(ctx, userID, pass)
}

// AssignRole calls Service.AssignRole.
func (f RolesFacet) AssignRole(ctx context.Context, orgSlug, userID, role string) error {
	return f.svc.AssignRole(ctx, orgSlug, userID, role)
}

// AssignRoleBySlug calls Service.AssignRoleBySlug.
func (f RolesFacet) AssignRoleBySlug(ctx context.Context, userID, slug string) error {
	return f.svc.AssignRoleBySlug(ctx, userID, slug)
}

// DefineRole calls Service.DefineRole.
func (f RolesFacet) DefineRole(ctx context.Context, orgSlug, role string) error {
	return f.svc.DefineRole(ctx, orgSlug, role)
}

// DeleteRole calls Service.DeleteRole.
func (f RolesFacet) DeleteRole(ctx context.Context, orgSlug, role string) error {
	return f.svc.DeleteRole(ctx, orgSlug, role)
}

// EffectivePermissions calls Service.EffectivePermissions.
func (f RolesFacet) EffectivePermissions(ctx context.Context, orgSlug, userID string) ([]string, error) {
	return f.svc.EffectivePermissions(ctx, orgSlug, userID)
}

// EffectiveRolePermissions calls Service.EffectiveRolePermissions.
func (f RolesFacet) EffectiveRolePermissions(ctx context.Context, orgSlug, role string) ([]string, error) {
	return f.svc.EffectiveRolePermissions(ctx, orgSlug, role)
}

// EnsureOwnerGrants calls Service.EnsureOwnerGrants.
func (f RolesFacet) EnsureOwnerGrants(ctx context.Context, orgSlug string) error {
	return f.svc.EnsureOwnerGrants(ctx, orgSlug)
}

// GetRolePermissions calls Service.GetRolePermissions.
func (f RolesFacet) GetRolePermissions(ctx context.Context, orgSlug, role string) ([]string, error) {
	return f.svc.GetRolePermissions(ctx, orgSlug, role)
}

// HasPermission calls Service.HasPermission.
func (f RolesFacet) HasPermission(ctx context.Context, orgSlug, userID, perm string) (bool, error) {
	return f.svc.HasPermission(ctx, orgSlug, userID, perm)
}

// ListOrgDefinedRoles calls Service.ListOrgDefinedRoles.
func (f RolesFacet) ListOrgDefinedRoles(ctx context.Context, orgSlug string) ([]string, error) {
	return f.svc.ListOrgDefinedRoles(ctx, orgSlug)
}

// ListRoleSlugsByUser calls Service.ListRoleSlugsByUser.
func (f RolesFacet) ListRoleSlugsByUser(ctx context.Context, userID string) []string {
	return f.svc.ListRoleSlugsByUser(ctx, userID)
}

// OrgRoleExists calls Service.OrgRoleExists.
func (f RolesFacet) OrgRoleExists(ctx context.Context, orgSlug, role string) (bool, error) {
	return f.svc.OrgRoleExists(ctx, orgSlug, role)
}

// Permissions calls Service.Permissions.
func (f RolesFacet) Permissions() []PermissionDef {
	return f.svc.Permissions()
}

// ReadMemberRoles calls Service.ReadMemberRoles.
func (f RolesFacet) ReadMemberRoles(ctx context.Context, orgSlug, userID string) ([]string, error) {
	return f.svc.ReadMemberRoles(ctx, orgSlug, userID)
}

// RemoveRoleBySlug calls Service.RemoveRoleBySlug.
func (f RolesFacet) RemoveRoleBySlug(ctx context.Context, userID, slug string) error {
	return f.svc.RemoveRoleBySlug(ctx, userID, slug)
}

// SetRolePermissions calls Service.SetRolePermissions.
func (f RolesFacet) SetRolePermissions(ctx context.Context, orgSlug, role string, perms []string) error {
	return f.svc.SetRolePermissions(ctx, orgSlug, role, perms)
}

// UnassignRole calls Service.UnassignRole.
func (f RolesFacet) UnassignRole(ctx context.Context, orgSlug, userID, role string) error {
	return f.svc.UnassignRole(ctx, orgSlug, userID, role)
}

// UpsertRoleBySlug calls Service.UpsertRoleBySlug.
func (f RolesFacet) UpsertRoleBySlug(ctx context.Context, name, slug string, description *string) error {
	return f.svc.UpsertRoleBySlug(ctx, name, slug, description)
}

// ValidateGrant calls Service.ValidateGrant.
func (f RolesFacet) ValidateGrant(ctx context.Context, orgSlug, actorUserID string, tokens []string, actorAll bool) (unknown, offending []string, err error) {
	return f.svc.ValidateGrant(ctx, orgSlug, actorUserID, tokens, actorAll)
}

// AuthorizeAPIKeyResources calls Service.AuthorizeAPIKeyResources.
func (f APIKeysFacet) AuthorizeAPIKeyResources(ctx context.Context, req ResourceScopeAuthorizationRequest) error {
	return f.svc.AuthorizeAPIKeyResources(ctx, req)
}

// ListAPIKeys calls Service.ListAPIKeys.
func (f APIKeysFacet) ListAPIKeys(ctx context.Context, orgSlug string) ([]APIKey, error) {
	return f.svc.ListAPIKeys(ctx, orgSlug)
}

// MintAPIKey calls Service.MintAPIKey.
func (f APIKeysFacet) MintAPIKey(ctx context.Context, orgSlug, name, role, createdBy string, expiresAt *time.Time) (APIKey, string, error) {
	return f.svc.MintAPIKey(ctx, orgSlug, name, role, createdBy, expiresAt)
}

// MintAPIKeyWithOptions calls Service.MintAPIKeyWithOptions.
func (f APIKeysFacet) MintAPIKeyWithOptions(ctx context.Context, orgSlug string, opts APIKeyMintOptions) (APIKey, string, error) {
	return f.svc.MintAPIKeyWithOptions(ctx, orgSlug, opts)
}

// ResolveAPIKey calls Service.ResolveAPIKey.
func (f APIKeysFacet) ResolveAPIKey(ctx context.Context, keyID, secret string) (orgSlug string, permissions []string, err error) {
	return f.svc.ResolveAPIKey(ctx, keyID, secret)
}

// ResolveAPIKeyWithResources calls Service.ResolveAPIKeyWithResources.
func (f APIKeysFacet) ResolveAPIKeyWithResources(ctx context.Context, keyID, secret string) (ResolvedAPIKey, error) {
	return f.svc.ResolveAPIKeyWithResources(ctx, keyID, secret)
}

// RevokeAPIKey calls Service.RevokeAPIKey.
func (f APIKeysFacet) RevokeAPIKey(ctx context.Context, orgSlug, tokenID string) (bool, error) {
	return f.svc.RevokeAPIKey(ctx, orgSlug, tokenID)
}

// IssueAccessToken calls Service.IssueAccessToken.
func (f TokensFacet) IssueAccessToken(ctx context.Context, userID, email string, extra map[string]any) (token string, expiresAt time.Time, err error) {
	return f.svc.IssueAccessToken(ctx, userID, email, extra)
}

// MintCustomJWT calls Service.MintCustomJWT.
func (f TokensFacet) MintCustomJWT(ctx context.Context, opts CustomJWTMintOptions) (string, error) {
	return f.svc.MintCustomJWT(ctx, opts)
}

// MintDelegatedAccessToken calls Service.MintDelegatedAccessToken.
func (f TokensFacet) MintDelegatedAccessToken(ctx context.Context, p DelegatedAccessParams) (string, error) {
	return f.svc.MintDelegatedAccessToken(ctx, p)
}

// MintRemoteApplicationAccessToken calls Service.MintRemoteApplicationAccessToken.
func (f TokensFacet) MintRemoteApplicationAccessToken(ctx context.Context, p RemoteApplicationAccessParams) (string, error) {
	return f.svc.MintRemoteApplicationAccessToken(ctx, p)
}

// MintServiceJWT calls Service.MintServiceJWT.
func (f TokensFacet) MintServiceJWT(ctx context.Context, opts ServiceJWTMintOptions) (string, ServiceJWTClaims, error) {
	return f.svc.MintServiceJWT(ctx, opts)
}

// Clear2FAChallenge calls Service.Clear2FAChallenge.
func (f TwoFactorFacet) Clear2FAChallenge(ctx context.Context, userID string) error {
	return f.svc.Clear2FAChallenge(ctx, userID)
}

// Create2FAChallenge calls Service.Create2FAChallenge.
func (f TwoFactorFacet) Create2FAChallenge(ctx context.Context, userID string) (string, error) {
	return f.svc.Create2FAChallenge(ctx, userID)
}

// Disable2FA calls Service.Disable2FA.
func (f TwoFactorFacet) Disable2FA(ctx context.Context, userID string) error {
	return f.svc.Disable2FA(ctx, userID)
}

// Enable2FA calls Service.Enable2FA.
func (f TwoFactorFacet) Enable2FA(ctx context.Context, userID, method string, phoneNumber *string) ([]string, error) {
	return f.svc.Enable2FA(ctx, userID, method, phoneNumber)
}

// Get2FASettings calls Service.Get2FASettings.
func (f TwoFactorFacet) Get2FASettings(ctx context.Context, userID string) (*TwoFactorSettings, error) {
	return f.svc.Get2FASettings(ctx, userID)
}

// RegenerateBackupCodes calls Service.RegenerateBackupCodes.
func (f TwoFactorFacet) RegenerateBackupCodes(ctx context.Context, userID string) ([]string, error) {
	return f.svc.RegenerateBackupCodes(ctx, userID)
}

// Require2FAForLogin calls Service.Require2FAForLogin.
func (f TwoFactorFacet) Require2FAForLogin(ctx context.Context, userID string) (string, error) {
	return f.svc.Require2FAForLogin(ctx, userID)
}

// SendPhone2FASetupCode calls Service.SendPhone2FASetupCode.
func (f TwoFactorFacet) SendPhone2FASetupCode(ctx context.Context, userID, phone, code string) error {
	return f.svc.SendPhone2FASetupCode(ctx, userID, phone, code)
}

// Verify2FAChallenge calls Service.Verify2FAChallenge.
func (f TwoFactorFacet) Verify2FAChallenge(ctx context.Context, userID, challenge string) (bool, error) {
	return f.svc.Verify2FAChallenge(ctx, userID, challenge)
}

// Verify2FACode calls Service.Verify2FACode.
func (f TwoFactorFacet) Verify2FACode(ctx context.Context, userID, code string) (bool, error) {
	return f.svc.Verify2FACode(ctx, userID, code)
}

// VerifyBackupCode calls Service.VerifyBackupCode.
func (f TwoFactorFacet) VerifyBackupCode(ctx context.Context, userID, backupCode string) (bool, error) {
	return f.svc.VerifyBackupCode(ctx, userID, backupCode)
}

// VerifyPhone2FASetupCode calls Service.VerifyPhone2FASetupCode.
func (f TwoFactorFacet) VerifyPhone2FASetupCode(ctx context.Context, userID, phone, code string) (bool, error) {
	return f.svc.VerifyPhone2FASetupCode(ctx, userID, phone, code)
}

// AdminListUserSessions calls Service.AdminListUserSessions.
func (f SessionsFacet) AdminListUserSessions(ctx context.Context, userID string) ([]Session, error) {
	return f.svc.AdminListUserSessions(ctx, userID)
}

// AdminRevokeUserSessions calls Service.AdminRevokeUserSessions.
func (f SessionsFacet) AdminRevokeUserSessions(ctx context.Context, userID string) error {
	return f.svc.AdminRevokeUserSessions(ctx, userID)
}

// CleanupExpiredAuthState calls Service.CleanupExpiredAuthState.
func (f SessionsFacet) CleanupExpiredAuthState(ctx context.Context) error {
	return f.svc.CleanupExpiredAuthState(ctx)
}

// ExchangeRefreshToken calls Service.ExchangeRefreshToken.
func (f SessionsFacet) ExchangeRefreshToken(ctx context.Context, refreshToken string, ua string, ip net.IP) (idToken string, expiresAt time.Time, newRefresh string, err error) {
	return f.svc.ExchangeRefreshToken(ctx, refreshToken, ua, ip)
}

// IssueRefreshSession calls Service.IssueRefreshSession.
func (f SessionsFacet) IssueRefreshSession(ctx context.Context, userID, userAgent string, ip net.IP) (sessionID, refreshToken string, expiresAt *time.Time, err error) {
	return f.svc.IssueRefreshSession(ctx, userID, userAgent, ip)
}

// ListUserSessions calls Service.ListUserSessions.
func (f SessionsFacet) ListUserSessions(ctx context.Context, userID string) ([]Session, error) {
	return f.svc.ListUserSessions(ctx, userID)
}

// LogPasswordChanged calls Service.LogPasswordChanged.
func (f SessionsFacet) LogPasswordChanged(ctx context.Context, userID string, sessionID string, ip *string, ua *string) {
	f.svc.LogPasswordChanged(ctx, userID, sessionID, ip, ua)
}

// LogPasswordRecovery calls Service.LogPasswordRecovery.
func (f SessionsFacet) LogPasswordRecovery(ctx context.Context, userID string, method, sessionID string, ip *string, ua *string) {
	f.svc.LogPasswordRecovery(ctx, userID, method, sessionID, ip, ua)
}

// LogSessionCreated calls Service.LogSessionCreated.
func (f SessionsFacet) LogSessionCreated(ctx context.Context, userID string, method string, sessionID string, ip *string, ua *string) {
	f.svc.LogSessionCreated(ctx, userID, method, sessionID, ip, ua)
}

// LogSessionFailed calls Service.LogSessionFailed.
func (f SessionsFacet) LogSessionFailed(ctx context.Context, userID string, sessionID string, reason *string, ip *string, ua *string) {
	f.svc.LogSessionFailed(ctx, userID, sessionID, reason, ip, ua)
}

// MarkSessionAuthenticated calls Service.MarkSessionAuthenticated.
func (f SessionsFacet) MarkSessionAuthenticated(ctx context.Context, userID, sessionID string) error {
	return f.svc.MarkSessionAuthenticated(ctx, userID, sessionID)
}

// RequireFreshSession calls Service.RequireFreshSession.
func (f SessionsFacet) RequireFreshSession(ctx context.Context, userID, sessionID string, now time.Time) (SessionFreshness, error) {
	return f.svc.RequireFreshSession(ctx, userID, sessionID, now)
}

// ResolveSessionByRefresh calls Service.ResolveSessionByRefresh.
func (f SessionsFacet) ResolveSessionByRefresh(ctx context.Context, refreshToken string) (string, error) {
	return f.svc.ResolveSessionByRefresh(ctx, refreshToken)
}

// RevokeAllSessions calls Service.RevokeAllSessions.
func (f SessionsFacet) RevokeAllSessions(ctx context.Context, userID string, keepSessionID *string) error {
	return f.svc.RevokeAllSessions(ctx, userID, keepSessionID)
}

// RevokeSessionByID calls Service.RevokeSessionByID.
func (f SessionsFacet) RevokeSessionByID(ctx context.Context, sessionID string) error {
	return f.svc.RevokeSessionByID(ctx, sessionID)
}

// RevokeSessionByIDForUser calls Service.RevokeSessionByIDForUser.
func (f SessionsFacet) RevokeSessionByIDForUser(ctx context.Context, userID, sessionID string) error {
	return f.svc.RevokeSessionByIDForUser(ctx, userID, sessionID)
}

// SessionFreshness calls Service.SessionFreshness.
func (f SessionsFacet) SessionFreshness(ctx context.Context, userID, sessionID string, now time.Time) (SessionFreshness, error) {
	return f.svc.SessionFreshness(ctx, userID, sessionID, now)
}

// AddRemoteApplicationMember calls Service.AddRemoteApplicationMember.
func (f IdentityFacet) AddRemoteApplicationMember(ctx context.Context, orgSlug, appID, role string) error {
	return f.svc.AddRemoteApplicationMember(ctx, orgSlug, appID, role)
}

// CountProviderLinks calls Service.CountProviderLinks.
func (f IdentityFacet) CountProviderLinks(ctx context.Context, userID string) int {
	return f.svc.CountProviderLinks(ctx, userID)
}

// DeleteRemoteAppAttributeDef calls Service.DeleteRemoteAppAttributeDef.
func (f IdentityFacet) DeleteRemoteAppAttributeDef(ctx context.Context, appID, key string) error {
	return f.svc.DeleteRemoteAppAttributeDef(ctx, appID, key)
}

// DeleteRemoteApplication calls Service.DeleteRemoteApplication.
func (f IdentityFacet) DeleteRemoteApplication(ctx context.Context, issuer string) error {
	return f.svc.DeleteRemoteApplication(ctx, issuer)
}

// GenerateSIWSChallenge calls Service.GenerateSIWSChallenge.
func (f IdentityFacet) GenerateSIWSChallenge(ctx context.Context, cache siws.ChallengeCache, domain, address, username string) (siws.SignInInput, error) {
	return f.svc.GenerateSIWSChallenge(ctx, cache, domain, address, username)
}

// GetDiscordUsername calls Service.GetDiscordUsername.
func (f IdentityFacet) GetDiscordUsername(ctx context.Context, userID string) (string, error) {
	return f.svc.GetDiscordUsername(ctx, userID)
}

// GetProviderLink calls Service.GetProviderLink.
func (f IdentityFacet) GetProviderLink(ctx context.Context, providerSlug, subject string) (string, *string, error) {
	return f.svc.GetProviderLink(ctx, providerSlug, subject)
}

// GetProviderLinkByIssuer calls Service.GetProviderLinkByIssuer.
func (f IdentityFacet) GetProviderLinkByIssuer(ctx context.Context, issuer, subject string) (string, *string, error) {
	return f.svc.GetProviderLinkByIssuer(ctx, issuer, subject)
}

// GetProviderUsername calls Service.GetProviderUsername.
func (f IdentityFacet) GetProviderUsername(ctx context.Context, userID, provider string) (string, error) {
	return f.svc.GetProviderUsername(ctx, userID, provider)
}

// GetRemoteApplication calls Service.GetRemoteApplication.
func (f IdentityFacet) GetRemoteApplication(ctx context.Context, issuer string) (*RemoteApplication, error) {
	return f.svc.GetRemoteApplication(ctx, issuer)
}

// GetRemoteApplicationBySlug calls Service.GetRemoteApplicationBySlug.
func (f IdentityFacet) GetRemoteApplicationBySlug(ctx context.Context, slug string) (*RemoteApplication, error) {
	return f.svc.GetRemoteApplicationBySlug(ctx, slug)
}

// GetSolanaAddress calls Service.GetSolanaAddress.
func (f IdentityFacet) GetSolanaAddress(ctx context.Context, userID string) (string, error) {
	return f.svc.GetSolanaAddress(ctx, userID)
}

// GetSolanaLinkedAccount calls Service.GetSolanaLinkedAccount.
func (f IdentityFacet) GetSolanaLinkedAccount(ctx context.Context, userID string) (*SolanaLinkedAccount, error) {
	return f.svc.GetSolanaLinkedAccount(ctx, userID)
}

// GetUserByEmail calls Service.GetUserByEmail.
func (f IdentityFacet) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	return f.svc.GetUserByEmail(ctx, email)
}

// GetUserBySolanaAddress calls Service.GetUserBySolanaAddress.
func (f IdentityFacet) GetUserBySolanaAddress(ctx context.Context, address string) (*User, error) {
	return f.svc.GetUserBySolanaAddress(ctx, address)
}

// GetUserByUsername calls Service.GetUserByUsername.
func (f IdentityFacet) GetUserByUsername(ctx context.Context, username string) (*User, error) {
	return f.svc.GetUserByUsername(ctx, username)
}

// HasPassword calls Service.HasPassword.
func (f IdentityFacet) HasPassword(ctx context.Context, userID string) bool {
	return f.svc.HasPassword(ctx, userID)
}

// LinkProvider calls Service.LinkProvider.
func (f IdentityFacet) LinkProvider(ctx context.Context, userID, provider, subject string, email *string) error {
	return f.svc.LinkProvider(ctx, userID, provider, subject, email)
}

// LinkProviderByIssuer calls Service.LinkProviderByIssuer.
func (f IdentityFacet) LinkProviderByIssuer(ctx context.Context, userID, issuer, providerSlug, subject string, email *string) error {
	return f.svc.LinkProviderByIssuer(ctx, userID, issuer, providerSlug, subject, email)
}

// LinkSolanaWallet calls Service.LinkSolanaWallet.
func (f IdentityFacet) LinkSolanaWallet(ctx context.Context, cache siws.ChallengeCache, userID string, output siws.SignInOutput) error {
	return f.svc.LinkSolanaWallet(ctx, cache, userID, output)
}

// ListRemoteAppAttributeDefs calls Service.ListRemoteAppAttributeDefs.
func (f IdentityFacet) ListRemoteAppAttributeDefs(ctx context.Context, appID string) ([]RemoteAppAttributeDef, error) {
	return f.svc.ListRemoteAppAttributeDefs(ctx, appID)
}

// ListRemoteApplications calls Service.ListRemoteApplications.
func (f IdentityFacet) ListRemoteApplications(ctx context.Context, activeOnly bool) ([]RemoteApplication, error) {
	return f.svc.ListRemoteApplications(ctx, activeOnly)
}

// RegisterRemoteAppAttributeDef calls Service.RegisterRemoteAppAttributeDef.
func (f IdentityFacet) RegisterRemoteAppAttributeDef(ctx context.Context, appID, key string, version int32, definition json.RawMessage) (*RemoteAppAttributeDef, error) {
	return f.svc.RegisterRemoteAppAttributeDef(ctx, appID, key, version, definition)
}

// RemoteApplicationOrgRole calls Service.RemoteApplicationOrgRole.
func (f IdentityFacet) RemoteApplicationOrgRole(ctx context.Context, orgSlug, appID string) (string, error) {
	return f.svc.RemoteApplicationOrgRole(ctx, orgSlug, appID)
}

// RemoteApplicationOrgRoles calls Service.RemoteApplicationOrgRoles.
func (f IdentityFacet) RemoteApplicationOrgRoles(ctx context.Context, appID string) ([]OrgMembership, error) {
	return f.svc.RemoteApplicationOrgRoles(ctx, appID)
}

// RemoveRemoteApplicationMember calls Service.RemoveRemoteApplicationMember.
func (f IdentityFacet) RemoveRemoteApplicationMember(ctx context.Context, orgSlug, appID string) error {
	return f.svc.RemoveRemoteApplicationMember(ctx, orgSlug, appID)
}

// ResolveAndStoreSolanaSNS calls Service.ResolveAndStoreSolanaSNS.
func (f IdentityFacet) ResolveAndStoreSolanaSNS(ctx context.Context, userID, address string) (SolanaLinkedAccount, error) {
	return f.svc.ResolveAndStoreSolanaSNS(ctx, userID, address)
}

// ResolveRemoteAppAttributeDef calls Service.ResolveRemoteAppAttributeDef.
func (f IdentityFacet) ResolveRemoteAppAttributeDef(ctx context.Context, appID, key string, version int32) (*RemoteAppAttributeDef, error) {
	return f.svc.ResolveRemoteAppAttributeDef(ctx, appID, key, version)
}

// ResolveRemoteApplicationAuthority calls Service.ResolveRemoteApplicationAuthority.
func (f IdentityFacet) ResolveRemoteApplicationAuthority(ctx context.Context, appID string) (memberships []OrgMembership, permissions []string, err error) {
	return f.svc.ResolveRemoteApplicationAuthority(ctx, appID)
}

// ResolveRemoteApplicationOrg calls Service.ResolveRemoteApplicationOrg.
func (f IdentityFacet) ResolveRemoteApplicationOrg(ctx context.Context, issuer string) (string, error) {
	return f.svc.ResolveRemoteApplicationOrg(ctx, issuer)
}

// SetProviderUsername calls Service.SetProviderUsername.
func (f IdentityFacet) SetProviderUsername(ctx context.Context, userID, provider, subject, username string) error {
	return f.svc.SetProviderUsername(ctx, userID, provider, subject, username)
}

// UnlinkProvider calls Service.UnlinkProvider.
func (f IdentityFacet) UnlinkProvider(ctx context.Context, userID, provider string) error {
	return f.svc.UnlinkProvider(ctx, userID, provider)
}

// UpsertRemoteApplication calls Service.UpsertRemoteApplication.
func (f IdentityFacet) UpsertRemoteApplication(ctx context.Context, in RemoteApplication) (*RemoteApplication, error) {
	return f.svc.UpsertRemoteApplication(ctx, in)
}

// VerifySIWSAndLogin calls Service.VerifySIWSAndLogin.
func (f IdentityFacet) VerifySIWSAndLogin(ctx context.Context, cache siws.ChallengeCache, output siws.SignInOutput, extra map[string]any) (accessToken string, expiresAt time.Time, refreshToken, userID string, created bool, err error) {
	return f.svc.VerifySIWSAndLogin(ctx, cache, output, extra)
}

// ProvisionOrg calls Service.ProvisionOrg.
func (f BootstrapFacet) ProvisionOrg(ctx context.Context, req OrgProvisionRequest, store OrgManifestTokenStore) (OrgProvisionResult, error) {
	return f.svc.ProvisionOrg(ctx, req, store)
}

// ReconcileBootstrapManifest calls Service.ReconcileBootstrapManifest.
func (f BootstrapFacet) ReconcileBootstrapManifest(ctx context.Context, manifest BootstrapManifest, store BootstrapTokenStore, opts BootstrapReconcileOptions) (BootstrapManifestResult, error) {
	return f.svc.ReconcileBootstrapManifest(ctx, manifest, store, opts)
}

// ReconcileOrgManifest calls Service.ReconcileOrgManifest.
func (f BootstrapFacet) ReconcileOrgManifest(ctx context.Context, manifest OrgManifest, store OrgManifestTokenStore) (OrgManifestResult, error) {
	return f.svc.ReconcileOrgManifest(ctx, manifest, store)
}
