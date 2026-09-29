package authkit

import (
	"context"
	"crypto/ed25519"
	"time"

	"github.com/open-rails/authkit/iam"
)

// User and account operations.

func (a *Auth) CreateUser(ctx context.Context, email string, username string) (*iam.User, error) {
	return a.engine.CreateUser(ctx, email, username)
}

func (a *Auth) GetUserByEmail(ctx context.Context, email string) (*iam.User, error) {
	return a.engine.GetUserByEmail(ctx, email)
}

func (a *Auth) GetUserByPhone(ctx context.Context, phone string) (*iam.User, error) {
	return a.engine.GetUserByPhone(ctx, phone)
}

func (a *Auth) GetUserByUsername(ctx context.Context, username string) (*iam.User, error) {
	return a.engine.GetUserByUsername(ctx, username)
}

// GetUserMetadata reads application-owned JSON under trusted host authority.
// Hosts select public fields explicitly; the metadata map is not a public profile.
func (a *Auth) GetUserMetadata(ctx context.Context, userID string) (map[string]any, error) {
	return a.engine.GetUserMetadata(ctx, userID)
}

// SoftDeleteUsers begins the fixed 30-day recoverable account lifecycle:
// per-item BEST-EFFORT — the returned OpResults pinpoint the failures; the
// outer error is a whole-call failure only (e.g. no store).
func (a *Auth) SoftDeleteUsers(ctx context.Context, userIDs []string) ([]iam.OpResult, error) {
	return a.engine.SoftDeleteUsers(ctx, userIDs)
}

func (a *Auth) MarkEmailVerified(ctx context.Context, id string) error {
	return a.engine.MarkEmailVerified(ctx, id)
}

// UpdateAvatarURL sets (or clears, with nil) the user's avatar URL/key
// string (#262). Blob storage/validation is the host's job.
func (a *Auth) UpdateAvatarURL(ctx context.Context, id string, avatarURL *string) error {
	return a.engine.UpdateAvatarURL(ctx, id, avatarURL)
}

func (a *Auth) UpdateEmail(ctx context.Context, id string, email string) error {
	return a.engine.UpdateEmail(ctx, id, email)
}

func (a *Auth) UpdateUsername(ctx context.Context, id string, username string) error {
	return a.engine.UpdateUsername(ctx, id, username)
}

func (a *Auth) UpdateImportedUser(ctx context.Context, userID string, input iam.ImportUserInput) (*iam.User, error) {
	return a.engine.UpdateImportedUser(ctx, userID, input)
}

func (a *Auth) ImportUsers(ctx context.Context, inputs []iam.ImportUserInput) (iam.ImportUsersResult, error) {
	return a.engine.ImportUsers(ctx, inputs)
}

// UsersByIDs resolves many user IDs to slim display projections in ONE
// query; missing IDs are absent. PRIVILEGED — the projection carries Email;
// render other users with PublicUsersByIDs.
func (a *Auth) UsersByIDs(ctx context.Context, ids []string) (map[string]iam.UserRef, error) {
	return a.engine.UsersByIDs(ctx, ids)
}

// PublicUsersByIDs is the PUBLIC-SAFE twin (#268): no email; soft-deleted
// users come back as tombstones, banned users normally, unknown ids absent.
func (a *Auth) PublicUsersByIDs(ctx context.Context, ids []string) (map[string]iam.PublicUserRef, error) {
	return a.engine.PublicUsersByIDs(ctx, ids)
}

// UserLivenessByIDs is the batch account-liveness read behind verify's
// per-request liveness gate (#267). Errors PROPAGATE so authorization
// callers fail closed; unknown ids are absent and a gate treats that as a
// denial.
func (a *Auth) UserLivenessByIDs(ctx context.Context, ids []string) (map[string]iam.UserLiveness, error) {
	return a.engine.UserLivenessByIDs(ctx, ids)
}

// ActiveDeviceKeys returns the user's unrevoked device public keys in
// enrollment order, for a host that admits the user's machines. Errors
// propagate; ErrDeviceKeysDisabled without Config.DeviceKeys.Enabled.
func (a *Auth) ActiveDeviceKeys(ctx context.Context, userID string) ([]ed25519.PublicKey, error) {
	return a.engine.ActiveDeviceKeys(ctx, userID)
}

func (a *Auth) UpsertPasswordHash(ctx context.Context, userID string, hash string, algo string) error {
	return a.engine.UpsertPasswordHash(ctx, userID, hash, algo)
}

func (a *Auth) AdminGetUser(ctx context.Context, id string) (*iam.AdminUser, error) {
	return a.engine.AdminGetUser(ctx, id)
}

func (a *Auth) AdminListUsers(ctx context.Context, opts iam.AdminUserListOptions) (*iam.AdminListUsersResult, error) {
	return a.engine.AdminListUsers(ctx, opts)
}

func (a *Auth) AdminSetPassword(ctx context.Context, userID string, new string) error {
	return a.engine.AdminSetPassword(ctx, userID, new)
}

func (a *Auth) BanUser(ctx context.Context, userID string, reason *string, until *time.Time, bannedBy string) error {
	return a.engine.BanUser(ctx, userID, reason, until, bannedBy)
}

func (a *Auth) UnbanUser(ctx context.Context, userID string) error {
	return a.engine.UnbanUser(ctx, userID)
}

// OperatorRestoreUsers restores soft-deleted accounts before their fixed
// recovery deadline under explicit trusted host authority.
func (a *Auth) OperatorRestoreUsers(ctx context.Context, userIDs []string) ([]iam.OpResult, error) {
	return a.engine.OperatorRestoreUsers(ctx, userIDs)
}

// ImportUnverifiedSolanaLinks preserves host migration associations without
// turning them into credentials; only a subsequent SIWS proof verifies a link.
func (a *Auth) ImportUnverifiedSolanaLinks(ctx context.Context, inputs []iam.ImportUnverifiedSolanaLinkInput) (iam.ImportUnverifiedSolanaLinksResult, error) {
	return a.engine.ImportUnverifiedSolanaLinks(ctx, inputs)
}

func (a *Auth) LinkProviderByIssuer(ctx context.Context, userID string, issuer string, providerSlug string, subject string, email *string) error {
	return a.engine.LinkProviderByIssuer(ctx, userID, issuer, providerSlug, subject, email)
}
