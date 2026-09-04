package authcore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5"

	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/internal/db"
)

// User directory and lifecycle: lookups, access/ban checks, create, import,
// update (email/username), ban/unban, soft/host delete.

// User is defined in the lean authkit contract package (#138 inversion); aliased
// here so engine code keeps using the bare name.
type User = authkit.User

func userFromByIDRow(r db.UserByIDRow) *User {
	return &User{ID: r.ID, Email: r.Email, PhoneNumber: r.PhoneNumber, Username: r.Username, EmailVerified: r.EmailVerified, PhoneVerified: r.PhoneVerified, BannedAt: r.BannedAt, BannedUntil: r.BannedUntil, BanReason: r.BanReason, BannedBy: r.BannedBy, DeletedAt: r.DeletedAt, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt, LastLogin: r.LastLogin, PreferredLanguage: r.PreferredLanguage, AvatarURL: r.AvatarUrl}
}

func userFromByEmailRow(r db.UserByEmailRow) *User {
	return &User{ID: r.ID, Email: r.Email, PhoneNumber: r.PhoneNumber, Username: r.Username, EmailVerified: r.EmailVerified, PhoneVerified: r.PhoneVerified, BannedAt: r.BannedAt, BannedUntil: r.BannedUntil, BanReason: r.BanReason, BannedBy: r.BannedBy, DeletedAt: r.DeletedAt, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt, LastLogin: r.LastLogin}
}

func userFromByPhoneRow(r db.UserByPhoneRow) *User {
	return &User{ID: r.ID, Email: r.Email, PhoneNumber: r.PhoneNumber, Username: r.Username, EmailVerified: r.EmailVerified, PhoneVerified: r.PhoneVerified, BannedAt: r.BannedAt, BannedUntil: r.BannedUntil, BanReason: r.BanReason, BannedBy: r.BannedBy, DeletedAt: r.DeletedAt, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt, LastLogin: r.LastLogin}
}

type ImportUserInput = authkit.ImportUserInput

func (s *Service) getUserByEmail(ctx context.Context, email string) (*User, error) {
	if s.pg == nil {
		return nil, nil
	}
	r, err := s.q.UserByEmail(ctx, email)
	if err != nil {
		return nil, err
	}
	return userFromByEmailRow(r), nil
}

// GetUserByEmail looks up a user by email.
func (s *Service) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	return s.getUserByEmail(ctx, email)
}

func (s *Service) getUserByUsername(ctx context.Context, username string) (*User, error) {
	if s.pg == nil {
		return nil, nil
	}
	resolution, err := s.ResolveUsername(ctx, username)
	if err != nil {
		return nil, err
	}
	return s.getUserByID(ctx, resolution.ID)
}

// GetUserByUsername looks up a user by username.
func (s *Service) GetUserByUsername(ctx context.Context, username string) (*User, error) {
	return s.getUserByUsername(ctx, username)
}

func (s *Service) getUserByID(ctx context.Context, id string) (*User, error) {
	if s.pg == nil {
		return nil, nil
	}
	r, err := s.q.UserByID(ctx, id)
	if err != nil {
		return nil, err
	}
	return userFromByIDRow(r), nil
}

// livenessAllowed is THE account-liveness policy, in one place: a loaded user
// row passes only when it is not soft-deleted, not reserved, and not banned.
// Both gates evaluate it — ensureUserAccess for the single-user login/refresh
// path (which resolves `reserved` with its own query) and UserLivenessByIDs for
// the batch per-request path (#267, which resolves it in the same query) — so
// the two can never disagree about who is live. autoUnbanIfExpired must already
// have run on u, since an expired temporary ban is allowed.
func livenessAllowed(u *User, reserved bool) bool {
	return u != nil && u.DeletedAt == nil && !reserved && !isUserBanned(u)
}

func (s *Service) ensureUserAccess(ctx context.Context, u *User) error {
	if u == nil {
		return jwt.ErrTokenInvalidClaims
	}
	if u.DeletedAt != nil {
		return ErrUserBanned
	}
	reserved, err := s.IsUserReserved(ctx, strings.TrimSpace(u.ID))
	if err != nil {
		return err
	}
	if reserved {
		return ErrUserBanned
	}
	if err := s.autoUnbanIfExpired(ctx, u); err != nil {
		return err
	}
	if !livenessAllowed(u, reserved) {
		return ErrUserBanned
	}
	return nil
}

func (s *Service) ensureUserAccessByID(ctx context.Context, userID string) error {
	if strings.TrimSpace(userID) == "" {
		return jwt.ErrTokenInvalidClaims
	}
	u, err := s.getUserByID(ctx, userID)
	if err != nil || u == nil {
		return errOrUnauthorized(err)
	}
	return s.ensureUserAccess(ctx, u)
}

func (s *Service) autoUnbanIfExpired(ctx context.Context, u *User) error {
	if u == nil || u.BannedUntil == nil {
		return nil
	}
	now := time.Now().UTC()
	if !u.BannedUntil.After(now) {
		if err := s.clearUserBan(ctx, u.ID); err != nil {
			return err
		}
		u.BannedAt = nil
		u.BannedUntil = nil
		u.BanReason = nil
		u.BannedBy = nil
	}
	return nil
}

func isUserBanned(u *User) bool {
	if u == nil {
		return false
	}
	return u.BannedAt != nil || u.BannedUntil != nil || u.BanReason != nil || u.BannedBy != nil
}

func (s *Service) createUser(ctx context.Context, email, username string) (*User, error) {
	if s.pg == nil {
		return nil, nil
	}
	userID, err := newUUIDV7String()
	if err != nil {
		return nil, err
	}
	if err := s.admitName(ctx, authkit.NameAdmissionRequest{OwnerKind: "user", OwnerID: userID, RequestedName: username, Operation: authkit.NameCreate}); err != nil {
		return nil, err
	}
	ins, err := s.q.UserInsert(ctx, db.UserInsertParams{ID: userID, Email: email, Username: &username, AtTime: s.namingNow()})
	if err != nil {
		return nil, nameClaimError(err, "user")
	}
	u := User{ID: ins.ID, Email: ins.Email, Username: ins.Username, EmailVerified: ins.EmailVerified, BannedAt: ins.BannedAt, DeletedAt: ins.DeletedAt}
	return &u, nil
}

// CreateUser inserts a new user with the given email and username.
func (s *Service) CreateUser(ctx context.Context, email, username string) (*User, error) {
	return s.createUser(ctx, email, username)
}

func normalizeImportUserInput(input ImportUserInput) (email *string, phone *string, username string, bannedBy *string, metadata string, createdAt time.Time, updatedAt time.Time, err error) {
	if trimmed := strings.TrimSpace(input.Email); trimmed != "" {
		if err := ValidateEmail(trimmed); err != nil {
			return nil, nil, "", nil, "", time.Time{}, time.Time{}, err
		}
		v := NormalizeEmail(trimmed)
		email = &v
	}
	if trimmed := strings.TrimSpace(input.PhoneNumber); trimmed != "" {
		if err := ValidatePhone(trimmed); err != nil {
			return nil, nil, "", nil, "", time.Time{}, time.Time{}, err
		}
		v := NormalizePhone(trimmed)
		phone = &v
	}
	username = strings.TrimSpace(input.Username)
	if err := validateImportUsername(username); err != nil {
		return nil, nil, "", nil, "", time.Time{}, time.Time{}, err
	}
	if input.BannedBy != nil && strings.TrimSpace(*input.BannedBy) != "" {
		v := strings.TrimSpace(*input.BannedBy)
		bannedBy = &v
	}
	rawMetadata := input.Metadata
	if rawMetadata == nil {
		rawMetadata = map[string]any{}
	}
	metadataJSON, err := json.Marshal(rawMetadata)
	if err != nil {
		return nil, nil, "", nil, "", time.Time{}, time.Time{}, err
	}
	now := time.Now().UTC()
	createdAt = now
	if input.CreatedAt != nil {
		createdAt = input.CreatedAt.UTC()
	}
	updatedAt = now
	if input.UpdatedAt != nil {
		updatedAt = input.UpdatedAt.UTC()
	}
	return email, phone, username, bannedBy, string(metadataJSON), createdAt, updatedAt, nil
}

func (s *Service) ImportUser(ctx context.Context, input ImportUserInput) (*User, error) {
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	email, phone, username, bannedBy, metadata, createdAt, updatedAt, err := normalizeImportUserInput(input)
	if err != nil {
		return nil, err
	}
	userID, err := newUUIDV7String()
	if err != nil {
		return nil, err
	}
	err = s.q.UserImportInsert(ctx, db.UserImportInsertParams{
		ID:            userID,
		Email:         email,
		PhoneNumber:   phone,
		Username:      &username,
		AtTime:        s.namingNow(),
		EmailVerified: input.EmailVerified,
		PhoneVerified: input.PhoneVerified,
		BannedAt:      input.BannedAt,
		BannedUntil:   input.BannedUntil,
		BanReason:     input.BanReason,
		BannedBy:      bannedBy,
		Metadata:      []byte(metadata),
		CreatedAt:     createdAt,
		UpdatedAt:     updatedAt,
	})
	if err != nil {
		return nil, err
	}
	return s.getUserByID(ctx, userID)
}

func (s *Service) UpdateImportedUser(ctx context.Context, userID string, input ImportUserInput) (*User, error) {
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return nil, ErrUserNotFound
	}
	email, phone, username, bannedBy, metadata, createdAt, updatedAt, err := normalizeImportUserInput(input)
	if err != nil {
		return nil, err
	}
	tx, err := s.pg.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := s.renameUsernameTx(ctx, tx, userID, username, importRename); err != nil {
		return nil, err
	}
	updatedID, err := s.qtx(tx).UserImportUpdate(ctx, db.UserImportUpdateParams{
		ID:            userID,
		Email:         email,
		PhoneNumber:   phone,
		Username:      &username,
		EmailVerified: input.EmailVerified,
		PhoneVerified: input.PhoneVerified,
		BannedAt:      input.BannedAt,
		BannedUntil:   input.BannedUntil,
		BanReason:     input.BanReason,
		BannedBy:      bannedBy,
		Metadata:      []byte(metadata),
		CreatedAt:     createdAt,
		UpdatedAt:     updatedAt,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrUserNotFound
	}
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return s.getUserByID(ctx, updatedID)
}

func (s *Service) setEmailVerified(ctx context.Context, id string, v bool) error {
	if s.pg == nil {
		return nil
	}
	return s.q.UserSetEmailVerified(ctx, db.UserSetEmailVerifiedParams{ID: id, EmailVerified: v})
}

// SetEmailVerified sets a user's email-verified flag.
func (s *Service) SetEmailVerified(ctx context.Context, id string, v bool) error {
	return s.setEmailVerified(ctx, id, v)
}

func (s *Service) setLastLogin(ctx context.Context, id string, t time.Time) error {
	if s.pg == nil {
		return nil
	}
	return s.q.UserSetLastLogin(ctx, db.UserSetLastLoginParams{ID: id, LastLogin: &t})
}

func (s *Service) clearUserBan(ctx context.Context, userID string) error {
	if s.pg == nil {
		return fmt.Errorf("postgres not configured")
	}
	if strings.TrimSpace(userID) == "" {
		return fmt.Errorf("invalid_user")
	}
	return s.q.UserClearBan(ctx, userID)
}

// BanUser disables a user account and stores ban metadata. bannedBy is the
// acting user and must hold every root grant the target holds (#286), so a
// bounded operator can never lock out a more privileged account. The ban,
// session revoke and device-key revoke commit together.
func (s *Service) BanUser(ctx context.Context, userID string, reason *string, until *time.Time, bannedBy string) error {
	if s.pg == nil {
		return fmt.Errorf("postgres not configured")
	}
	if strings.TrimSpace(userID) == "" {
		return fmt.Errorf("invalid_user")
	}
	now := time.Now().UTC()
	if until != nil && !until.UTC().After(now) {
		return ErrInvalidUntil
	}
	if err := s.authorizeAccountAuthority(ctx, bannedBy, userID); err != nil {
		return err
	}
	var reasonPtr *string
	if reason != nil {
		trimmed := strings.TrimSpace(*reason)
		if trimmed != "" {
			reasonPtr = &trimmed
		}
	}
	bannedBy = strings.TrimSpace(bannedBy)
	var untilPtr *time.Time
	if until != nil {
		t := until.UTC()
		untilPtr = &t
	}
	tx, err := s.pg.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := s.qtx(tx).UserBan(ctx, db.UserBanParams{ID: userID, BannedAt: &now, BannedUntil: untilPtr, BanReason: reasonPtr, BannedBy: &bannedBy}); err != nil {
		return err
	}
	sessionIDs, err := s.revokeCredentialsTx(ctx, tx, userID)
	if err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	s.logSessionsRevoked(ctx, userID, sessionIDs, SessionRevokeReasonBanned)
	return nil
}

// UnbanUser clears ban metadata and re-enables the account.
func (s *Service) UnbanUser(ctx context.Context, userID string) error {
	return s.clearUserBan(ctx, userID)
}

// SoftDeleteUser marks the user deleted without dropping rows. Sessions and
// device keys are revoked in the same transaction.
func (s *Service) SoftDeleteUser(ctx context.Context, id string) error {
	if s.pg == nil {
		return nil
	}
	tx, err := s.pg.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	sessionIDs, err := s.revokeCredentialsTx(ctx, tx, id)
	if err != nil {
		return err
	}
	if err := s.qtx(tx).UserSoftDelete(ctx, id); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	s.logSessionsRevoked(ctx, id, sessionIDs, SessionRevokeReasonSoftDeleted)
	return nil
}

// revokeCredentialsTx revokes every refresh session and device key of userID
// inside tx, returning the revoked session ids for post-commit audit logging.
func (s *Service) revokeCredentialsTx(ctx context.Context, tx pgx.Tx, userID string) ([]string, error) {
	ids, err := s.qtx(tx).SessionsRevokeAll(ctx, db.SessionsRevokeAllParams{UserID: userID, Issuer: s.cfg.Token.Issuer})
	if err != nil {
		return nil, err
	}
	if err := s.revokeAllDeviceKeys(ctx, tx, userID); err != nil {
		return nil, err
	}
	return ids, nil
}

func (s *Service) logSessionsRevoked(ctx context.Context, userID string, sessionIDs []string, reason SessionRevokeReason) {
	r := string(reason)
	for _, sid := range sessionIDs {
		s.logSessionRevoked(ctx, userID, sid, &r)
	}
}

// HostDeleteUser performs deletion on behalf of the host application.
// If soft is true, it performs a soft delete (see SoftDeleteUser). If false, it hard-deletes the user
// and all dependent rows via ON DELETE CASCADE.
func (s *Service) HostDeleteUser(ctx context.Context, id string, soft bool) error {
	if soft {
		return s.SoftDeleteUser(ctx, id)
	}
	return s.AdminDeleteUser(ctx, id)
}

// RenameAuthority is internal: ordinary account changes obey the site policy;
// trusted import updates can bypass only the enabled/cooldown checks.
type renameAuthority uint8

const (
	normalRename renameAuthority = iota
	importRename
)

// UpdateUsername applies the deployment policy to an account rename.
func (s *Service) UpdateUsername(ctx context.Context, id, username string) error {
	if err := s.requirePG(); err != nil {
		return err
	}
	username = strings.TrimSpace(username)
	if err := ValidateUsername(username); err != nil {
		return err
	}
	tx, err := s.pg.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := s.renameUsernameTx(ctx, tx, id, username, normalRename); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
func (s *Service) renameUsernameTx(ctx context.Context, tx pgx.Tx, id, username string, authority renameAuthority) error {
	q := db.ForSchema(tx, s.dbSchema())
	var old *string
	var last *time.Time
	if err := q.QueryRow(ctx, `SELECT username::text,last_renamed_at FROM profiles.users WHERE id=$1::uuid AND deleted_at IS NULL FOR UPDATE`, id).Scan(&old, &last); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrUserNotFound
		}
		return err
	}
	oldName := ""
	if old != nil {
		oldName = *old
	}
	if strings.EqualFold(oldName, username) {
		return nil
	}
	now := s.namingNow()
	policy := s.NamingPolicy()
	if authority == normalRename {
		if err := policy.CheckRename(last, now); err != nil {
			return err
		}
	}
	if err := s.admitName(ctx, authkit.NameAdmissionRequest{OwnerKind: "user", OwnerID: id, ActorID: id, CurrentName: oldName, RequestedName: username, Operation: authkit.NameRename}); err != nil {
		return err
	}
	if err := renameNameClaim(ctx, q, "user", "", id, oldName, username, now, policy); err != nil {
		return err
	}
	if _, err := q.Exec(ctx, `UPDATE profiles.users SET username=$2,last_renamed_at=$3,updated_at=$3 WHERE id=$1::uuid`, id, username, now); err != nil {
		return err
	}
	if oldName != "" {
		if _, err := q.Exec(ctx, `INSERT INTO profiles.user_renames(user_id,from_slug,renamed_at) VALUES ($1::uuid,lower($2),$3)`, id, oldName, now); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) updateEmail(ctx context.Context, id, email string) error {
	if s.pg == nil {
		return nil
	}
	if err := ValidateEmail(email); err != nil {
		return err
	}
	trimmed := NormalizeEmail(email)
	u, err := s.getUserByID(ctx, id)
	if err != nil {
		return err
	}

	if u == nil {
		return fmt.Errorf("user not found")
	}

	if u.Email != nil && strings.EqualFold(*u.Email, trimmed) {
		return nil
	}

	if err := s.q.UserSetEmailAndUnverify(ctx, db.UserSetEmailAndUnverifyParams{ID: id, Email: trimmed}); err != nil {
		return err
	}

	return s.RequestEmailVerification(ctx, trimmed, 0)
}

// UpdateEmail updates a user's email and re-triggers email verification.
func (s *Service) UpdateEmail(ctx context.Context, id, email string) error {
	return s.updateEmail(ctx, id, email)
}

// maxAvatarURLLen caps the stored avatar URL/key string (#262) — a sanity
// bound, not format validation: hosts may store URLs or opaque object keys.
const maxAvatarURLLen = 2048

// UpdateAvatarURL sets (nil clears) a user's avatar URL/key string (#262).
// Blob storage and content validation are host-owned; authkit stores the
// string verbatim (trimmed) and serves it on GET /me.
func (s *Service) UpdateAvatarURL(ctx context.Context, id string, avatarURL *string) error {
	if s.pg == nil {
		return nil
	}
	if avatarURL != nil {
		trimmed := strings.TrimSpace(*avatarURL)
		if trimmed == "" {
			avatarURL = nil
		} else {
			if len(trimmed) > maxAvatarURLLen || strings.ContainsAny(trimmed, "\n\r") {
				return authkit.ErrAvatarURLInvalid
			}
			avatarURL = &trimmed
		}
	}
	n, err := s.q.UserSetAvatarURL(ctx, db.UserSetAvatarURLParams{ID: id, AvatarUrl: avatarURL})
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrUserNotFound
	}
	return nil
}

// IsUserAllowed reports whether a user exists and passes access/ban checks.
func (s *Service) IsUserAllowed(ctx context.Context, userID string) (bool, error) {
	if s.pg == nil {
		return true, nil
	}
	u, err := s.getUserByID(ctx, userID)
	if err != nil || u == nil {
		return false, err
	}
	if err := s.ensureUserAccess(ctx, u); err != nil {
		if errors.Is(err, ErrUserBanned) || errors.Is(err, jwt.ErrTokenInvalidClaims) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}
