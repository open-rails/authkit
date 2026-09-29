package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/contact"
	"github.com/open-rails/authkit/internal/db"
	"github.com/open-rails/authkit/internal/errmodel"
)

// Account records: the engine's working row, its public projection, the
// internal lookups the flows use, the liveness policy and username renames.

// userRecord is a users row as the flows read it. iam.User is its public
// projection (public).
type userRecord struct {
	ID                string
	Email             *string
	PhoneNumber       *string
	Username          *string
	EmailVerified     bool
	PhoneVerified     bool
	BannedAt          *time.Time
	BannedUntil       *time.Time
	BanReason         *string
	BannedBy          *string
	DeletedAt         *time.Time
	CreatedAt         time.Time
	UpdatedAt         time.Time
	LastLogin         *time.Time
	PreferredLanguage *string
	AvatarURL         *string
}

// public projects r; reserved comes from the same read. An expired temporary
// ban is no ban.
func (r *userRecord) public(reserved bool, now time.Time) iam.User {
	u := iam.User{
		ID: r.ID, Email: deref(r.Email), Phone: deref(r.PhoneNumber), Username: deref(r.Username),
		EmailVerified: r.EmailVerified, PhoneVerified: r.PhoneVerified,
		PreferredLanguage: deref(r.PreferredLanguage), AvatarURL: deref(r.AvatarURL),
		CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt, LastLogin: r.LastLogin, DeletedAt: r.DeletedAt,
	}
	if banInForce(r, now) {
		u.Ban = &iam.BanState{Until: r.BannedUntil, Reason: deref(r.BanReason), By: deref(r.BannedBy)}
		if r.BannedAt != nil {
			u.Ban.At = *r.BannedAt
		}
	}
	u.Live = r.DeletedAt == nil && !reserved && u.Ban == nil
	return u
}

// banInForce is isUserBanned without the lazy unban: a ban whose Until has
// passed is over.
func banInForce(r *userRecord, now time.Time) bool {
	return isUserBanned(r) && (r.BannedUntil == nil || r.BannedUntil.After(now))
}

func deref(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func userFromByIDRow(r db.UserByIDRow) *userRecord {
	return &userRecord{ID: r.ID, Email: r.Email, PhoneNumber: r.PhoneNumber, Username: r.Username, EmailVerified: r.EmailVerified, PhoneVerified: r.PhoneVerified, BannedAt: r.BannedAt, BannedUntil: r.BannedUntil, BanReason: r.BanReason, BannedBy: r.BannedBy, DeletedAt: r.DeletedAt, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt, LastLogin: r.LastLogin, PreferredLanguage: r.PreferredLanguage, AvatarURL: r.AvatarUrl}
}

func userFromByEmailRow(r db.UserByEmailRow) *userRecord {
	return &userRecord{ID: r.ID, Email: r.Email, PhoneNumber: r.PhoneNumber, Username: r.Username, EmailVerified: r.EmailVerified, PhoneVerified: r.PhoneVerified, BannedAt: r.BannedAt, BannedUntil: r.BannedUntil, BanReason: r.BanReason, BannedBy: r.BannedBy, DeletedAt: r.DeletedAt, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt, LastLogin: r.LastLogin}
}

func userFromByPhoneRow(r db.UserByPhoneRow) *userRecord {
	return &userRecord{ID: r.ID, Email: r.Email, PhoneNumber: r.PhoneNumber, Username: r.Username, EmailVerified: r.EmailVerified, PhoneVerified: r.PhoneVerified, BannedAt: r.BannedAt, BannedUntil: r.BannedUntil, BanReason: r.BanReason, BannedBy: r.BannedBy, DeletedAt: r.DeletedAt, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt, LastLogin: r.LastLogin}
}

func (s *Engine) getUserByEmail(ctx context.Context, email string) (*userRecord, error) {
	if s.pg == nil {
		return nil, nil
	}
	r, err := s.q.UserByEmail(ctx, email)
	if err != nil {
		return nil, err
	}
	return userFromByEmailRow(r), nil
}

func (s *Engine) getUserByUsername(ctx context.Context, username string) (*userRecord, error) {
	if s.pg == nil {
		return nil, nil
	}
	resolution, err := s.resolveUsername(ctx, username)
	if err != nil {
		return nil, err
	}
	return s.getUserByID(ctx, resolution.ID)
}

func (s *Engine) getUserByID(ctx context.Context, id string) (*userRecord, error) {
	if s.pg == nil {
		return nil, nil
	}
	r, err := s.q.UserByID(ctx, id)
	if err != nil {
		return nil, err
	}
	return userFromByIDRow(r), nil
}

// livenessAllowed is the login and refresh gate: not soft-deleted, not
// reserved, not banned. autoUnbanIfExpired must already have run on u, since
// an expired temporary ban is allowed; userRecord.public computes the same
// verdict for reads (iam.User.Live) without that write.
func livenessAllowed(u *userRecord, reserved bool) bool {
	return u != nil && u.DeletedAt == nil && !reserved && !isUserBanned(u)
}

func (s *Engine) ensureUserAccess(ctx context.Context, u *userRecord) error {
	if u == nil {
		return jwt.ErrTokenInvalidClaims
	}
	if u.DeletedAt != nil {
		return errmodel.ErrUserBanned
	}
	reserved, err := s.isUserReserved(ctx, strings.TrimSpace(u.ID))
	if err != nil {
		return err
	}
	if reserved {
		return errmodel.ErrUserBanned
	}
	if err := s.autoUnbanIfExpired(ctx, u); err != nil {
		return err
	}
	if !livenessAllowed(u, reserved) {
		return errmodel.ErrUserBanned
	}
	return nil
}

func (s *Engine) autoUnbanIfExpired(ctx context.Context, u *userRecord) error {
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

func isUserBanned(u *userRecord) bool {
	if u == nil {
		return false
	}
	return u.BannedAt != nil || u.BannedUntil != nil || u.BanReason != nil || u.BannedBy != nil
}

// mapUserUniqueViolation turns a users-table unique violation into the typed
// conflict the identifier's flows already speak (#326): the race loser of a
// check-then-insert gets username_in_use / email_in_use / phone_in_use, never
// a raw 23505.
func mapUserUniqueViolation(err error) error {
	switch {
	case err == nil:
		return nil
	case isUniqueViolation(err, "users_username_key"), isUniqueViolation(err, "name_claims_pkey"):
		return iam.ErrUsernameInUse
	case isUniqueViolation(err, "users_email_uidx"):
		return iam.ErrEmailInUse
	case isUniqueViolation(err, "users_phone_number_key"):
		return iam.ErrPhoneInUse
	}
	return err
}

func (s *Engine) createUser(ctx context.Context, email, username string) (*userRecord, error) {
	if s.pg == nil {
		return nil, nil
	}
	username = strings.TrimSpace(username)
	if err := s.cfg.Username.ValidateImport(username); err != nil {
		return nil, err
	}
	userID, err := newUUIDV7String()
	if err != nil {
		return nil, err
	}
	if err := s.admitName(ctx, iam.NameAdmissionRequest{UserID: userID, RequestedName: username, Operation: iam.NameCreate}); err != nil {
		return nil, err
	}
	tx, err := s.pg.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	ins, err := s.qtx(tx).UserInsert(ctx, db.UserInsertParams{ID: userID, Email: email, Username: &username, AtTime: s.namingNow()})
	if err != nil {
		return nil, mapUserUniqueViolation(err)
	}
	if err := s.emitEvents(ctx, tx, iam.UserActor(ins.ID), userEvent(iam.EventUserRegistered, ins.ID)); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	u := userRecord{ID: ins.ID, Email: ins.Email, Username: ins.Username, EmailVerified: ins.EmailVerified, BannedAt: ins.BannedAt, DeletedAt: ins.DeletedAt}
	return &u, nil
}

func (s *Engine) normalizeImportUserInput(input newAccount) (email *string, phone *string, username string, bannedBy *string, metadata string, createdAt time.Time, updatedAt time.Time, err error) {
	if trimmed := strings.TrimSpace(input.Email); trimmed != "" {
		if err := contact.ValidateEmail(trimmed); err != nil {
			return nil, nil, "", nil, "", time.Time{}, time.Time{}, err
		}
		v := contact.NormalizeEmail(trimmed)
		email = &v
	}
	if trimmed := strings.TrimSpace(input.PhoneNumber); trimmed != "" {
		if err := contact.ValidatePhone(trimmed); err != nil {
			return nil, nil, "", nil, "", time.Time{}, time.Time{}, err
		}
		v := contact.NormalizePhone(trimmed)
		phone = &v
	}
	username = strings.TrimSpace(input.Username)
	if err := s.cfg.Username.ValidateImport(username); err != nil {
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

func (s *Engine) importUser(ctx context.Context, q *db.Queries, input newAccount) (*userRecord, error) {
	email, phone, username, bannedBy, metadata, createdAt, updatedAt, err := s.normalizeImportUserInput(input)
	if err != nil {
		return nil, err
	}
	userID, err := newUUIDV7String()
	if err != nil {
		return nil, err
	}
	err = q.UserImportInsert(ctx, db.UserImportInsertParams{
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
	row, err := q.UserByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	return userFromByIDRow(row), nil
}

func (s *Engine) updateImportedUserTx(ctx context.Context, tx pgx.Tx, userID string, input newAccount) (*userRecord, error) {
	email, phone, username, bannedBy, metadata, createdAt, updatedAt, err := s.normalizeImportUserInput(input)
	if err != nil {
		return nil, err
	}
	banned := input.BannedAt != nil || input.BannedUntil != nil || input.BanReason != nil || bannedBy != nil
	if input.BannedUntil != nil && !input.BannedUntil.After(time.Now()) {
		banned = false
	}
	reserved := metadataMarksReserved([]byte(metadata))
	st := s.groupStoreFor(tx)
	if banned || reserved {
		if err := s.refuseSubjectOwnerLoss(ctx, st, iam.UserSubject(userID)); err != nil {
			return nil, err
		}
	}
	before, err := readContactState(ctx, tx, userID, true)
	if err != nil {
		return nil, err
	}
	// Marking a contact verified is a proof transition (L8).
	if input.EmailVerified || input.PhoneVerified {
		if _, err := s.retirePreProofCredentials(ctx, tx, userID, nil); err != nil {
			return nil, err
		}
	}
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
		return nil, iam.ErrUserNotFound
	}
	if err != nil {
		return nil, err
	}
	if err := s.keepMFAHolderProven(ctx, tx, userID, before); err != nil {
		return nil, err
	}
	if banned || reserved {
		if _, err := s.revokeCredentialsTx(ctx, tx, userID); err != nil {
			return nil, err
		}
		if err := s.revokeCredentialsOf(ctx, st, userID); err != nil {
			return nil, err
		}
	}
	row, err := s.qtx(tx).UserByID(ctx, updatedID)
	if err != nil {
		return nil, err
	}
	return userFromByIDRow(row), nil
}

func (s *Engine) clearUserBan(ctx context.Context, userID string) error {
	if s.pg == nil {
		return fmt.Errorf("postgres not configured")
	}
	if strings.TrimSpace(userID) == "" {
		return fmt.Errorf("invalid_user")
	}
	return s.q.UserClearBan(ctx, userID)
}

// revokeCredentialsTx revokes every refresh session (all account issuers) and
// device key of userID inside tx, returning sessions for post-commit audit.
func (s *Engine) revokeCredentialsTx(ctx context.Context, tx pgx.Tx, userID string) ([]revokedSession, error) {
	revoked, err := revokeSessionsTx(ctx, s.qtx(tx), userID, s.accountIssuers(), nil)
	if err != nil {
		return nil, err
	}
	if _, err := s.revokeAllDeviceKeys(ctx, tx, userID); err != nil {
		return nil, err
	}
	return revoked, nil
}

// RenameAuthority is internal: ordinary account changes obey the site policy;
// trusted import updates can bypass only the enabled/cooldown checks.
type renameAuthority uint8

const (
	normalRename renameAuthority = iota
	importRename
)

func (s *Engine) renameUsernameTx(ctx context.Context, tx pgx.Tx, id, username string, authority renameAuthority) error {
	q := tx
	var old *string
	var last *time.Time
	if err := q.QueryRow(ctx, `SELECT username::text,last_renamed_at FROM users WHERE id=$1::uuid AND deleted_at IS NULL FOR UPDATE`, id).Scan(&old, &last); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return iam.ErrUserNotFound
		}
		return err
	}
	oldName := ""
	if old != nil {
		oldName = *old
	}
	if strings.EqualFold(oldName, username) {
		if oldName == username || authority != normalRename {
			return nil
		}
		// Same identity, new display spelling: no name claim, alias or cooldown.
		_, err := q.Exec(ctx, `UPDATE users SET username=$2,updated_at=$3 WHERE id=$1::uuid`, id, username, s.namingNow())
		return err
	}
	if authority == normalRename {
		if err := s.ValidateUsername(username); err != nil {
			return err
		}
	}
	now := s.namingNow()
	policy := s.NamingPolicy()
	if authority == normalRename {
		if err := policy.CheckRename(last, now); err != nil {
			return err
		}
	}
	if err := s.admitName(ctx, iam.NameAdmissionRequest{UserID: id, ActorID: id, CurrentName: oldName, RequestedName: username, Operation: iam.NameRename}); err != nil {
		return err
	}
	if err := renameNameClaim(ctx, q, id, oldName, username, now, policy); err != nil {
		return err
	}
	if _, err := q.Exec(ctx, `UPDATE users SET username=$2,last_renamed_at=$3,updated_at=$3 WHERE id=$1::uuid`, id, username, now); err != nil {
		return err
	}

	return nil
}
