package engine

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/contact"
	"github.com/open-rails/authkit/internal/db"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/internal/naming"
)

// Account records: the engine's working row (db.User, from sqlc), its public
// projection, the internal lookups the flows use, the login account gate and
// username renames.

// publicUser projects r. An expired temporary ban is no ban.
func publicUser(r *db.User, now time.Time) iam.User {
	u := iam.User{
		ID: r.ID, Email: nullable(deref(r.Email)), Phone: nullable(deref(r.PhoneNumber)), Username: deref(r.Username),
		EmailVerified: r.EmailVerified, PhoneVerified: r.PhoneVerified,
		PreferredLanguage: nullable(deref(r.PreferredLanguage)), AvatarURL: nullable(deref(r.AvatarURL)),
		CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt, LastLogin: r.LastLogin, DeletedAt: r.DeletedAt,
	}
	if banInForce(r.BannedAt, r.BannedUntil, now) {
		u.Ban = &iam.BanState{Until: r.BannedUntil, Reason: nullable(deref(r.BanReason)), By: nullable(deref(r.BannedBy))}
		if r.BannedAt != nil {
			u.Ban.At = *r.BannedAt
		}
	}
	return u
}

// banInForce is the schema's ban_in_force on columns already read: a ban
// exists while banned_at is set (users_ban_chk), and an expired temporary ban
// is none.
func banInForce(bannedAt, bannedUntil *time.Time, now time.Time) bool {
	return bannedAt != nil && (bannedUntil == nil || bannedUntil.After(now))
}

func deref(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func (s *Engine) getUserByEmail(ctx context.Context, email string) (*db.User, error) {
	if s.pg == nil {
		return nil, nil
	}
	r, err := s.q.UserByEmail(ctx, email)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

func (s *Engine) getUserByUsername(ctx context.Context, username string) (*db.User, error) {
	if s.pg == nil {
		return nil, nil
	}
	resolution, err := s.resolveUsername(ctx, username)
	if err != nil {
		return nil, err
	}
	return s.getUserByID(ctx, resolution.ID)
}

func (s *Engine) getUserByID(ctx context.Context, id string) (*db.User, error) {
	if s.pg == nil {
		return nil, nil
	}
	r, err := s.q.UserByID(ctx, id)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

// ensureUserAccess is the login and refresh gate: not soft-deleted, no ban in
// force.
func (s *Engine) ensureUserAccess(_ context.Context, u *db.User) error {
	if u == nil {
		return jwt.ErrTokenInvalidClaims
	}
	if u.DeletedAt != nil || banInForce(u.BannedAt, u.BannedUntil, time.Now()) {
		return errmodel.ErrUserBanned
	}
	return nil
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

func (s *Engine) createUser(ctx context.Context, email, username string) (*db.User, error) {
	if s.pg == nil {
		return nil, nil
	}
	username = strings.TrimSpace(username)
	if err := naming.ValidateImport(s.cfg.Username, username); err != nil {
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
	return &ins, nil
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
	if err := naming.ValidateImport(s.cfg.Username, username); err != nil {
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

func (s *Engine) importUser(ctx context.Context, q *db.Queries, input newAccount) (*db.User, error) {
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
	return &row, nil
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

// renameAuthority is who renames: an account itself obeys the site's rename
// policy; staff renaming another account (root:users:manage) and trusted
// imports bypass only the enabled/cooldown checks, and imports also the
// interactive username rule.
type renameAuthority uint8

const (
	normalRename renameAuthority = iota
	staffRename
	importRename
)

func (s *Engine) renameUsernameTx(ctx context.Context, tx pgx.Tx, id, username string, authority renameAuthority) error {
	q := s.qtx(tx)
	current, err := q.UserNameForUpdate(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return iam.ErrUserNotFound
	}
	if err != nil {
		return err
	}
	oldName := deref(current.Username)
	if strings.EqualFold(oldName, username) {
		if oldName == username || authority == importRename {
			return nil
		}
		// Same identity, new display spelling: no name claim, alias or cooldown.
		return q.UserSetUsernameSpelling(ctx, db.UserSetUsernameSpellingParams{ID: id, Username: &username, AtTime: s.namingNow()})
	}
	if authority != importRename {
		if err := s.ValidateUsername(username); err != nil {
			return err
		}
	}
	now := s.namingNow()
	policy := s.cfg.Username
	if authority == normalRename {
		if err := naming.CheckRename(policy, current.LastRenamedAt, now); err != nil {
			return err
		}
	}
	if err := s.admitName(ctx, iam.NameAdmissionRequest{UserID: id, ActorID: id, CurrentName: oldName, RequestedName: username, Operation: iam.NameRename}); err != nil {
		return err
	}
	if err := renameNameClaim(ctx, tx, id, oldName, username, now, policy); err != nil {
		return err
	}
	return q.UserRename(ctx, db.UserRenameParams{ID: id, Username: &username, AtTime: now})
}

func isUniqueViolation(err error, constraint string) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505" && strings.Contains(pgErr.ConstraintName, constraint)
}
