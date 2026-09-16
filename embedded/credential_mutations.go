package embedded

import (
	"context"
	"errors"
	"strings"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5"
	"github.com/open-rails/authkit/internal/db"
	"github.com/open-rails/authkit/password"
)

// mutateCredentials owns the account lock and the transaction for credential
// writes. No caller may authorize from a password/version read before this lock.
func (s *Client) mutateCredentials(ctx context.Context, userID string, keepSessionID *string, reason SessionRevokeReason, apply func(*db.Queries, db.UserCredentialVersionForUpdateRow) error) error {
	if s.pg == nil {
		return jwt.ErrTokenUnverifiable
	}
	tx, err := s.pg.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	q := s.qtx(tx)
	revoked, err := s.mutateCredentialsTx(ctx, q, userID, keepSessionID, apply)
	if err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	s.logRevokedSessions(ctx, userID, revoked, string(reason))
	return nil
}

// mutateCredentialsTx is shared by credential flows and transactional host bootstrap.
// Credentials are account-wide, so sessions on every account issuer are revoked.
// The caller owns commit/rollback and logs returned sessions only after commit.
func (s *Client) mutateCredentialsTx(ctx context.Context, q *db.Queries, userID string, keepSessionID *string, apply func(*db.Queries, db.UserCredentialVersionForUpdateRow) error) ([]revokedSession, error) {
	account, err := q.UserCredentialVersionForUpdate(ctx, userID)
	if err != nil {
		return nil, err
	}
	if err := apply(q, account); err != nil {
		return nil, err
	}
	if err := q.UserAdvanceCredentialVersion(ctx, userID); err != nil {
		return nil, err
	}
	return revokeSessionsTx(ctx, q, userID, s.accountIssuers(), keepSessionID)
}

func (s *Client) changePassword(ctx context.Context, userID, new string, current *string, keepSessionID *string, grant *passwordResetData, reason SessionRevokeReason) error {
	if strings.TrimSpace(userID) == "" {
		return jwt.ErrTokenInvalidClaims
	}
	if err := ValidatePassword(new); err != nil {
		return err
	}
	phc, err := password.HashArgon2id(new)
	if err != nil {
		return err
	}
	err = s.mutateCredentials(ctx, userID, keepSessionID, reason, func(q *db.Queries, account db.UserCredentialVersionForUpdateRow) error {
		if grant != nil {
			if account.DeletedAt != nil || account.BannedAt != nil && (account.BannedUntil == nil || account.BannedUntil.After(time.Now())) {
				return ErrUserBanned
			}
			reserved, err := q.UserIsReserved(ctx, userID)
			if err != nil {
				return err
			}
			if reserved {
				return ErrUserBanned
			}
			contact := account.Email
			if grant.Channel == "sms" {
				contact = account.PhoneNumber
			}
			if grant.Version <= 0 || grant.Version != account.CredentialVersion || (grant.Channel != "email" && grant.Channel != "sms") || contact == nil || *contact != grant.Contact {
				return jwt.ErrTokenInvalidClaims
			}
		}
		if current != nil {
			row, err := q.UserPasswordRow(ctx, userID)
			if err != nil && !errors.Is(err, pgx.ErrNoRows) {
				return err
			}
			if err == nil {
				if err := verifyPasswordHash(row.PasswordHash, row.HashAlgo, *current); err != nil {
					return err
				}
			}
		}
		return q.UserPasswordUpsert(ctx, db.UserPasswordUpsertParams{UserID: userID, PasswordHash: phc, HashAlgo: "argon2id"})
	})
	if err != nil {
		return err
	}
	sessionID := ""
	if keepSessionID != nil {
		sessionID = *keepSessionID
	}
	s.LogPasswordChanged(ctx, userID, sessionID, nil, nil)
	return nil
}

func verifyPasswordHash(hash, algo, pass string) error {
	var ok bool
	var err error
	switch algo {
	case HashAlgoLegacyResetRequired:
		return ErrPasswordResetRequired
	case "argon2id":
		ok, err = password.VerifyArgon2id(hash, pass)
	case "bcrypt":
		ok, err = password.VerifyBcrypt(hash, pass)
	default:
		return ErrPasswordResetRequired
	}
	if errors.Is(err, password.ErrInvalidHash) {
		return ErrPasswordResetRequired
	}
	if err != nil || !ok {
		return jwt.ErrTokenInvalidClaims
	}
	return nil
}
