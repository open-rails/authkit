package embedded

import (
	"context"

	"github.com/open-rails/authkit/internal/db"
	"github.com/open-rails/authkit/password"
)

// Password-hash storage and the short-lived email-verification / password-reset
// token helpers. The tokens themselves live only in the ephemeral store; these
// helpers fail closed (ErrTokenUnverifiable) when it is not configured.

// setPasswordSet removed; presence of password is inferred from user_passwords

func (s *engine) getPasswordHash(ctx context.Context, userID string) (hash, algo string, err error) {
	if s.pg == nil {
		return "", "", nil
	}
	row, err := s.q.UserPasswordRow(ctx, userID)
	return row.PasswordHash, row.HashAlgo, err
}

// UpsertPasswordHash replaces a precomputed password hash and invalidates all
// sessions and recovery grants. Intended for trusted host import/maintenance.
func (s *engine) UpsertPasswordHash(ctx context.Context, userID, hash, algo string) error {
	if err := validatePasswordHashForStorage(hash, algo); err != nil {
		return err
	}
	return s.mutateCredentials(ctx, userID, nil, SessionRevokeReasonAdminSetPassword, func(q *db.Queries, _ db.UserCredentialVersionForUpdateRow) error {
		return q.UserPasswordUpsert(ctx, db.UserPasswordUpsertParams{UserID: userID, PasswordHash: hash, HashAlgo: algo})
	})
}

func validatePasswordHashForStorage(hash, algo string) error {
	if algo == HashAlgoLegacyResetRequired {
		return nil
	}
	return password.ValidateHash(hash, algo)
}
