package embedded

import (
	"context"

	"github.com/open-rails/authkit/internal/db"
)

// Password-hash storage and the short-lived email-verification / password-reset
// token helpers. The tokens themselves live only in the ephemeral store; these
// helpers fail closed (ErrTokenUnverifiable) when it is not configured.

// setPasswordSet removed; presence of password is inferred from profiles.user_passwords

func (s *Client) getPasswordHash(ctx context.Context, userID string) (hash, algo string, params []byte, err error) {
	if s.pg == nil {
		return "", "", nil, nil
	}
	row, err := s.q.UserPasswordRow(ctx, userID)
	return row.PasswordHash, row.HashAlgo, row.HashParams, err
}

func (s *Client) upsertPasswordHash(ctx context.Context, userID, hash, algo string, params []byte) error {
	if s.pg == nil {
		return nil
	}
	return s.q.UserPasswordUpsert(ctx, db.UserPasswordUpsertParams{UserID: userID, PasswordHash: hash, HashAlgo: algo, HashParams: params})
}

// UpsertPasswordHash replaces a precomputed password hash and invalidates all
// sessions and recovery grants. Intended for trusted host import/maintenance.
func (s *Client) UpsertPasswordHash(ctx context.Context, userID, hash, algo string, params []byte) error {
	return s.mutateCredentials(ctx, userID, nil, SessionRevokeReasonAdminSetPassword, func(q *db.Queries, _ db.UserCredentialVersionForUpdateRow) error {
		return q.UserPasswordUpsert(ctx, db.UserPasswordUpsertParams{UserID: userID, PasswordHash: hash, HashAlgo: algo, HashParams: params})
	})
}

// email verification tokens
type emailVerifyToken struct {
	UserID string
	Email  *string
}
