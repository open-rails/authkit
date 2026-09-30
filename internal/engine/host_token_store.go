package engine

import (
	"context"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/password"
)

// Password-hash storage and the short-lived email-verification / password-reset
// token helpers. The tokens themselves live only in the ephemeral store; these
// helpers fail closed (ErrTokenUnverifiable) when it is not configured.

// setPasswordSet removed; presence of password is inferred from user_passwords

func (s *Engine) getPasswordHash(ctx context.Context, userID string) (hash, algo string, err error) {
	if s.pg == nil {
		return "", "", nil
	}
	row, err := s.q.UserPasswordRow(ctx, userID)
	return row.PasswordHash, row.HashAlgo, err
}

func validatePasswordHashForStorage(hash, algo string) error {
	if algo == string(iam.HashLegacyResetRequired) {
		return nil
	}
	return password.ValidateHash(hash, algo)
}
