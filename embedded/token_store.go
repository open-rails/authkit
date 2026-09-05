package embedded

import (
	"context"
	"fmt"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
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

// UpsertPasswordHash stores a precomputed password hash for a user.
func (s *Client) UpsertPasswordHash(ctx context.Context, userID, hash, algo string, params []byte) error {
	return s.upsertPasswordHash(ctx, userID, hash, algo, params)
}

// email verification tokens
type emailVerifyToken struct {
	UserID string
	Email  *string
}

func (s *Client) useResetToken(ctx context.Context, tokenHash string) (struct{ UserID string }, error) {
	if s.useEphemeralStore() {
		userID, err := s.consumePasswordReset(ctx, tokenHash)
		return struct{ UserID string }{UserID: userID}, err
	}
	return struct{ UserID string }{}, jwt.ErrTokenUnverifiable
}

func (s *Client) createResetToken(ctx context.Context, userID, tokenHash string, expiresAt time.Time) error {
	if s.useEphemeralStore() {
		ttl := time.Until(expiresAt)
		if ttl <= 0 {
			ttl = time.Hour
		}
		return s.storePasswordReset(ctx, tokenHash, userID, ttl)
	}
	return fmt.Errorf("ephemeral store not configured")
}
