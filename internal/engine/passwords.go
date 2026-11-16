package engine

import (
	"context"
	"strings"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/db"
	"github.com/open-rails/authkit/internal/password"
)

// authenticatePassword is the credential half of a password login once the
// user row is resolved: the stored hash (with the bcrypt import rehash to
// Argon2id), with its credential version captured before checking the hash,
// then the account gate, so only the account's own password shows its state.
// It mints nothing — PasswordLogin issues the session from its outcome.
func (s *Engine) authenticatePassword(ctx context.Context, u *db.User, pass string) (int64, error) {
	if s.pg == nil || u == nil {
		return 0, jwt.ErrTokenUnverifiable
	}
	version, err := s.q.UserCredentialVersion(ctx, u.ID)
	if err != nil {
		return 0, err
	}
	hash, algo, err := s.verifyStoredPassword(ctx, u.ID, pass)
	if err != nil {
		return 0, err
	}
	if err := s.ensureLoginProofAccess(ctx, u); err != nil {
		return 0, err
	}
	s.rehashPassword(ctx, u.ID, hash, algo, pass)
	return version.CredentialVersion, nil
}

// verifyStoredPassword checks pass against the account's stored hash. An
// account with none costs one check, as a wrong password does.
func (s *Engine) verifyStoredPassword(ctx context.Context, userID, pass string) (hash, algo string, err error) {
	hash, algo, err = s.getPasswordHash(ctx, userID)
	if err != nil {
		if busy := spendPasswordCheck(ctx, pass); busy != nil {
			return "", "", busy
		}
		return "", "", errOrUnauthorized(err)
	}
	return hash, algo, verifyPasswordHash(ctx, hash, algo, pass)
}

func errOrUnauthorized(err error) error {
	if err != nil {
		return err
	}
	return jwt.ErrTokenInvalidClaims
}

// CheckUserPassword is the error-returning form of VerifyUserPassword: nil on
// success, ErrPasswordResetRequired when the stored hash is flagged
// iam.HashLegacyResetRequired (no plaintext can verify; the user must reset),
// and a generic unauthorized error otherwise. Callers that need to route
// reset-required users (step-up, change-password) should use this form.
func (s *Engine) CheckUserPassword(ctx context.Context, userID, pass string) error {
	if s.pg == nil || strings.TrimSpace(userID) == "" {
		return errOrUnauthorized(nil)
	}
	hash, algo, err := s.verifyStoredPassword(ctx, userID, pass)
	if err != nil {
		return err
	}
	s.rehashPassword(ctx, userID, hash, algo, pass)
	return nil
}

// Rehash is a compare-and-swap: a successful concurrent recovery always wins.
func (s *Engine) rehashPassword(ctx context.Context, userID, hash, algo, pass string) {
	if algo != "bcrypt" {
		return
	}
	if phc, err := password.HashArgon2id(ctx, pass); err == nil {
		_ = s.q.UserPasswordRehash(ctx, db.UserPasswordRehashParams{UserID: userID, OldHash: hash, NewHash: phc})
	}
}

// SetPasswordAfterFreshAuth sets or replaces the password of an account whose
// session recently signed in, invalidates recovery grants and revokes its
// other sessions atomically. keepSessionID may preserve one.
func (s *Engine) SetPasswordAfterFreshAuth(ctx context.Context, userID, new string, keepSessionID *string) error {
	return s.changePassword(ctx, userID, new, keepSessionID, nil, authflow.SessionRevokeReasonPasswordChange)
}
