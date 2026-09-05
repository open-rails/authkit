package embedded

import (
	"context"
	"fmt"
	"strings"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/open-rails/authkit/password"
)

// authenticatePassword is the credential half of a password login once the
// user row is resolved: the liveness gate, then the stored hash (with the
// legacy-bcrypt lazy rehash to Argon2id) and the last-login stamp. It mints
// nothing — PasswordLogin issues the session from its outcome.
func (s *Client) authenticatePassword(ctx context.Context, u *User, pass string) error {
	if s.pg == nil {
		return jwt.ErrTokenUnverifiable
	}
	if err := s.ensureUserAccess(ctx, u); err != nil {
		return err
	}
	hash, algo, _, err := s.getPasswordHash(ctx, u.ID)
	if err != nil {
		return errOrUnauthorized(err)
	}
	switch algo {
	case HashAlgoLegacyResetRequired:
		return ErrPasswordResetRequired
	case "argon2id":
		ok, err := password.VerifyArgon2id(hash, pass)
		if err != nil || !ok {
			return errOrUnauthorized(err)
		}
	case "bcrypt", "":
		// Some legacy rows may have empty algo but a bcrypt-formatted hash
		// ($2b$...); accept those too.
		if !password.IsBcryptHash(hash) && algo == "" {
			return errOrUnauthorized(nil)
		}
		ok, err := password.VerifyBcrypt(hash, pass)
		if err != nil || !ok {
			return errOrUnauthorized(err)
		}
		if phc, err := password.HashArgon2id(pass); err == nil {
			_ = s.upsertPasswordHash(ctx, u.ID, phc, "argon2id", nil)
		}
	default:
		return errOrUnauthorized(nil)
	}
	_ = s.setLastLogin(ctx, u.ID, time.Now())
	return nil
}

func errOrUnauthorized(err error) error {
	if err != nil {
		return err
	}
	return jwt.ErrTokenInvalidClaims
}

// CheckUserPassword is the error-returning form of VerifyUserPassword: nil on
// success, ErrPasswordResetRequired when the stored hash is flagged
// HashAlgoLegacyResetRequired (no plaintext can verify; the user must reset),
// and a generic unauthorized error otherwise. Callers that need to route
// reset-required users (step-up, change-password) should use this form.
func (s *Client) CheckUserPassword(ctx context.Context, userID, pass string) error {
	if s.pg == nil || strings.TrimSpace(userID) == "" {
		return errOrUnauthorized(nil)
	}
	hash, algo, _, err := s.getPasswordHash(ctx, userID)
	if err != nil {
		return errOrUnauthorized(err)
	}
	switch algo {
	case HashAlgoLegacyResetRequired:
		return ErrPasswordResetRequired
	case "argon2id":
		ok, err := password.VerifyArgon2id(hash, pass)
		if err != nil || !ok {
			return errOrUnauthorized(err)
		}
		return nil
	case "bcrypt", "":
		if !password.IsBcryptHash(hash) && algo == "" {
			return errOrUnauthorized(nil)
		}
		ok, err := password.VerifyBcrypt(hash, pass)
		if err == nil && ok {
			// Rehash to Argon2id opportunistically.
			if phc, hErr := password.HashArgon2id(pass); hErr == nil {
				_ = s.upsertPasswordHash(ctx, userID, phc, "argon2id", nil)
			}
			return nil
		}
		return errOrUnauthorized(err)
	default:
		return errOrUnauthorized(nil)
	}
}

// ChangePassword sets or changes a user's password.
// If the user already has a password, current must verify; otherwise current is ignored.
// Always Argon2id-hashes the new password and upserts it, then revokes all
// other sessions for the user; caller may keep one active session via keepSessionID.
func (s *Client) ChangePassword(ctx context.Context, userID, current, new string, keepSessionID *string) error {
	if s.pg == nil {
		return jwt.ErrTokenUnverifiable
	}
	if strings.TrimSpace(userID) == "" {
		return fmt.Errorf("invalid_user")
	}
	if err := ValidatePassword(new); err != nil {
		return err
	}
	hadPassword, err := s.HasPassword(ctx, userID)
	if err != nil {
		return err
	}
	if hadPassword {
		hash, algo, _, err := s.getPasswordHash(ctx, userID)
		if err != nil {
			return err
		}
		switch algo {
		case HashAlgoLegacyResetRequired:
			// The current password can never verify against a reset-required
			// hash; the user must go through the password-reset flow instead.
			return ErrPasswordResetRequired
		case "argon2id":
			ok, err := password.VerifyArgon2id(hash, current)
			if err != nil || !ok {
				return jwt.ErrTokenInvalidClaims
			}
		case "bcrypt", "":
			if !password.IsBcryptHash(hash) && algo == "" {
				return jwt.ErrTokenInvalidClaims
			}
			ok, err := password.VerifyBcrypt(hash, current)
			if err != nil || !ok {
				return jwt.ErrTokenInvalidClaims
			}
		default:
			return jwt.ErrTokenInvalidClaims
		}
	}
	// Hash and store new password
	phc, err := password.HashArgon2id(new)
	if err != nil {
		return err
	}
	if err := s.upsertPasswordHash(ctx, userID, phc, "argon2id", nil); err != nil {
		return err
	}
	// Revoke all other sessions after a successful password change to ensure that
	// any previously compromised refresh tokens are invalidated. The current
	// session can be preserved via keepSessionID if provided.
	ctx = WithSessionRevokeReason(ctx, SessionRevokeReasonPasswordChange)
	if err := s.RevokeAllSessions(ctx, userID, keepSessionID); err != nil {
		return err
	}
	sessionID := ""
	if keepSessionID != nil {
		sessionID = *keepSessionID
	}
	s.LogPasswordChanged(ctx, userID, sessionID, nil, nil)
	return nil
}

// SetPasswordAfterFreshAuth sets a new password without verifying a current one,
// for flows that already proved freshness (e.g. step-up). It still revokes other
// sessions, keeping keepSessionID if provided.
func (s *Client) SetPasswordAfterFreshAuth(ctx context.Context, userID, new string, keepSessionID *string) error {
	if s.pg == nil {
		return jwt.ErrTokenUnverifiable
	}
	if strings.TrimSpace(userID) == "" {
		return fmt.Errorf("invalid_user")
	}
	if err := ValidatePassword(new); err != nil {
		return err
	}
	phc, err := password.HashArgon2id(new)
	if err != nil {
		return err
	}
	if err := s.upsertPasswordHash(ctx, userID, phc, "argon2id", nil); err != nil {
		return err
	}
	ctx = WithSessionRevokeReason(ctx, SessionRevokeReasonPasswordChange)
	if err := s.RevokeAllSessions(ctx, userID, keepSessionID); err != nil {
		return err
	}
	sessionID := ""
	if keepSessionID != nil {
		sessionID = *keepSessionID
	}
	s.LogPasswordChanged(ctx, userID, sessionID, nil, nil)
	return nil
}
