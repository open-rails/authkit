package authcore

import (
	"context"
	"fmt"
	"strings"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/open-rails/authkit/password"
)

// PasswordLogin verifies an email + password and issues an access token.
func (s *Service) PasswordLogin(ctx context.Context, email, pass string, extra map[string]any) (string, time.Time, error) {
	if s.pg == nil {
		return "", time.Time{}, jwt.ErrTokenUnverifiable
	}
	u, err := s.getUserByEmail(ctx, email)
	if err != nil || u == nil {
		return "", time.Time{}, errOrUnauthorized(err)
	}
	if err := s.ensureUserAccess(ctx, u); err != nil {
		return "", time.Time{}, err
	}
	return s.loginVerifiedUser(ctx, u, pass, extra)
}

// PasswordLoginByUserID verifies credentials for a specific user ID and issues
// an access token. This supports login flows where the identifier is a phone
// number or username and email may be NULL.
func (s *Service) PasswordLoginByUserID(ctx context.Context, userID, pass string, extra map[string]any) (string, time.Time, error) {
	if s.pg == nil {
		return "", time.Time{}, jwt.ErrTokenUnverifiable
	}
	if strings.TrimSpace(userID) == "" {
		return "", time.Time{}, jwt.ErrTokenInvalidClaims
	}
	u, err := s.getUserByID(ctx, userID)
	if err != nil || u == nil {
		return "", time.Time{}, errOrUnauthorized(err)
	}
	if err := s.ensureUserAccess(ctx, u); err != nil {
		return "", time.Time{}, err
	}
	return s.loginVerifiedUser(ctx, u, pass, extra)
}

// loginVerifiedUser is the shared tail of password login once the user has been
// resolved and access-checked: verify the password (with legacy-bcrypt lazy
// rehash to Argon2id), record last-login, and issue the access token. Extracted
// so PasswordLogin (by email) and PasswordLoginByUserID stay identical.
func (s *Service) loginVerifiedUser(ctx context.Context, u *User, pass string, extra map[string]any) (string, time.Time, error) {
	hash, algo, _, err := s.getPasswordHash(ctx, u.ID)
	if err != nil {
		return "", time.Time{}, errOrUnauthorized(err)
	}
	switch algo {
	case HashAlgoLegacyResetRequired:
		return "", time.Time{}, ErrPasswordResetRequired
	case "argon2id":
		ok, err := password.VerifyArgon2id(hash, pass)
		if err != nil || !ok {
			return "", time.Time{}, errOrUnauthorized(err)
		}
	case "bcrypt", "":
		// Some legacy rows may have empty algo but a bcrypt-formatted hash
		// ($2b$...); accept those too.
		if !password.IsBcryptHash(hash) && algo == "" {
			return "", time.Time{}, errOrUnauthorized(nil)
		}
		ok, err := password.VerifyBcrypt(hash, pass)
		if err != nil || !ok {
			return "", time.Time{}, errOrUnauthorized(err)
		}
		// Rehash to Argon2id and upsert.
		phc, err := password.HashArgon2id(pass)
		if err == nil {
			_ = s.upsertPasswordHash(ctx, u.ID, phc, "argon2id", nil)
		}
	default:
		return "", time.Time{}, errOrUnauthorized(nil)
	}
	_ = s.setLastLogin(ctx, u.ID, time.Now())
	return s.MintAccessToken(ctx, u.ID, extra)
}

func errOrUnauthorized(err error) error {
	if err != nil {
		return err
	}
	return jwt.ErrTokenInvalidClaims
}

// VerifyUserPassword checks a user's password without issuing tokens or updating
// last-login. Returns true if the password is correct, false otherwise.
func (s *Service) VerifyUserPassword(ctx context.Context, userID, pass string) bool {
	return s.CheckUserPassword(ctx, userID, pass) == nil
}

// CheckUserPassword is the error-returning form of VerifyUserPassword: nil on
// success, ErrPasswordResetRequired when the stored hash is flagged
// HashAlgoLegacyResetRequired (no plaintext can verify; the user must reset),
// and a generic unauthorized error otherwise. Callers that need to route
// reset-required users (step-up, change-password) should use this form.
func (s *Service) CheckUserPassword(ctx context.Context, userID, pass string) error {
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
func (s *Service) ChangePassword(ctx context.Context, userID, current, new string, keepSessionID *string) error {
	if s.pg == nil {
		return jwt.ErrTokenUnverifiable
	}
	if strings.TrimSpace(userID) == "" {
		return fmt.Errorf("invalid_user")
	}
	if err := ValidatePassword(new); err != nil {
		return err
	}
	// If a password exists, verify current
	hadPassword := s.hasPassword(ctx, userID)
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
func (s *Service) SetPasswordAfterFreshAuth(ctx context.Context, userID, new string, keepSessionID *string) error {
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
