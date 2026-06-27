package authcore

import (
	"context"
	"fmt"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/open-rails/authkit/password"
)

// RequestPasswordReset creates a password reset token and dispatches a reset link via email.
// Returns nil for unknown emails to prevent user enumeration (202-like behavior).
func (s *Service) RequestPasswordReset(ctx context.Context, email string, ttl time.Duration, ip *string, ua *string) error {
	if s.pg == nil {
		return nil
	}
	u, err := s.getUserByEmail(ctx, email)
	if err != nil || u == nil {
		return nil
	}
	if ttl <= 0 {
		ttl = time.Hour
	}

	token := randB64(32)
	hash := sha256Hex(token)
	if err := s.createResetToken(ctx, u.ID, hash, time.Now().Add(ttl)); err != nil {
		// Internal error, but do not reveal anything about whether user exists.
		return err
	}

	if u.Email == nil {
		return nil
	}
	username := ""
	if u.Username != nil {
		username = *u.Username
	}

	if s.email == nil {
		if !s.isDevEnvironment() {
			return fmt.Errorf("email password reset unavailable: email sender not configured")
		}
		return nil
	}

	sendCtx := s.contextWithUserPreferredLanguage(ctx, u.ID)
	if err := s.withSendTimeout(sendCtx, func(sendCtx context.Context) error {
		return s.email.SendPasswordResetLink(sendCtx, *u.Email, username, s.emailPasswordResetURL(token))
	}); err != nil {
		return emailDeliveryError(err)
	}

	s.LogPasswordRecovery(ctx, u.ID, "email", "", ip, ua)

	return nil
}

// ConfirmPasswordReset verifies token and sets a new password.
func (s *Service) ConfirmPasswordReset(ctx context.Context, token, newPassword string) (string, error) {
	if s.pg == nil {
		return "", jwt.ErrTokenUnverifiable
	}
	rt, err := s.useResetToken(ctx, sha256Hex(token))
	if err != nil {
		return "", err
	}
	if err := s.finishPasswordReset(ctx, rt.UserID, newPassword); err != nil {
		return "", err
	}
	return rt.UserID, nil
}

func (s *Service) finishPasswordReset(ctx context.Context, userID, newPassword string) error {
	phc, err := password.HashArgon2id(newPassword)
	if err != nil {
		return err
	}
	if err := s.upsertPasswordHash(ctx, userID, phc, "argon2id", nil); err != nil {
		return err
	}
	// Revoke all sessions to invalidate any potentially compromised refresh tokens.
	_ = s.RevokeAllSessions(ctx, userID, nil)
	s.LogPasswordChanged(ctx, userID, "", nil, nil)
	return nil
}

// --- Phone Password Reset (for phone+password users) ---

// RequestPhonePasswordReset creates a password reset token and sends a reset link via SMS.
// Always returns nil for unknown phone numbers to prevent user enumeration (202-like behavior).
func (s *Service) RequestPhonePasswordReset(ctx context.Context, phone string, ttl time.Duration, ip *string, ua *string) error {
	// Look up user by phone
	u, err := s.GetUserByPhone(ctx, phone)
	if err != nil || u == nil {
		return nil // Don't reveal if phone exists
	}

	if ttl <= 0 {
		ttl = time.Hour
	}

	token := randB64(32)
	hash := sha256Hex(token)
	if err := s.createResetToken(ctx, u.ID, hash, time.Now().Add(ttl)); err != nil {
		return err
	}

	if s.sms == nil {
		if !s.isDevEnvironment() {
			return fmt.Errorf("SMS password reset unavailable: sms sender not configured")
		}
		return nil
	}

	sendCtx := s.contextWithUserPreferredLanguage(ctx, u.ID)
	if err := s.withSendTimeout(sendCtx, func(sendCtx context.Context) error {
		return s.sms.SendPasswordResetLink(sendCtx, phone, s.phonePasswordResetURL(token))
	}); err != nil {
		return smsDeliveryError(err)
	}

	s.LogPasswordRecovery(ctx, u.ID, "sms", "", ip, ua)

	return nil
}
