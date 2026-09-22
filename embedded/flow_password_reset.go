package embedded

import (
	"context"
	"errors"
	"fmt"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
)

// RequestPasswordReset creates a password reset token and dispatches a reset link via email.
// Returns nil for unknown emails to prevent user enumeration (202-like behavior).
func (s *Runtime) RequestPasswordReset(ctx context.Context, email string, ttl time.Duration, ip *string, ua *string) error {
	if s.pg == nil {
		return nil
	}
	u, err := s.getUserByEmail(ctx, email)
	if err != nil || u == nil {
		return nil
	}
	if err := s.ensureUserAccess(ctx, u); err != nil {
		return resetGateError(err)
	}
	if ttl <= 0 {
		ttl = time.Hour
	}

	token := RandB64(32)
	hash := sha256Hex(token)
	if err := s.storePasswordReset(ctx, hash, u.ID, "email", email, ttl); err != nil {
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
		if !s.cfg.Registration.AllowMissingSenders {
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
func (s *Runtime) ConfirmPasswordReset(ctx context.Context, token, newPassword string) (string, error) {
	if s.pg == nil {
		return "", jwt.ErrTokenUnverifiable
	}
	rt, err := s.consumePasswordReset(ctx, sha256Hex(token))
	if err != nil {
		return "", err
	}
	if err := s.changePassword(ctx, rt.UserID, newPassword, nil, nil, &rt, SessionRevokeReasonPasswordChange); err != nil {
		return "", err
	}
	return rt.UserID, nil
}

// resetGateError maps the account gate for a reset REQUEST: a banned, deleted
// or reserved account gets the same silent 202 as an unknown address (no token,
// no message); only a lookup failure is surfaced.
func resetGateError(err error) error {
	if errors.Is(err, ErrUserBanned) {
		return nil
	}
	return err
}

// --- Phone Password Reset (for phone+password users) ---

// RequestPhonePasswordReset creates a password reset token and sends a reset link via SMS.
// Always returns nil for unknown phone numbers to prevent user enumeration (202-like behavior).
func (s *Runtime) RequestPhonePasswordReset(ctx context.Context, phone string, ttl time.Duration, ip *string, ua *string) error {
	// Look up user by phone
	u, err := s.GetUserByPhone(ctx, phone)
	if err != nil || u == nil {
		return nil // Don't reveal if phone exists
	}
	if err := s.ensureUserAccess(ctx, u); err != nil {
		return resetGateError(err)
	}

	if ttl <= 0 {
		ttl = time.Hour
	}

	token := RandB64(32)
	hash := sha256Hex(token)
	if err := s.storePasswordReset(ctx, hash, u.ID, "sms", NormalizePhone(phone), ttl); err != nil {
		return err
	}

	if s.sms == nil {
		if !s.cfg.Registration.AllowMissingSenders {
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
