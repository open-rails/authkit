package engine

import (
	"context"
	"errors"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/contact"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/internal/secret"
)

// RequestPasswordReset creates a password reset token and dispatches a reset link via email.
// Returns nil for unknown emails to prevent user enumeration (202-like behavior).
func (s *Engine) RequestPasswordReset(ctx context.Context, email string, ttl time.Duration, ip *string, ua *string) error {
	if s.pg == nil {
		return nil
	}
	// Refused before the lookup, so the answer never depends on the account.
	if s.email == nil && !s.cfg.Registration.AllowMissingSenders {
		return errEmailNotConfigured
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

	token := secret.Token(32)
	hash := secret.Hash(token)
	if err := s.storePasswordReset(ctx, hash, u.ID, "email", email, ttl); err != nil {
		// Internal error, but do not reveal anything about whether user exists.
		return err
	}

	if u.Email == nil {
		return nil
	}
	if s.email == nil {
		return nil
	}

	if err := s.sendEmail(ctx, iam.EmailMessage{Kind: iam.MessagePasswordReset, To: *u.Email, Username: deref(u.Username),
		Language: s.userLanguage(ctx, u.ID), Link: s.emailPasswordResetURL(token)}); err != nil {
		return err
	}

	s.logPasswordRecovery(ctx, u.ID, "email", "", ip, ua)

	return nil
}

// ConfirmPasswordReset verifies token and sets a new password.
func (s *Engine) ConfirmPasswordReset(ctx context.Context, token, newPassword string) (string, error) {
	if s.pg == nil {
		return "", jwt.ErrTokenUnverifiable
	}
	var err error
	ctx, err = s.proofContext(ctx, "password-reset", secret.Hash(token))
	if err != nil {
		return "", err
	}
	rt, err := s.consumePasswordReset(ctx, secret.Hash(token))
	if err != nil {
		return "", err
	}
	if err := s.changePassword(ctx, rt.UserID, newPassword, nil, &rt, authflow.SessionRevokeReasonPasswordChange); err != nil {
		return "", err
	}
	return rt.UserID, nil
}

// resetGateError maps the account gate for a reset REQUEST: a banned or
// deleted account gets the same silent 202 as an unknown address (no token,
// no message); only a lookup failure is surfaced.
func resetGateError(err error) error {
	if errors.Is(err, errmodel.ErrUserBanned) {
		return nil
	}
	return err
}

// --- Phone Password Reset (for phone+password users) ---

// RequestPhonePasswordReset creates a password reset token and sends a reset link via SMS.
// Always returns nil for unknown phone numbers to prevent user enumeration (202-like behavior).
func (s *Engine) RequestPhonePasswordReset(ctx context.Context, phone string, ttl time.Duration, ip *string, ua *string) error {
	if s.sms == nil && !s.cfg.Registration.AllowMissingSenders {
		return errSMSNotConfigured
	}
	u, err := s.getUserByPhone(ctx, phone)
	if err != nil || u == nil {
		return nil // Don't reveal if phone exists
	}
	if err := s.ensureUserAccess(ctx, u); err != nil {
		return resetGateError(err)
	}

	if ttl <= 0 {
		ttl = time.Hour
	}

	token := secret.Token(32)
	hash := secret.Hash(token)
	if err := s.storePasswordReset(ctx, hash, u.ID, "sms", contact.NormalizePhone(phone), ttl); err != nil {
		return err
	}

	if s.sms == nil {
		return nil
	}

	if err := s.sendSMS(ctx, iam.SMSMessage{Kind: iam.MessagePasswordReset, To: phone, UserID: u.ID, Language: s.userLanguage(ctx, u.ID),
		Link: s.phonePasswordResetURL(token)}); err != nil {
		return err
	}

	s.logPasswordRecovery(ctx, u.ID, "sms", "", ip, ua)

	return nil
}
