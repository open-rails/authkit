package engine

import (
	"context"
	"errors"
	"log/slog"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/contact"
	"github.com/open-rails/authkit/internal/db"
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

// notifyAccountExists tells the owner of an email address or phone number
// that someone tried to register it, or to move another account onto it,
// with a reset link. The attempt is answered as if the address were free, so
// only the owner learns it is taken. A sender that refuses
// MessageAccountExists gets MessagePasswordReset with the same link. A holder
// that cannot sign in (a pending sign-up, a deleted or banned account) gets
// nothing.
func (s *Engine) notifyAccountExists(ctx context.Context, channel, target string) error {
	var (
		u   *db.User
		err error
	)
	if channel == "email" {
		u, err = s.getUserByEmail(ctx, target)
	} else {
		u, err = s.getUserByPhone(ctx, target)
	}
	if err != nil || u == nil || s.ensureUserAccess(ctx, u) != nil {
		return nil
	}
	stored := deref(u.Email)
	if channel != "email" {
		stored = deref(u.PhoneNumber)
	}
	if stored == "" {
		return nil
	}
	token := secret.Token(32)
	if err := s.storePasswordReset(ctx, secret.Hash(token), u.ID, channel, stored, time.Hour); err != nil {
		return err
	}
	language := s.userLanguage(ctx, u.ID)
	if channel == "email" {
		if s.email == nil {
			return nil
		}
		msg := iam.EmailMessage{Kind: iam.MessageAccountExists, To: stored, Username: deref(u.Username), Language: language, Link: s.emailPasswordResetURL(token)}
		if err := s.sendEmail(ctx, msg); !senderRefused(err, errmodel.ErrEmailDeliveryFailed) {
			return err
		}
		slog.Warn("account_exists email refused by the sender, sending password_reset instead", "user_id", u.ID)
		msg.Kind = iam.MessagePasswordReset
		return s.sendEmail(ctx, msg)
	}
	if s.sms == nil {
		return nil
	}
	msg := iam.SMSMessage{Kind: iam.MessageAccountExists, To: stored, UserID: u.ID, Language: language, Link: s.phonePasswordResetURL(token)}
	if err := s.sendSMS(ctx, msg); !senderRefused(err, errmodel.ErrSMSDeliveryFailed) {
		return err
	}
	slog.Warn("account_exists SMS refused by the sender, sending password_reset instead", "user_id", u.ID)
	msg.Kind = iam.MessagePasswordReset
	return s.sendSMS(ctx, msg)
}

// senderRefused reports a send the host's sender itself failed without timing
// out, as one with no copy for a kind does. Admission refusals (rate, region,
// health) and timeouts are not retried as another kind.
func senderRefused(err, delivery error) bool {
	return errors.Is(err, delivery) && !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled)
}
