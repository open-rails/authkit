package engine

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/contact"
	"github.com/open-rails/authkit/internal/db"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/internal/secret"
)

// getUserByPhone returns a user by phone number (if any)
func (s *Engine) getUserByPhone(ctx context.Context, phone string) (*db.User, error) {
	if s.pg == nil {
		return nil, nil
	}
	r, err := s.q.UserByPhone(ctx, &phone)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

// RequestEmailVerification sends a verification code to an account or pending
// registration whose address is unproven. An unknown or already verified
// address gets the same nil, so the answer reveals neither.
func (s *Engine) RequestEmailVerification(ctx context.Context, email string, ttl time.Duration) error {
	email = contact.NormalizeEmail(email)
	if err := contact.ValidateEmail(email); err != nil {
		return err
	}
	if s.pg != nil {
		u, err := s.getUserByEmail(ctx, email)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if u != nil {
			if u.EmailVerified {
				return nil
			}
			return s.sendEmailVerificationToUser(ctx, u, ttl)
		}
	}

	if found, err := s.resendRegistration(ctx, email); found || err != nil {
		return err
	}
	return s.requirePG()
}

func (s *Engine) sendEmailVerificationToUser(ctx context.Context, u *db.User, ttl time.Duration) error {
	if u == nil {
		return iam.ErrUserNotFound
	}
	if u.EmailVerified {
		return errmodel.ErrEmailAlreadyVerified
	}
	if ttl <= 0 {
		ttl = defaultEmailVerificationTTL
	}
	if u.Email == nil {
		return iam.ErrUserNotFound
	}
	code := secret.Digits(6)
	codeHash := secret.Hash(code)
	linkToken := secret.Token(32)
	linkTokenHash := secret.Hash(linkToken)
	if err := s.storeEmailVerification(ctx, u.ID, u.Email, codeHash, linkTokenHash, ttl); err != nil {
		return err
	}
	username := ""
	if u.Username != nil {
		username = *u.Username
	}
	msg := iam.VerificationMessage{Code: code, LinkURL: s.emailVerificationURL(linkToken), Purpose: "contact_verify"}
	if err := msg.Validate(); err != nil {
		return nil
	}
	if s.email != nil {
		sendCtx := s.contextWithUserPreferredLanguage(ctx, u.ID)
		if err := s.withSendTimeout(sendCtx, func(sendCtx context.Context) error { return s.email.SendVerification(sendCtx, *u.Email, username, msg) }); err != nil {
			return emailDeliveryError(err)
		}
	} else if !s.cfg.Registration.AllowMissingSenders {
		return fmt.Errorf("email verification unavailable: email sender not configured")
	}
	return nil
}

// --- Phone Verification (for existing users with unverified phones) ---

// RequestPhoneVerification is RequestEmailVerification for a phone number.
func (s *Engine) RequestPhoneVerification(ctx context.Context, phone string, ttl time.Duration) error {
	phone = contact.NormalizePhone(phone)
	if err := contact.ValidatePhone(phone); err != nil {
		return err
	}
	if s.pg != nil {
		u, err := s.getUserByPhone(ctx, phone)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if u != nil {
			if u.PhoneVerified || u.PhoneNumber == nil {
				return nil
			}
			return s.sendPhoneVerificationToUser(ctx, *u.PhoneNumber, u.ID, ttl)
		}
	}

	if found, err := s.resendRegistration(ctx, phone); found || err != nil {
		return err
	}
	return s.requirePG()
}

// sendPhoneVerificationToUser creates a verification code and sends it via SMS to a known user.
// Use RequestPhoneVerification if you only have a phone number and need to look up the user.
// Always returns nil for security.
func (s *Engine) sendPhoneVerificationToUser(ctx context.Context, phone, userID string, ttl time.Duration) error {
	if ttl <= 0 {
		ttl = defaultPhoneVerificationTTL
	}

	// Generate a numeric code for manual entry + a high-entropy link token.
	code := secret.Digits(6)
	codeHash := secret.Hash(code)
	linkToken := secret.Token(32)
	linkHash := secret.Hash(linkToken)
	if err := s.storePhoneVerification(ctx, "verify_phone", phone, userID, codeHash, linkHash, ttl); err != nil {
		return err
	}

	msg := iam.VerificationMessage{Code: code, LinkURL: s.phoneVerificationURL(linkToken), Purpose: "contact_verify"}
	if err := msg.Validate(); err != nil {
		return nil
	}

	// Send SMS
	if s.sms != nil {
		sendCtx := s.contextWithUserPreferredLanguage(ctx, userID)
		if err := s.withSendTimeout(sendCtx, func(sendCtx context.Context) error { return s.sms.SendVerification(sendCtx, phone, msg) }); err != nil {
			return smsDeliveryError(err)
		}
	} else {
		// In production, require SMS to be configured
		if !s.cfg.Registration.AllowMissingSenders {
			return fmt.Errorf("SMS verification unavailable: SMS sender not configured (phone verification requires SMS in production)")
		}
	}

	return nil
}
