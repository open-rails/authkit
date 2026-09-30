package engine

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/contact"
	"github.com/open-rails/authkit/internal/db"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/internal/secret"
)

func (s *Engine) issuePendingEmailRegistration(ctx context.Context, email, username, passwordHash string, ttl time.Duration, preferredLanguage string) (string, error) {
	allowed, err := s.registrationAllowedForEmail(ctx, email)
	if err != nil {
		return "", err
	}
	if !allowed {
		return "", errmodel.ErrRegistrationDisabled
	}
	language, err := authflow.NormalizePreferredLanguage(preferredLanguage)
	if err != nil {
		return "", err
	}
	if ttl <= 0 {
		ttl = defaultEmailVerificationTTL
	}
	code := secret.Digits(6)
	codeHash := secret.Hash(code)
	linkToken := secret.Token(32)
	linkHash := secret.Hash(linkToken)

	if err := s.storePendingChange(ctx, pendingChange{
		Kind:              kindRegisterEmail,
		Target:            email,
		Username:          username,
		PasswordHash:      passwordHash,
		PreferredLanguage: language,
		CodeHash:          codeHash,
		LinkHash:          linkHash,
	}, ttl); err != nil {
		return "", err
	}

	if s.email != nil {
		if err := s.sendEmail(ctx, iam.EmailMessage{Kind: iam.MessageVerification, To: email, Username: username, Language: s.messageLanguage(ctx, language),
			Code: code, Link: s.emailVerificationURL(linkToken), Purpose: iam.PurposeSignup}); err != nil {
			return "", err
		}
	} else if !s.cfg.Registration.AllowMissingSenders {
		return "", fmt.Errorf("registration verification unavailable: email sender not configured")
	}

	return code, nil
}

// CheckPendingRegistrationConflict checks if email or username exists in users or pending registration cache.
// Returns (emailTaken, usernameTaken, error)
func (s *Engine) CheckPendingRegistrationConflict(ctx context.Context, email, username string) (bool, bool, error) {
	var emailTaken, usernameTaken bool
	email = contact.NormalizeEmail(email)
	username = strings.TrimSpace(username)
	if s.pg != nil {
		taken, err := s.q.UserEmailOrUsernameTaken(ctx, db.UserEmailOrUsernameTakenParams{Email: email, Username: username, AtTime: s.namingNow()})
		if err != nil {
			return false, false, err
		}
		emailTaken, usernameTaken = taken.EmailTaken, taken.UsernameTaken
	}

	if emailTaken || usernameTaken {
		return emailTaken, usernameTaken, nil
	}

	if s.useEphemeralStore() {
		if s.pendingChangeTargetTaken(ctx, kindRegisterEmail, email) {
			emailTaken = true
		}
		if s.pendingChangeUsernameTaken(ctx, username) {
			usernameTaken = true
		}
	}
	return emailTaken, usernameTaken, nil
}

// --- Phone Registration (for phone+password signups) ---

func (s *Engine) issuePendingPhoneRegistration(ctx context.Context, phone, username, passwordHash, preferredLanguage string) (string, error) {
	allowed, err := s.registrationAllowedForEmail(ctx, phone)
	if err != nil {
		return "", err
	}
	if !allowed {
		return "", errmodel.ErrRegistrationDisabled
	}
	language, err := authflow.NormalizePreferredLanguage(preferredLanguage)
	if err != nil {
		return "", err
	}
	code := secret.Digits(6)
	codeHash := secret.Hash(code)
	linkToken := secret.Token(32)
	linkHash := secret.Hash(linkToken)
	if err := s.storePendingChange(ctx, pendingChange{
		Kind:              kindRegisterPhone,
		Target:            phone,
		Username:          username,
		PasswordHash:      passwordHash,
		PreferredLanguage: language,
		CodeHash:          codeHash,
		LinkHash:          linkHash,
	}, defaultPhoneVerificationTTL); err != nil {
		return "", err
	}

	if s.sms != nil {
		if err := s.sendSMS(ctx, iam.SMSMessage{Kind: iam.MessageVerification, To: phone, Language: s.messageLanguage(ctx, language),
			Code: code, Link: s.phoneVerificationURL(linkToken), Purpose: iam.PurposeSignup}); err != nil {
			return "", err
		}
	} else if !s.cfg.Registration.AllowMissingSenders {
		return "", fmt.Errorf("SMS verification unavailable: SMS sender not configured (phone registration requires SMS in production)")
	}

	return code, nil
}

// CheckPhoneRegistrationConflict checks if phone or username exists in users OR pending tables.
// Returns (phoneTaken, usernameTaken, error)
func (s *Engine) CheckPhoneRegistrationConflict(ctx context.Context, phone, username string) (bool, bool, error) {
	var phoneTaken, usernameTaken bool
	phone = contact.NormalizePhone(phone)
	username = strings.TrimSpace(username)

	if s.pg != nil {
		taken, err := s.q.UserPhoneOrUsernameTaken(ctx, db.UserPhoneOrUsernameTakenParams{Phone: phone, Username: username, AtTime: s.namingNow()})
		if err != nil {
			return false, false, err
		}
		phoneTaken, usernameTaken = taken.PhoneTaken, taken.UsernameTaken
	}

	if phoneTaken || usernameTaken {
		return phoneTaken, usernameTaken, nil
	}

	if s.useEphemeralStore() {
		if s.pendingChangeTargetTaken(ctx, kindRegisterPhone, phone) {
			phoneTaken = true
		}
		if s.pendingChangeUsernameTaken(ctx, username) {
			usernameTaken = true
		}
		return phoneTaken, usernameTaken, nil
	}
	return phoneTaken, usernameTaken, nil
}

// resendRegistration reissues the pending signup while retaining its invitation,
// username, password and language. A resend never creates an account.
func (s *Engine) resendRegistration(ctx context.Context, identifier string) (bool, error) {
	kind := kindRegisterEmail
	if !strings.Contains(identifier, "@") {
		kind = kindRegisterPhone
	}
	rec, ok, err := s.pendingChangeByTarget(ctx, kind, identifier)
	if err != nil || !ok {
		return false, err
	}
	ctx = contextWithAccountRegistrationInviteToken(ctx, rec.AccountInviteToken)
	if kind == kindRegisterEmail {
		_, err = s.issuePendingEmailRegistration(ctx, rec.Target, rec.Username, rec.PasswordHash, 0, rec.PreferredLanguage)
	} else {
		_, err = s.issuePendingPhoneRegistration(ctx, rec.Target, rec.Username, rec.PasswordHash, rec.PreferredLanguage)
	}
	return true, err
}
