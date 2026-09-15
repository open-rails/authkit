package embedded

import (
	"context"
	"fmt"
	"strings"
	"time"

	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/internal/db"
)

// Registration policy vocabulary is defined in authkit (core-free) and
// re-exported here (#147). The former AdminOnly/AdminBootstrapOnly/ManifestOnly
// modes were removed — RegistrationMode is now public self-registration policy
// only (Open/InviteOnly/Closed).
type RegistrationVerificationPolicy = authkit.RegistrationVerificationPolicy

const (
	RegistrationVerificationNone     = authkit.RegistrationVerificationNone
	RegistrationVerificationOptional = authkit.RegistrationVerificationOptional
	RegistrationVerificationRequired = authkit.RegistrationVerificationRequired
)

type RegistrationMode = authkit.RegistrationMode

const (
	RegistrationModeOpen       = authkit.RegistrationModeOpen
	RegistrationModeInviteOnly = authkit.RegistrationModeInviteOnly
	RegistrationModeClosed     = authkit.RegistrationModeClosed
)

func (s *Client) issuePendingEmailRegistration(ctx context.Context, email, username, passwordHash string, ttl time.Duration, preferredLanguage string) (string, error) {
	allowed, err := s.registrationAllowedForEmail(ctx, email)
	if err != nil {
		return "", err
	}
	if !allowed {
		return "", ErrRegistrationDisabled
	}
	language, err := NormalizePreferredLanguage(preferredLanguage)
	if err != nil {
		return "", err
	}
	sendCtx := contextWithPreferredLanguage(ctx, language)
	if ttl <= 0 {
		ttl = defaultEmailVerificationTTL
	}
	code := randAlphanumeric(6)
	codeHash := sha256Hex(code)
	linkToken := RandB64(32)
	linkHash := sha256Hex(linkToken)

	if err := s.storePendingChange(ctx, pendingChange{
		Kind:              KindRegisterEmail,
		Target:            email,
		Username:          username,
		PasswordHash:      passwordHash,
		PreferredLanguage: language,
		CodeHash:          codeHash,
		LinkHash:          linkHash,
	}, ttl); err != nil {
		return "", err
	}

	msg := VerificationMessage{Code: code, LinkURL: s.emailVerificationURL(linkToken), Purpose: "signup"}
	if err := msg.Validate(); err == nil {
		if s.email != nil {
			if err := s.withSendTimeout(sendCtx, func(sendCtx context.Context) error { return s.email.SendVerification(sendCtx, email, username, msg) }); err != nil {
				return "", emailDeliveryError(err)
			}
		} else if !s.cfg.Registration.AllowMissingSenders {
			return "", fmt.Errorf("registration verification unavailable: email sender not configured")
		}
	}

	return code, nil
}

// CheckPendingRegistrationConflict checks if email or username exists in users or pending registration cache.
// Returns (emailTaken, usernameTaken, error)
func (s *Client) CheckPendingRegistrationConflict(ctx context.Context, email, username string) (bool, bool, error) {
	var emailTaken, usernameTaken bool
	email = NormalizeEmail(email)
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
		if s.pendingChangeTargetTaken(ctx, KindRegisterEmail, email) {
			emailTaken = true
		}
		if s.pendingChangeUsernameTaken(ctx, username) {
			usernameTaken = true
		}
	}
	return emailTaken, usernameTaken, nil
}

// --- Phone Registration (for phone+password signups) ---

func (s *Client) issuePendingPhoneRegistration(ctx context.Context, phone, username, passwordHash, preferredLanguage string) (string, error) {
	allowed, err := s.registrationAllowedForEmail(ctx, phone)
	if err != nil {
		return "", err
	}
	if !allowed {
		return "", ErrRegistrationDisabled
	}
	language, err := NormalizePreferredLanguage(preferredLanguage)
	if err != nil {
		return "", err
	}
	sendCtx := contextWithPreferredLanguage(ctx, language)
	code := randAlphanumeric(6)
	codeHash := sha256Hex(code)
	linkToken := RandB64(32)
	linkHash := sha256Hex(linkToken)
	if err := s.storePendingChange(ctx, pendingChange{
		Kind:              KindRegisterPhone,
		Target:            phone,
		Username:          username,
		PasswordHash:      passwordHash,
		PreferredLanguage: language,
		CodeHash:          codeHash,
		LinkHash:          linkHash,
	}, defaultPhoneVerificationTTL); err != nil {
		return "", err
	}

	msg := VerificationMessage{Code: code, LinkURL: s.phoneVerificationURL(linkToken), Purpose: "signup"}
	if err := msg.Validate(); err == nil {
		if s.sms != nil {
			if err := s.withSendTimeout(sendCtx, func(sendCtx context.Context) error { return s.sms.SendVerification(sendCtx, phone, msg) }); err != nil {
				return "", smsDeliveryError(err)
			}
		} else {
			if !s.cfg.Registration.AllowMissingSenders {
				return "", fmt.Errorf("SMS verification unavailable: SMS sender not configured (phone registration requires SMS in production)")
			}
		}
	}

	return code, nil
}

// CheckPhoneRegistrationConflict checks if phone or username exists in users OR pending tables.
// Returns (phoneTaken, usernameTaken, error)
func (s *Client) CheckPhoneRegistrationConflict(ctx context.Context, phone, username string) (bool, bool, error) {
	var phoneTaken, usernameTaken bool
	phone = NormalizePhone(phone)
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
		if s.pendingChangeTargetTaken(ctx, KindRegisterPhone, phone) {
			phoneTaken = true
		}
		if s.pendingChangeUsernameTaken(ctx, username) {
			usernameTaken = true
		}
		return phoneTaken, usernameTaken, nil
	}
	return phoneTaken, usernameTaken, nil
}

// ResendRegistration reissues the pending signup while retaining its invitation,
// username, password and language. A resend never creates an account.
func (s *Client) ResendRegistration(ctx context.Context, identifier string) (bool, error) {
	kind := KindRegisterEmail
	if !strings.Contains(identifier, "@") {
		kind = KindRegisterPhone
	}
	rec, ok, err := s.pendingChangeByTarget(ctx, kind, identifier)
	if err != nil || !ok {
		return false, err
	}
	ctx = contextWithAccountRegistrationInviteToken(ctx, rec.AccountInviteToken)
	if kind == KindRegisterEmail {
		_, err = s.issuePendingEmailRegistration(ctx, rec.Target, rec.Username, rec.PasswordHash, 0, rec.PreferredLanguage)
	} else {
		_, err = s.issuePendingPhoneRegistration(ctx, rec.Target, rec.Username, rec.PasswordHash, rec.PreferredLanguage)
	}
	return true, err
}
