package engine

import (
	"context"
	"strings"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/contact"
	"github.com/open-rails/authkit/internal/db"
	"github.com/open-rails/authkit/internal/errmodel"
)

// issuePendingRegistration holds target and username for a sign-up pending its
// proof and sends the first code, answering its challenge.
func (s *Engine) issuePendingRegistration(ctx context.Context, kind pendingChangeKind, target, username, passwordHash, preferredLanguage string) (string, error) {
	allowed, err := s.registrationAllowedForEmail(ctx, target)
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
	rec, err := s.storePendingChange(ctx, pendingChange{
		Kind:              kind,
		Target:            target,
		Username:          username,
		PasswordHash:      passwordHash,
		PreferredLanguage: language,
	}, kind.defaultTTL())
	if err != nil {
		return "", err
	}
	return s.sendRegistrationCode(ctx, rec)
}

// sendRegistrationCode sends a code proving rec's address for the pending
// sign-up, beside any code already out for it.
func (s *Engine) sendRegistrationCode(ctx context.Context, rec pendingChange) (string, error) {
	language := s.messageLanguage(ctx, rec.PreferredLanguage)
	return s.sendVerification(ctx, verificationChallenge{Kind: rec.Kind, Target: rec.Target, PendingID: rec.ID}, func(code, link string) error {
		if rec.Kind == kindRegisterEmail {
			if s.email == nil {
				return s.missingSender(errEmailNotConfigured)
			}
			return s.sendEmail(ctx, iam.EmailMessage{Kind: iam.MessageVerification, To: rec.Target, Username: rec.Username, Language: language,
				Code: code, Link: s.emailVerificationURL(link), Purpose: iam.PurposeSignup})
		}
		if s.sms == nil {
			return s.missingSender(errSMSNotConfigured)
		}
		return s.sendSMS(ctx, iam.SMSMessage{Kind: iam.MessageVerification, To: rec.Target, Language: language,
			Code: code, Link: s.phoneVerificationURL(link), Purpose: iam.PurposeSignup})
	})
}

// CheckPendingRegistrationConflict checks if email or username exists in users or pending registration cache.
// Returns (emailTaken, usernameTaken, error)
func (s *Engine) CheckPendingRegistrationConflict(ctx context.Context, email, username string) (bool, bool, error) {
	var emailTaken, usernameTaken bool
	email = contact.NormalizeEmail(email)
	username = strings.TrimSpace(username)
	if s.pg != nil {
		taken, err := s.q.UserEmailOrUsernameTaken(ctx, db.UserEmailOrUsernameTakenParams{TenantID: s.tenantKey(ctx), Email: email, Username: username, AtTime: s.namingNow()})
		if err != nil {
			return false, false, err
		}
		emailTaken, usernameTaken = taken.EmailTaken, taken.UsernameTaken
	}

	// Both answers are always worked out in full: one must not depend on the
	// other, or a taken username would reveal whether the email is taken.
	if s.useEphemeralStore() {
		pendingEmail := s.pendingChangeTargetTaken(ctx, kindRegisterEmail, email)
		pendingUsername := s.pendingChangeUsernameTaken(ctx, username)
		emailTaken, usernameTaken = emailTaken || pendingEmail, usernameTaken || pendingUsername
	}
	return emailTaken, usernameTaken, nil
}

// CheckPhoneRegistrationConflict checks if phone or username exists in users OR pending tables.
// Returns (phoneTaken, usernameTaken, error)
func (s *Engine) CheckPhoneRegistrationConflict(ctx context.Context, phone, username string) (bool, bool, error) {
	var phoneTaken, usernameTaken bool
	phone = contact.NormalizePhone(phone)
	username = strings.TrimSpace(username)

	if s.pg != nil {
		taken, err := s.q.UserPhoneOrUsernameTaken(ctx, db.UserPhoneOrUsernameTakenParams{TenantID: s.tenantKey(ctx), Phone: phone, Username: username, AtTime: s.namingNow()})
		if err != nil {
			return false, false, err
		}
		phoneTaken, usernameTaken = taken.PhoneTaken, taken.UsernameTaken
	}

	if s.useEphemeralStore() {
		pendingPhone := s.pendingChangeTargetTaken(ctx, kindRegisterPhone, phone)
		pendingUsername := s.pendingChangeUsernameTaken(ctx, username)
		phoneTaken, usernameTaken = phoneTaken || pendingPhone, usernameTaken || pendingUsername
	}
	return phoneTaken, usernameTaken, nil
}

// resendRegistration sends the pending sign-up for identifier another code,
// keeping the codes already out, and renews its lifetime. A resend never
// creates an account.
func (s *Engine) resendRegistration(ctx context.Context, identifier string) (string, bool, error) {
	kind := kindRegisterEmail
	if !strings.Contains(identifier, "@") {
		kind = kindRegisterPhone
	}
	rec, ok, err := s.pendingChangeByTarget(ctx, kind, identifier)
	if err != nil || !ok {
		return "", false, err
	}
	if renewed, err := s.renewPendingChange(ctx, rec); err != nil || !renewed {
		return newChallengeHandle(), true, err
	}
	handle, err := s.sendRegistrationCode(ctx, rec)
	return handle, true, err
}
