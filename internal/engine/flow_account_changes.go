package engine

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/contact"
	"github.com/open-rails/authkit/internal/db"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/internal/ident"
	"github.com/open-rails/authkit/internal/secret"
	"github.com/open-rails/helpers/auth"
)

// Account contact-change flows (email + phone). Each is a request / confirm /
// resend / cancel state machine over the unified pending-change store; the new
// value is applied to the profile only on confirmation, so cancellation is a
// clean delete with nothing to roll back.
//
// The email and phone families share two helpers (newPendingContactChange,
// sendContactChangeVerification) for the parts that are byte-identical across
// channels. The remaining per-channel differences (validation, lookup, sender
// signature, finalize) are small enough to read inline; a fuller channel
// abstraction was considered and rejected as heavier than the duplication it
// would remove.

// newPendingContactChange generates a fresh manual code + high-entropy link
// token for a pending contact change, stores both (hashed) in the unified
// pending-change store under kind/target/userID with ttl, and returns the
// plaintext code and link token for delivery. Re-storing supersedes any prior
// record for the same user/kind.
func (s *Engine) newPendingContactChange(ctx context.Context, kind pendingChangeKind, target, userID string, ttl time.Duration) (code, linkToken string, err error) {
	code = secret.Digits(6)
	linkToken = secret.Token(32)
	if err := s.storePendingChange(ctx, pendingChange{
		Kind:     kind,
		Target:   target,
		UserID:   userID,
		CodeHash: secret.Hash(code),
		LinkHash: secret.Hash(linkToken),
	}, ttl); err != nil {
		return "", "", err
	}
	return code, linkToken, nil
}

// sendContactChangeVerification delivers a contact-change verification
// message through the channel's sender. When no sender is configured it is a
// no-op in development and returns unavailable otherwise.
func (s *Engine) sendContactChangeVerification(senderConfigured bool, send func() error, unavailable error) error {
	if senderConfigured {
		return send()
	}
	if !s.cfg.Registration.AllowMissingSenders {
		return unavailable
	}
	return nil
}

// RequestPhoneChange initiates a phone number change by sending a verification code to the new phone.
// The current phone is NOT changed until the user confirms via ConfirmPhoneChange.
func (s *Engine) RequestPhoneChange(ctx context.Context, userID, newPhone string) error {
	if s.pg == nil {
		return fmt.Errorf("postgres not configured")
	}
	if err := contact.ValidatePhone(newPhone); err != nil {
		return err
	}
	trimmed := contact.NormalizePhone(newPhone)

	u, err := s.getUserByID(ctx, userID)
	if err != nil {
		return err
	}
	if u == nil {
		return iam.ErrUserNotFound
	}
	if u.PhoneNumber != nil && strings.EqualFold(*u.PhoneNumber, trimmed) {
		if u.PhoneVerified {
			return errmodel.ErrPhoneAlreadyVerified
		}
		return s.sendPhoneVerificationToUser(ctx, trimmed, userID, 0)
	}
	if err := refuseProofBesideUnproven(u, passwordlessChannelSMS); err != nil {
		return err
	}
	// Check if new phone is already in use by another user.
	existing, _ := s.getUserByPhone(ctx, trimmed)
	if existing != nil && existing.ID != userID {
		return iam.ErrPhoneInUse
	}

	code, linkToken, err := s.newPendingContactChange(ctx, kindChangePhone, trimmed, userID, defaultPhoneVerificationTTL)
	if err != nil {
		return err
	}
	msg := iam.SMSMessage{Kind: iam.MessageVerification, To: trimmed, UserID: userID, Language: s.userLanguage(ctx, userID),
		Code: code, Link: s.phoneVerificationURL(linkToken), Purpose: iam.PurposeContactChange}
	return s.sendContactChangeVerification(s.sms != nil,
		func() error { return s.sendSMS(ctx, msg) },
		fmt.Errorf("phone change verification unavailable: SMS sender not configured"))
}

// RequestEmailChange initiates an email change by sending a verification code to the new email.
// The current email is NOT changed until the user confirms it (ConfirmVerification).
// The old address is not notified by AuthKit (only a security log line); a host
// that wants that notification sends it itself.
func (s *Engine) RequestEmailChange(ctx context.Context, userID, newEmail string) error {
	if s.pg == nil {
		return fmt.Errorf("postgres not configured")
	}
	if err := contact.ValidateEmail(newEmail); err != nil {
		return err
	}
	trimmed := contact.NormalizeEmail(newEmail)

	u, err := s.getUserByID(ctx, userID)
	if err != nil {
		return err
	}
	if u == nil {
		return iam.ErrUserNotFound
	}
	if u.Email != nil && strings.EqualFold(*u.Email, trimmed) {
		if u.EmailVerified {
			return errmodel.ErrEmailAlreadyVerified
		}
		return s.sendEmailVerificationToUser(ctx, u, 0)
	}
	if err := refuseProofBesideUnproven(u, passwordlessChannelEmail); err != nil {
		return err
	}
	// Check if new email is already in use by another user.
	existing, _ := s.getUserByEmail(ctx, trimmed)
	if existing != nil && existing.ID != userID {
		return iam.ErrEmailInUse
	}

	code, linkToken, err := s.newPendingContactChange(ctx, kindChangeEmail, trimmed, userID, defaultEmailVerificationTTL)
	if err != nil {
		return err
	}
	msg := iam.EmailMessage{Kind: iam.MessageVerification, To: trimmed, Username: deref(u.Username), Language: s.userLanguage(ctx, userID),
		Code: code, Link: s.emailVerificationURL(linkToken), Purpose: iam.PurposeContactChange}
	return s.sendContactChangeVerification(s.email != nil,
		func() error { return s.sendEmail(ctx, msg) },
		fmt.Errorf("email change verification unavailable: email sender not configured"))
}

// RemovePhone clears the account's phone number under ACCT(root:users:manage),
// the account's own included. It is refused (ErrCannotRemoveLastContact)
// unless a proven email remains, so the account keeps an address to sign in
// and recover with, and an MFA holder keeps a proven contact. An account
// without a phone is unchanged.
func (s *Engine) RemovePhone(ctx context.Context, a auth.Identity, userID string) error {
	return s.withAccountMutation(ctx, a, userID, ident.RootUsersManage, selfAllowed, func(at accountTx) error {
		if _, err := contactStateForUpdate(ctx, at.tx, at.userID); err != nil {
			return err
		}
		u, err := at.q.UserByID(ctx, at.userID)
		if err != nil {
			return err
		}
		if u.PhoneNumber == nil {
			return nil
		}
		if u.Email == nil || !u.EmailVerified {
			return errmodel.ErrCannotRemoveLastContact
		}
		before, err := readAccountIdentity(ctx, at.tx, at.userID)
		if err != nil {
			return err
		}
		if err := at.q.UserSetPhone(ctx, db.UserSetPhoneParams{ID: at.userID}); err != nil {
			return err
		}
		changes, err := identityChanges(ctx, at.tx, at.userID, before)
		if err != nil {
			return err
		}
		return at.st.record(ctx, changes...)
	})
}
