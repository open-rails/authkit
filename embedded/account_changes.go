package embedded

import (
	"context"
	"fmt"
	"strings"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
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
func (s *Client) newPendingContactChange(ctx context.Context, kind PendingChangeKind, target, userID string, ttl time.Duration) (code, linkToken string, err error) {
	code = randAlphanumeric(6)
	linkToken = RandB64(32)
	if err := s.storePendingChange(ctx, pendingChange{
		Kind:     kind,
		Target:   target,
		UserID:   userID,
		CodeHash: sha256Hex(code),
		LinkHash: sha256Hex(linkToken),
	}, ttl); err != nil {
		return "", "", err
	}
	return code, linkToken, nil
}

// confirmContactChangeCode finalizes the caller's own pending change when the
// typed code matches and (if supplied) the target is the one being changed to.
func (s *Client) confirmContactChangeCode(ctx context.Context, kind PendingChangeKind, userID, target, code string, keepSessionID *string) error {
	if s.pg == nil {
		return jwt.ErrTokenUnverifiable
	}
	rec, ok, err := s.pendingChangeByUser(ctx, kind, userID)
	if err != nil {
		return err
	}
	if !ok {
		return jwt.ErrTokenUnverifiable
	}
	if strings.TrimSpace(target) != "" && !strings.EqualFold(normalizePendingTarget(kind, target), rec.Target) {
		return jwt.ErrTokenUnverifiable
	}
	_, err = s.consumePendingChangeCode(ctx, rec, code, keepSessionID)
	return err
}

// sendContactChangeVerification delivers a contact-change verification message
// through the channel's sender, enriching the context with the user's preferred
// language and bounding it with the send timeout. When no sender is configured
// it is a no-op in development and returns unavailable otherwise.
func (s *Client) sendContactChangeVerification(ctx context.Context, userID string, senderConfigured bool, send func(context.Context) error, wrapErr func(error) error, unavailable error) error {
	if senderConfigured {
		sendCtx := s.contextWithUserPreferredLanguage(ctx, userID)
		if err := s.withSendTimeout(sendCtx, send); err != nil {
			return wrapErr(err)
		}
		return nil
	}
	if !s.cfg.Registration.AllowMissingSenders {
		return unavailable
	}
	return nil
}

// RequestPhoneChange initiates a phone number change by sending a verification code to the new phone.
// The current phone is NOT changed until the user confirms via ConfirmPhoneChange.
func (s *Client) RequestPhoneChange(ctx context.Context, userID, newPhone string) error {
	if s.pg == nil {
		return fmt.Errorf("postgres not configured")
	}
	if err := ValidatePhone(newPhone); err != nil {
		return err
	}
	trimmed := NormalizePhone(newPhone)

	u, err := s.getUserByID(ctx, userID)
	if err != nil {
		return err
	}
	if u == nil {
		return fmt.Errorf("user not found")
	}
	if u.PhoneNumber != nil && strings.EqualFold(*u.PhoneNumber, trimmed) {
		if u.PhoneVerified {
			return ErrPhoneAlreadyVerified
		}
		return s.SendPhoneVerificationToUser(ctx, trimmed, userID, 0)
	}
	// Check if new phone is already in use by another user.
	existing, _ := s.getUserByPhone(ctx, trimmed)
	if existing != nil && existing.ID != userID {
		return fmt.Errorf("phone already in use")
	}

	code, linkToken, err := s.newPendingContactChange(ctx, KindChangePhone, trimmed, userID, defaultPhoneVerificationTTL)
	if err != nil {
		return err
	}
	msg := VerificationMessage{Code: code, LinkURL: s.phoneVerificationURL(linkToken), Purpose: "contact_change"}
	// Optionally: notify old phone (not implemented).
	return s.sendContactChangeVerification(ctx, userID, s.sms != nil,
		func(c context.Context) error { return s.sms.SendVerification(c, trimmed, msg) },
		smsDeliveryError,
		fmt.Errorf("phone change verification unavailable: SMS sender not configured"))
}

// ConfirmPhoneChange verifies the code and applies the new phone. Every other
// session is revoked; keepSessionID (the confirming session) survives.
func (s *Client) ConfirmPhoneChange(ctx context.Context, userID, phone, code string, keepSessionID *string) error {
	return s.confirmContactChangeCode(ctx, KindChangePhone, userID, phone, code, keepSessionID)
}

// ConfirmPhoneChangeByToken applies a pending phone change using its high-entropy link token.
func (s *Client) ConfirmPhoneChangeByToken(ctx context.Context, token string) (string, error) {
	return s.consumePendingChangeByLink(ctx, sha256Hex(token), KindChangePhone)
}

// RequestEmailChange initiates an email change by sending a verification code to the new email.
// The current email is NOT changed until the user confirms via ConfirmEmailChange.
// The old address is not notified by AuthKit (only a security log line); a host
// that wants that notification sends it itself.
func (s *Client) RequestEmailChange(ctx context.Context, userID, newEmail string) error {
	if s.pg == nil {
		return fmt.Errorf("postgres not configured")
	}
	if err := ValidateEmail(newEmail); err != nil {
		return err
	}
	trimmed := NormalizeEmail(newEmail)

	u, err := s.getUserByID(ctx, userID)
	if err != nil {
		return err
	}
	if u == nil {
		return fmt.Errorf("user not found")
	}
	if u.Email != nil && strings.EqualFold(*u.Email, trimmed) {
		if u.EmailVerified {
			return ErrEmailAlreadyVerified
		}
		return s.sendEmailVerificationToUser(ctx, u, 0)
	}
	// Check if new email is already in use by another user.
	existing, _ := s.getUserByEmail(ctx, trimmed)
	if existing != nil && existing.ID != userID {
		return fmt.Errorf("email already in use")
	}

	code, linkToken, err := s.newPendingContactChange(ctx, KindChangeEmail, trimmed, userID, defaultEmailVerificationTTL)
	if err != nil {
		return err
	}
	username := ""
	if u.Username != nil {
		username = *u.Username
	}
	msg := VerificationMessage{Code: code, LinkURL: s.emailVerificationURL(linkToken), Purpose: "contact_change"}
	if err := s.sendContactChangeVerification(ctx, userID, s.email != nil,
		func(c context.Context) error { return s.email.SendVerification(c, trimmed, username, msg) },
		emailDeliveryError,
		fmt.Errorf("email change verification unavailable: email sender not configured")); err != nil {
		return err
	}
	return nil
}

// ConfirmEmailChange verifies the code and applies the new email. Every other
// session is revoked; keepSessionID (the confirming session) survives.
func (s *Client) ConfirmEmailChange(ctx context.Context, userID, email, code string, keepSessionID *string) error {
	return s.confirmContactChangeCode(ctx, KindChangeEmail, userID, email, code, keepSessionID)
}

// ConfirmEmailChangeByToken applies a pending email change using its high-entropy link token.
func (s *Client) ConfirmEmailChangeByToken(ctx context.Context, token string) (string, error) {
	return s.consumePendingChangeByLink(ctx, sha256Hex(token), KindChangeEmail)
}
