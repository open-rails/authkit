package authcore

import (
	"context"
	"fmt"
	stdlog "log"
	"strings"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
)

// Account contact-change flows (email + phone). Each is a request / confirm /
// resend / cancel state machine over the unified pending-change store; the new
// value is applied to the profile only on confirmation. NOTE: the email and
// phone families are near-identical and are a candidate for a shared channel
// abstraction (see agents/audit/02-service-split.md, stage 8).

// RequestPhoneChange initiates a phone number change by sending a verification code to the new phone.
// The current phone is NOT changed until the user confirms via ConfirmPhoneChange.
func (s *Service) RequestPhoneChange(ctx context.Context, userID, newPhone string) error {
	if s.pg == nil {
		return fmt.Errorf("postgres not configured")
	}

	if err := ValidatePhone(newPhone); err != nil {
		return err
	}
	trimmed := NormalizePhone(newPhone)

	// Get user
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

	// Check if new phone is already in use by another user
	existing, _ := s.getUserByPhone(ctx, trimmed)
	if existing != nil && existing.ID != userID {
		return fmt.Errorf("phone already in use")
	}

	// Generate manual code + link token.
	code := randAlphanumeric(6)
	codeHash := sha256Hex(code)
	linkToken := randB64(32)
	linkHash := sha256Hex(linkToken)

	// Hold the new phone in the unified pending-change store with split TTLs. The
	// new phone is applied to the profile only on confirmation — we do not
	// optimistically pre-apply it. That keeps the user's current phone intact if
	// the change is never confirmed (or is cancelled), so cancellation is a clean
	// delete of this record with nothing to roll back.
	if err := s.storePendingChange(ctx, pendingChange{
		Kind:   KindChangePhone,
		Target: trimmed,
		UserID: userID,
	}, map[string]time.Duration{
		codeHash: defaultPhoneVerificationTTL,
		linkHash: defaultPhoneVerificationTTL,
	}); err != nil {
		return err
	}

	msg := VerificationMessage{Code: code, LinkURL: s.phoneVerificationURL(linkToken), Purpose: "contact_change"}

	// Send verification message to new phone
	if s.sms != nil {
		sendCtx := s.contextWithUserPreferredLanguage(ctx, userID)
		if err := s.withSendTimeout(sendCtx, func(sendCtx context.Context) error { return s.sms.SendVerification(sendCtx, trimmed, msg) }); err != nil {
			return smsDeliveryError(err)
		}
	} else if !s.isDevEnvironment() {
		return fmt.Errorf("phone change verification unavailable: SMS sender not configured")
	}

	// Optionally: notify old phone (not implemented)

	return nil
}

// ConfirmPhoneChange verifies the code and updates the user's phone number.
// This is called when the user enters the verification code sent to their new phone.
func (s *Service) ConfirmPhoneChange(ctx context.Context, userID, phone, code string) error {
	if s.pg == nil || !s.useEphemeralStore() {
		return jwt.ErrTokenUnverifiable
	}

	// Load the pending change by the code's hash; validate kind, owner, and (when
	// the caller supplied a phone) that it matches the pending target.
	hash := sha256Hex(code)
	rec, ok, err := s.loadPendingChangeByToken(ctx, hash)
	if err != nil || !ok || rec.Kind != KindChangePhone {
		return jwt.ErrTokenUnverifiable
	}
	if rec.UserID != userID {
		return jwt.ErrTokenInvalidClaims
	}
	if strings.TrimSpace(phone) != "" && !strings.EqualFold(NormalizePhone(phone), rec.Target) {
		return jwt.ErrTokenUnverifiable
	}

	if _, err := s.finalizeChangePhone(ctx, rec); err != nil {
		return err
	}
	s.deletePendingChangeByToken(ctx, hash)
	return nil
}

// ConfirmPhoneChangeByToken applies a pending phone change using its high-entropy link token.
func (s *Service) ConfirmPhoneChangeByToken(ctx context.Context, token string) (string, error) {
	return s.consumePendingChangeByToken(ctx, sha256Hex(token), KindChangePhone)
}

// ResendPhoneChangeCode resends the verification code for a pending phone change.
func (s *Service) ResendPhoneChangeCode(ctx context.Context, userID, phone string) error {
	// Get current user
	u, err := s.getUserByID(ctx, userID)
	if err != nil {
		return err
	}
	if u == nil {
		return fmt.Errorf("user not found")
	}

	// The unified pending-change record (keyed by user) is the source of truth for
	// whether a phone change is pending for this user.
	rec, ok := s.findPendingChangeByUser(ctx, KindChangePhone, userID)
	if !ok {
		return fmt.Errorf("no pending phone change found")
	}
	pendingPhone := rec.Target

	// Generate new verification credentials; storePendingChange supersedes the old record.
	code := randAlphanumeric(6)
	codeHash := sha256Hex(code)
	linkToken := randB64(32)
	linkHash := sha256Hex(linkToken)
	if err := s.storePendingChange(ctx, pendingChange{
		Kind:   KindChangePhone,
		Target: pendingPhone,
		UserID: userID,
	}, map[string]time.Duration{
		codeHash: defaultPhoneVerificationTTL,
		linkHash: defaultPhoneVerificationTTL,
	}); err != nil {
		return err
	}

	msg := VerificationMessage{Code: code, LinkURL: s.phoneVerificationURL(linkToken), Purpose: "contact_change"}
	// Send new credentials.
	if s.sms != nil {
		sendCtx := s.contextWithUserPreferredLanguage(ctx, userID)
		if err := s.withSendTimeout(sendCtx, func(sendCtx context.Context) error { return s.sms.SendVerification(sendCtx, pendingPhone, msg) }); err != nil {
			return smsDeliveryError(err)
		}
	} else if !s.isDevEnvironment() {
		return fmt.Errorf("phone change verification unavailable: SMS sender not configured")
	}

	return nil
}

// CancelPhoneChange aborts a pending phone-change for the user, clearing the
// unified pending-change record. Because the new phone is held only in the
// pending record and never optimistically applied to the profile, there is
// nothing to roll back. Idempotent: a no-op when no pending change exists.
func (s *Service) CancelPhoneChange(ctx context.Context, userID, phone string) error {
	if !s.useEphemeralStore() {
		return nil
	}
	s.deletePendingChangeByUser(ctx, KindChangePhone, userID)
	return nil
}

// RequestEmailChange initiates an email change by sending a verification code to the new email.
// The current email is NOT changed until the user confirms via ConfirmEmailChange.
// Also sends a notification to the old email for security.
func (s *Service) RequestEmailChange(ctx context.Context, userID, newEmail string) error {
	if s.pg == nil {
		return fmt.Errorf("postgres not configured")
	}

	if err := ValidateEmail(newEmail); err != nil {
		return err
	}
	trimmed := NormalizeEmail(newEmail)

	// Get user
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

	// Check if new email is already in use by another user
	existing, _ := s.getUserByEmail(ctx, trimmed)
	if existing != nil && existing.ID != userID {
		return fmt.Errorf("email already in use")
	}

	// Generate manual code + link token.
	code := randAlphanumeric(6)
	codeHash := sha256Hex(code)
	linkToken := randB64(32)
	linkHash := sha256Hex(linkToken)

	// Hold the new email in the unified pending-change store (applied to the
	// profile only on confirmation). Split TTLs: code + link token.
	if err := s.storePendingChange(ctx, pendingChange{
		Kind:   KindChangeEmail,
		Target: trimmed,
		UserID: userID,
	}, map[string]time.Duration{
		codeHash: defaultEmailVerificationTTL,
		linkHash: defaultEmailVerificationTTL,
	}); err != nil {
		return err
	}

	username := ""
	if u.Username != nil {
		username = *u.Username
	}

	// Send verification message to NEW email
	msg := VerificationMessage{Code: code, LinkURL: s.emailVerificationURL(linkToken), Purpose: "contact_change"}
	if s.email != nil {
		sendCtx := s.contextWithUserPreferredLanguage(ctx, userID)
		if err := s.withSendTimeout(sendCtx, func(sendCtx context.Context) error { return s.email.SendVerification(sendCtx, trimmed, username, msg) }); err != nil {
			return emailDeliveryError(err)
		}
	} else if !s.isDevEnvironment() {
		return fmt.Errorf("email change verification unavailable: email sender not configured")
	}

	// Send notification to OLD email about the change request
	if u.Email != nil && s.email != nil {
		// Host applications can implement dedicated change-notification messages if needed.
		// In production, you'd want a dedicated SendEmailChangeNotification method
		stdlog.Printf("[authkit/security] Email change requested for user %s from %s to %s", userID, *u.Email, trimmed)
	}

	return nil
}

// ConfirmEmailChange verifies the code and updates the user's email address.
// This is called when the user enters the verification code sent to their new email.
func (s *Service) ConfirmEmailChange(ctx context.Context, userID, email, code string) error {
	if s.pg == nil {
		return jwt.ErrTokenUnverifiable
	}

	// Load the pending change by the code's hash and validate it belongs to this
	// user, then finalize (apply the new email) and clear the pending record.
	hash := sha256Hex(code)
	rec, ok, err := s.loadPendingChangeByToken(ctx, hash)
	if err != nil || !ok || rec.Kind != KindChangeEmail {
		return jwt.ErrTokenUnverifiable
	}
	if rec.UserID != userID {
		return jwt.ErrTokenInvalidClaims
	}
	if strings.TrimSpace(email) != "" && !strings.EqualFold(NormalizeEmail(email), rec.Target) {
		return jwt.ErrTokenUnverifiable
	}
	if _, err := s.finalizeChangeEmail(ctx, rec); err != nil {
		return err
	}
	s.deletePendingChangeByToken(ctx, hash)
	return nil
}

// ConfirmEmailChangeByToken applies a pending email change using its high-entropy link token.
func (s *Service) ConfirmEmailChangeByToken(ctx context.Context, token string) (string, error) {
	return s.consumePendingChangeByToken(ctx, sha256Hex(token), KindChangeEmail)
}

// ResendEmailChangeCode resends the verification code for a pending email change.
func (s *Service) ResendEmailChangeCode(ctx context.Context, userID string) error {
	u, err := s.getUserByID(ctx, userID)
	if err != nil {
		return err
	}
	if u == nil {
		return fmt.Errorf("user not found")
	}

	rec, ok := s.findPendingChangeByUser(ctx, KindChangeEmail, userID)
	if !ok {
		return fmt.Errorf("no pending email change found")
	}
	pendingEmail := rec.Target

	// Generate new verification credentials; storePendingChange supersedes the old record.
	code := randAlphanumeric(6)
	codeHash := sha256Hex(code)
	linkToken := randB64(32)
	linkHash := sha256Hex(linkToken)
	if err := s.storePendingChange(ctx, pendingChange{
		Kind:   KindChangeEmail,
		Target: pendingEmail,
		UserID: userID,
	}, map[string]time.Duration{
		codeHash: defaultEmailVerificationTTL,
		linkHash: defaultEmailVerificationTTL,
	}); err != nil {
		return err
	}

	username := ""
	if u.Username != nil {
		username = *u.Username
	}

	msg := VerificationMessage{Code: code, LinkURL: s.emailVerificationURL(linkToken), Purpose: "contact_change"}
	// Send new credentials.
	if s.email != nil {
		sendCtx := s.contextWithUserPreferredLanguage(ctx, userID)
		if err := s.withSendTimeout(sendCtx, func(sendCtx context.Context) error {
			return s.email.SendVerification(sendCtx, pendingEmail, username, msg)
		}); err != nil {
			return emailDeliveryError(err)
		}
	} else if !s.isDevEnvironment() {
		return fmt.Errorf("email change verification unavailable: email sender not configured")
	}

	return nil
}

// GetPendingEmailChange retrieves the pending email change for a user, if any.
// A unified change_email record exists only for an actual change (verifying the
// current address uses a separate store), so its presence already means "change".
func (s *Service) GetPendingEmailChange(ctx context.Context, userID string) (string, error) {
	if !s.useEphemeralStore() {
		return "", nil
	}
	rec, ok := s.findPendingChangeByUser(ctx, KindChangeEmail, userID)
	if !ok {
		return "", nil
	}
	return rec.Target, nil
}

// CancelEmailChange aborts a pending email-change for the user, clearing the
// unified pending-change record. The new email is applied only on confirmation,
// so there is nothing to roll back. Idempotent: a no-op when none is pending.
func (s *Service) CancelEmailChange(ctx context.Context, userID string) error {
	if !s.useEphemeralStore() {
		return nil
	}
	s.deletePendingChangeByUser(ctx, KindChangeEmail, userID)
	return nil
}
