package authcore

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5"
	"github.com/open-rails/authkit/internal/db"
)

// getUserByPhone returns a user by phone number (if any)
func (s *Service) getUserByPhone(ctx context.Context, phone string) (*User, error) {
	if s.pg == nil {
		return nil, nil
	}
	r, err := s.q.UserByPhone(ctx, &phone)
	if err != nil {
		return nil, err
	}
	return userFromByPhoneRow(r), nil
}

// setPhoneVerified sets the phone_verified flag for a user.
func (s *Service) setPhoneVerified(ctx context.Context, id string, v bool) error {
	if s.pg == nil {
		return nil
	}
	return s.q.UserSetPhoneVerifiedByID(ctx, db.UserSetPhoneVerifiedByIDParams{ID: id, PhoneVerified: v})
}

// RequestEmailVerification creates a verification code and dispatches an email.
func (s *Service) RequestEmailVerification(ctx context.Context, email string, ttl time.Duration) error {
	email = NormalizeEmail(email)
	if err := ValidateEmail(email); err != nil {
		return err
	}
	if s.pg != nil {
		u, err := s.getUserByEmail(ctx, email)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if u != nil {
			return s.sendEmailVerificationToUser(ctx, u, ttl)
		}
	}

	if pending, err := s.GetPendingRegistrationByEmail(ctx, email); err == nil && pending != nil {
		_, err := s.CreatePendingRegistrationWithLanguage(ctx, email, pending.Username, pending.PasswordHash, ttl, pending.PreferredLanguage)
		return err
	}
	if s.pg == nil {
		return s.requirePG()
	}
	return ErrUserNotFound
}

func (s *Service) sendEmailVerificationToUser(ctx context.Context, u *User, ttl time.Duration) error {
	if u == nil {
		return ErrUserNotFound
	}
	if u.EmailVerified {
		return ErrEmailAlreadyVerified
	}
	if ttl <= 0 {
		ttl = defaultEmailVerificationTTL
	}
	if u.Email == nil {
		return ErrUserNotFound
	}
	code := randAlphanumeric(6)
	codeHash := sha256Hex(code)
	linkToken := randB64(32)
	linkTokenHash := sha256Hex(linkToken)
	if err := s.storeEmailVerificationTokens(ctx, u.ID, u.Email, map[string]time.Duration{
		codeHash:      ttl,
		linkTokenHash: defaultEmailVerificationTTL,
	}); err != nil {
		return err
	}
	username := ""
	if u.Username != nil {
		username = *u.Username
	}
	msg := VerificationMessage{Code: code, LinkURL: s.emailVerificationURL(linkToken), Purpose: "contact_verify"}
	if err := msg.Validate(); err != nil {
		return nil
	}
	if s.email != nil {
		sendCtx := s.contextWithUserPreferredLanguage(ctx, u.ID)
		if err := s.withSendTimeout(sendCtx, func(sendCtx context.Context) error { return s.email.SendVerification(sendCtx, *u.Email, username, msg) }); err != nil {
			return emailDeliveryError(err)
		}
	} else if !s.isDevEnvironment() {
		return fmt.Errorf("email verification unavailable: email sender not configured")
	}
	return nil
}

// ConfirmEmailVerification verifies a short typed code for a SPECIFIC email and
// marks email_verified = true. The code is only 6 digits, so it is brute-force
// resistant ONLY because it is scoped to the address it was issued to (a guessed
// code that happens to match another account's record is rejected here without
// being consumed) and the HTTP layer caps attempts per-identifier (AK security
// audit F1). For the unguessable 256-bit emailed link token use
// ConfirmEmailVerificationByToken instead.
func (s *Service) ConfirmEmailVerification(ctx context.Context, email, code string) (userID string, err error) {
	if s.pg == nil {
		return "", jwt.ErrTokenUnverifiable
	}
	if !s.useEphemeralStore() {
		return "", jwt.ErrTokenUnverifiable
	}
	email = NormalizeEmail(strings.TrimSpace(email))
	if email == "" {
		return "", jwt.ErrTokenInvalidClaims
	}
	tokenHash := sha256Hex(code)
	data, ok := s.peekEmailVerification(ctx, tokenHash)
	if !ok {
		return "", jwt.ErrTokenUnverifiable
	}
	// Email-scope: the short code is honored only for the address it was issued
	// to. Do NOT consume on mismatch — leave the legitimate owner's code intact.
	if data.Email == nil || !strings.EqualFold(NormalizeEmail(*data.Email), email) {
		return "", jwt.ErrTokenInvalidClaims
	}
	u, err := s.getUserByID(ctx, data.UserID)
	if err != nil || u == nil {
		return "", errOrUnauthorized(err)
	}
	// The supplied address must still be the account's current email.
	if u.Email == nil || !strings.EqualFold(*u.Email, email) {
		return "", jwt.ErrTokenInvalidClaims
	}
	if err := s.setEmailVerified(ctx, data.UserID, true); err != nil {
		return "", err
	}
	s.deleteEmailVerificationByToken(ctx, tokenHash)
	return data.UserID, nil
}

// ConfirmEmailVerificationByToken verifies the 256-bit emailed link token and
// marks email_verified = true. The token's own entropy is the security boundary
// (it is unguessable), so this path is global-lookup and needs no email scoping.
func (s *Service) ConfirmEmailVerificationByToken(ctx context.Context, token string) (userID string, err error) {
	if s.pg == nil {
		return "", jwt.ErrTokenUnverifiable
	}
	rec, err := s.useEmailVerifyToken(ctx, sha256Hex(token))
	if err != nil {
		return "", err
	}
	u, err := s.getUserByID(ctx, rec.UserID)
	if err != nil || u == nil {
		return "", errOrUnauthorized(err)
	}
	if rec.Email != nil && u.Email != nil && !strings.EqualFold(*u.Email, *rec.Email) {
		// Email changed since request; token consumed but invalid for current address.
		return "", jwt.ErrTokenInvalidClaims
	}
	if err := s.setEmailVerified(ctx, rec.UserID, true); err != nil {
		return "", err
	}
	return rec.UserID, nil
}

// GetUserByPhone looks up a user by phone number.
func (s *Service) GetUserByPhone(ctx context.Context, phone string) (*User, error) {
	if s.pg == nil {
		return nil, nil
	}
	r, err := s.q.UserByPhone(ctx, &phone)
	if err != nil {
		return nil, err
	}
	u := userFromByPhoneRow(r)
	// Match the historical narrow projection of this lookup: banned_until,
	// ban_reason, and banned_by were not selected here.
	u.BannedUntil, u.BanReason, u.BannedBy = nil, nil, nil
	return u, nil
}

// --- Phone Verification (for existing users with unverified phones) ---

// RequestPhoneVerification looks up the user by phone number and sends a verification code.
// This mirrors the RequestEmailVerification pattern - caller only needs to provide the phone number.
func (s *Service) RequestPhoneVerification(ctx context.Context, phone string, ttl time.Duration) error {
	phone = NormalizePhone(phone)
	if err := ValidatePhone(phone); err != nil {
		return err
	}
	if s.pg != nil {
		u, err := s.GetUserByPhone(ctx, phone)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if u != nil {
			if u.PhoneVerified {
				return ErrPhoneAlreadyVerified
			}
			if u.PhoneNumber == nil {
				return ErrUserNotFound
			}
			return s.SendPhoneVerificationToUser(ctx, *u.PhoneNumber, u.ID, ttl)
		}
	}

	if pending, err := s.GetPendingPhoneRegistrationByPhone(ctx, phone); err == nil && pending != nil {
		_, err := s.CreatePendingPhoneRegistrationWithLanguage(ctx, phone, pending.Username, pending.PasswordHash, pending.PreferredLanguage)
		return err
	}
	if s.pg == nil {
		return s.requirePG()
	}
	return ErrUserNotFound
}

// SendPhoneVerificationToUser creates a verification code and sends it via SMS to a known user.
// Use RequestPhoneVerification if you only have a phone number and need to look up the user.
// Always returns nil for security.
func (s *Service) SendPhoneVerificationToUser(ctx context.Context, phone, userID string, ttl time.Duration) error {
	if ttl <= 0 {
		ttl = defaultPhoneVerificationTTL
	}

	// Generate a numeric code for manual entry + a high-entropy link token.
	code := randAlphanumeric(6)
	codeHash := sha256Hex(code)
	linkToken := randB64(32)
	linkHash := sha256Hex(linkToken)
	if s.useEphemeralStore() {
		if err := s.storePhoneVerificationTokens(ctx, "verify_phone", phone, userID, map[string]time.Duration{
			codeHash: ttl,
			linkHash: defaultPhoneVerificationTTL,
		}); err != nil {
			return err
		}
	} else {
		return nil
	}

	msg := VerificationMessage{Code: code, LinkURL: s.phoneVerificationURL(linkToken), Purpose: "contact_verify"}
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
		if !s.isDevEnvironment() {
			return fmt.Errorf("SMS verification unavailable: SMS sender not configured (phone verification requires SMS in production)")
		}
	}

	return nil
}

// ConfirmPhoneVerificationUserID verifies a token, marks phone_verified = true, and returns the user ID.
func (s *Service) ConfirmPhoneVerificationUserID(ctx context.Context, phone, code string) (string, error) {
	hash := sha256Hex(code)

	var userID string
	if s.useEphemeralStore() {
		uid, err := s.consumePhoneVerification(ctx, "verify_phone", phone, hash)
		if err != nil {
			return "", err
		}
		userID = uid
	} else {
		return "", jwt.ErrTokenUnverifiable
	}

	// Mark phone as verified
	if err := s.q.UserSetPhoneVerifiedByIDAndPhone(ctx, db.UserSetPhoneVerifiedByIDAndPhoneParams{ID: userID, PhoneNumber: &phone}); err != nil {
		return "", err
	}
	return userID, nil
}

// ConfirmPhoneVerificationByTokenUserID verifies phone ownership using a one-click token and returns the user ID.
func (s *Service) ConfirmPhoneVerificationByTokenUserID(ctx context.Context, token string) (string, error) {
	hash := sha256Hex(token)
	userID, phone, err := s.consumePhoneVerificationByToken(ctx, "verify_phone", hash)
	if err != nil {
		return "", err
	}

	if err := s.q.UserSetPhoneVerifiedByIDAndPhone(ctx, db.UserSetPhoneVerifiedByIDAndPhoneParams{ID: userID, PhoneNumber: &phone}); err != nil {
		return "", err
	}
	return userID, nil
}
