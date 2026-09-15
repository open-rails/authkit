package embedded

import (
	"context"
	"fmt"
	"strings"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
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

func (s *Client) CreatePendingRegistrationWithLanguage(ctx context.Context, email, username, passwordHash string, ttl time.Duration, preferredLanguage string) (string, error) {
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
	switch s.RegistrationVerificationPolicy() {
	case RegistrationVerificationNone:
		_, err := s.createEmailRegistrationUser(ctx, email, username, passwordHash, true, language)
		if err != nil {
			return "", err
		}
		return "", nil
	case RegistrationVerificationOptional:
		verified := s.email == nil
		userID, err := s.createEmailRegistrationUser(ctx, email, username, passwordHash, verified, language)
		if err != nil {
			return "", err
		}
		if verified {
			return "", nil
		}
		if ttl <= 0 {
			ttl = defaultEmailVerificationTTL
		}
		code := randAlphanumeric(6)
		codeHash := sha256Hex(code)
		linkToken := RandB64(32)
		linkHash := sha256Hex(linkToken)
		normEmail := NormalizeEmail(email)
		if err := s.storeEmailVerification(ctx, userID, &normEmail, codeHash, linkHash, ttl); err != nil {
			return "", err
		}
		msg := VerificationMessage{Code: code, LinkURL: s.emailVerificationURL(linkToken), Purpose: "signup"}
		if err := msg.Validate(); err == nil {
			if err := s.withSendTimeout(sendCtx, func(sendCtx context.Context) error {
				return s.email.SendVerification(sendCtx, normEmail, username, msg)
			}); err != nil {
				return "", emailDeliveryError(err)
			}
		}
		return code, nil
	default:
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
}

// ConfirmPendingRegistration finalizes a pending email registration from the
// short typed code. The code is only honored against the record issued for this
// exact address (the record is keyed by it), so a guessed code can never confirm
// another signup; the HTTP layer caps attempts per-identifier. For the 256-bit
// emailed link token use ConfirmPendingRegistrationByToken instead.
func (s *Client) ConfirmPendingRegistration(ctx context.Context, email, code string) (userID string, err error) {
	return s.confirmPendingRegistrationCode(ctx, KindRegisterEmail, email, code)
}

// ConfirmPendingRegistrationByToken finalizes a pending email registration from
// the 256-bit emailed link token, whose entropy is the security boundary.
func (s *Client) ConfirmPendingRegistrationByToken(ctx context.Context, token string) (userID string, err error) {
	return s.confirmPendingRegistrationLink(ctx, KindRegisterEmail, token)
}

func (s *Client) confirmPendingRegistrationCode(ctx context.Context, kind PendingChangeKind, target, code string) (string, error) {
	rec, ok, err := s.pendingChangeByTarget(ctx, kind, strings.TrimSpace(target))
	if err != nil {
		return "", err
	}
	if !ok {
		return "", jwt.ErrTokenUnverifiable
	}
	return s.consumePendingChangeCode(ctx, rec, code, nil)
}

func (s *Client) confirmPendingRegistrationLink(ctx context.Context, kind PendingChangeKind, token string) (string, error) {
	return s.consumePendingChangeByLink(ctx, sha256Hex(token), kind)
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

func (s *Client) CreatePendingPhoneRegistrationWithLanguage(ctx context.Context, phone, username, passwordHash, preferredLanguage string) (string, error) {
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
	switch s.RegistrationVerificationPolicy() {
	case RegistrationVerificationNone:
		_, err := s.createPhoneRegistrationUser(ctx, phone, username, passwordHash, true, language)
		if err != nil {
			return "", err
		}
		return "", nil
	case RegistrationVerificationOptional:
		verified := s.sms == nil
		userID, err := s.createPhoneRegistrationUser(ctx, phone, username, passwordHash, verified, language)
		if err != nil {
			return "", err
		}
		if verified {
			return "", nil
		}
		code := randAlphanumeric(6)
		codeHash := sha256Hex(code)
		linkToken := RandB64(32)
		linkHash := sha256Hex(linkToken)
		if err := s.storePhoneVerification(ctx, "verify_phone", phone, userID, codeHash, linkHash, defaultPhoneVerificationTTL); err != nil {
			return "", err
		}
		msg := VerificationMessage{Code: code, LinkURL: s.phoneVerificationURL(linkToken), Purpose: "signup"}
		if err := msg.Validate(); err == nil {
			if err := s.withSendTimeout(sendCtx, func(sendCtx context.Context) error { return s.sms.SendVerification(sendCtx, phone, msg) }); err != nil {
				return "", smsDeliveryError(err)
			}
		}
		return code, nil
	default:
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
}

// ConfirmPendingPhoneRegistration finalizes a pending phone registration from the
// short typed code, honored only against the record issued for this phone.
func (s *Client) ConfirmPendingPhoneRegistration(ctx context.Context, phone, code string) (userID string, err error) {
	return s.confirmPendingRegistrationCode(ctx, KindRegisterPhone, phone, code)
}

// ConfirmPendingPhoneRegistrationByToken finalizes a pending phone registration
// from the 256-bit link token.
func (s *Client) ConfirmPendingPhoneRegistrationByToken(ctx context.Context, token string) (string, error) {
	return s.confirmPendingRegistrationLink(ctx, KindRegisterPhone, token)
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

func (s *Client) createEmailRegistrationUser(ctx context.Context, email, username, passwordHash string, verified bool, language string) (string, error) {
	user, err := s.registerAccount(ctx, accountRegistration{User: ImportUserInput{Email: email, Username: username, PasswordHash: passwordHash, HashAlgo: "argon2id", EmailVerified: verified}, Language: language, InviteToken: accountRegistrationInviteTokenFromContext(ctx)})
	if err != nil {
		return "", err
	}
	return user.ID, nil
}

func (s *Client) createPhoneRegistrationUser(ctx context.Context, phone, username, passwordHash string, verified bool, language string) (string, error) {
	user, err := s.registerAccount(ctx, accountRegistration{User: ImportUserInput{PhoneNumber: phone, Username: username, PasswordHash: passwordHash, HashAlgo: "argon2id", PhoneVerified: verified}, Language: language, InviteToken: accountRegistrationInviteTokenFromContext(ctx)})
	if err != nil {
		return "", err
	}
	return user.ID, nil
}
