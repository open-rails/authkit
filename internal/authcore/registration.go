package authcore

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

func (s *Service) CreatePendingRegistrationWithLanguage(ctx context.Context, email, username, passwordHash string, ttl time.Duration, preferredLanguage string) (string, error) {
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
		userID, err := s.createEmailRegistrationUser(ctx, email, username, passwordHash, true)
		if err != nil {
			return "", err
		}
		if language != "" {
			if err := s.SetPreferredLanguage(ctx, userID, language); err != nil {
				return "", err
			}
		}
		if err := s.consumeAccountRegistrationInvite(ctx, email, userID); err != nil {
			return "", err
		}
		return "", nil
	case RegistrationVerificationOptional:
		verified := s.email == nil
		userID, err := s.createEmailRegistrationUser(ctx, email, username, passwordHash, verified)
		if err != nil {
			return "", err
		}
		if language != "" {
			if err := s.SetPreferredLanguage(ctx, userID, language); err != nil {
				return "", err
			}
		}
		if verified {
			if err := s.consumeAccountRegistrationInvite(ctx, email, userID); err != nil {
				return "", err
			}
			return "", nil
		}
		if ttl <= 0 {
			ttl = defaultEmailVerificationTTL
		}
		code := randAlphanumeric(6)
		codeHash := sha256Hex(code)
		linkToken := randB64(32)
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
		linkToken := randB64(32)
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
			} else if !s.isDevEnvironment() {
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
func (s *Service) ConfirmPendingRegistration(ctx context.Context, email, code string) (userID string, err error) {
	return s.confirmPendingRegistrationCode(ctx, KindRegisterEmail, email, code)
}

// ConfirmPendingRegistrationByToken finalizes a pending email registration from
// the 256-bit emailed link token, whose entropy is the security boundary.
func (s *Service) ConfirmPendingRegistrationByToken(ctx context.Context, token string) (userID string, err error) {
	return s.confirmPendingRegistrationLink(ctx, KindRegisterEmail, token)
}

func (s *Service) confirmPendingRegistrationCode(ctx context.Context, kind PendingChangeKind, target, code string) (string, error) {
	if !s.PublicNativeUserRegistrationEnabled() {
		return "", ErrRegistrationDisabled
	}
	rec, ok := s.findPendingChangeByTarget(ctx, kind, strings.TrimSpace(target))
	if !ok {
		return "", jwt.ErrTokenUnverifiable
	}
	return s.consumePendingChangeCode(ctx, rec, code, nil)
}

func (s *Service) confirmPendingRegistrationLink(ctx context.Context, kind PendingChangeKind, token string) (string, error) {
	if !s.PublicNativeUserRegistrationEnabled() {
		return "", ErrRegistrationDisabled
	}
	return s.consumePendingChangeByLink(ctx, sha256Hex(token), kind)
}

// CheckPendingRegistrationConflict checks if email or username exists in users or pending registration cache.
// Returns (emailTaken, usernameTaken, error)
func (s *Service) CheckPendingRegistrationConflict(ctx context.Context, email, username string) (bool, bool, error) {
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

func (s *Service) CreatePendingPhoneRegistrationWithLanguage(ctx context.Context, phone, username, passwordHash, preferredLanguage string) (string, error) {
	if !s.PublicNativeUserRegistrationEnabled() {
		return "", ErrRegistrationDisabled
	}
	language, err := NormalizePreferredLanguage(preferredLanguage)
	if err != nil {
		return "", err
	}
	sendCtx := contextWithPreferredLanguage(ctx, language)
	switch s.RegistrationVerificationPolicy() {
	case RegistrationVerificationNone:
		userID, err := s.createPhoneRegistrationUser(ctx, phone, username, passwordHash, true)
		if err != nil {
			return "", err
		}
		if language != "" {
			if err := s.SetPreferredLanguage(ctx, userID, language); err != nil {
				return "", err
			}
		}
		return "", nil
	case RegistrationVerificationOptional:
		verified := s.sms == nil
		userID, err := s.createPhoneRegistrationUser(ctx, phone, username, passwordHash, verified)
		if err != nil {
			return "", err
		}
		if language != "" {
			if err := s.SetPreferredLanguage(ctx, userID, language); err != nil {
				return "", err
			}
		}
		if verified {
			return "", nil
		}
		code := randAlphanumeric(6)
		codeHash := sha256Hex(code)
		linkToken := randB64(32)
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
		linkToken := randB64(32)
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
				if !s.isDevEnvironment() {
					return "", fmt.Errorf("SMS verification unavailable: SMS sender not configured (phone registration requires SMS in production)")
				}
			}
		}

		return code, nil
	}
}

// ConfirmPendingPhoneRegistration finalizes a pending phone registration from the
// short typed code, honored only against the record issued for this phone.
func (s *Service) ConfirmPendingPhoneRegistration(ctx context.Context, phone, code string) (userID string, err error) {
	return s.confirmPendingRegistrationCode(ctx, KindRegisterPhone, phone, code)
}

// ConfirmPendingPhoneRegistrationByToken finalizes a pending phone registration
// from the 256-bit link token.
func (s *Service) ConfirmPendingPhoneRegistrationByToken(ctx context.Context, token string) (string, error) {
	return s.confirmPendingRegistrationLink(ctx, KindRegisterPhone, token)
}

// CheckPhoneRegistrationConflict checks if phone or username exists in users OR pending tables.
// Returns (phoneTaken, usernameTaken, error)
func (s *Service) CheckPhoneRegistrationConflict(ctx context.Context, phone, username string) (bool, bool, error) {
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

func (s *Service) createVerifiedRegistrationUser(ctx context.Context, email, username, passwordHash string) (string, error) {
	return s.createEmailRegistrationUser(ctx, email, username, passwordHash, true)
}

func (s *Service) createEmailRegistrationUser(ctx context.Context, email, username, passwordHash string, emailVerified bool) (string, error) {
	if s.pg == nil {
		return "", fmt.Errorf("postgres not configured")
	}
	if err := ValidateEmail(email); err != nil {
		return "", err
	}
	if err := ValidateUsername(username); err != nil { // availability is the insert's verdict (#326)
		return "", err
	}
	email = NormalizeEmail(email)
	username = strings.TrimSpace(username)

	tx, err := s.pg.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := s.qtx(tx)

	userID, err := newUUIDV7String()
	if err != nil {
		return "", err
	}
	if err := s.admitName(ctx, authkit.NameAdmissionRequest{OwnerKind: "user", OwnerID: userID, RequestedName: username, Operation: authkit.NameCreate}); err != nil {
		return "", err
	}
	if _, err := q.UserInsert(ctx, db.UserInsertParams{ID: userID, Email: email, Username: &username, AtTime: s.namingNow()}); err != nil {
		return "", mapUserUniqueViolation(err)
	}
	if err := q.UserPasswordInsert(ctx, db.UserPasswordInsertParams{UserID: userID, PasswordHash: passwordHash}); err != nil {
		return "", err
	}
	if err := q.UserSetEmailVerified(ctx, db.UserSetEmailVerifiedParams{ID: userID, EmailVerified: emailVerified}); err != nil {
		return "", err
	}
	if err := tx.Commit(ctx); err != nil {
		return "", err
	}
	return userID, nil
}

func (s *Service) createPhoneRegistrationUser(ctx context.Context, phone, username, passwordHash string, phoneVerified bool) (string, error) {
	if s.pg == nil {
		return "", fmt.Errorf("postgres not configured")
	}
	if err := ValidatePhone(phone); err != nil {
		return "", err
	}
	if err := ValidateUsername(username); err != nil { // availability is the insert's verdict (#326)
		return "", err
	}
	phone = NormalizePhone(phone)
	username = strings.TrimSpace(username)

	tx, err := s.pg.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := s.qtx(tx)

	userID, err := newUUIDV7String()
	if err != nil {
		return "", err
	}
	if err := s.admitName(ctx, authkit.NameAdmissionRequest{OwnerKind: "user", OwnerID: userID, RequestedName: username, Operation: authkit.NameCreate}); err != nil {
		return "", err
	}
	if _, err := q.UserInsert(ctx, db.UserInsertParams{ID: userID, Email: "", Username: &username, AtTime: s.namingNow()}); err != nil {
		return "", mapUserUniqueViolation(err)
	}
	if err := q.UserPasswordInsert(ctx, db.UserPasswordInsertParams{UserID: userID, PasswordHash: passwordHash}); err != nil {
		return "", err
	}
	if err := q.UserSetPhoneAndVerified(ctx, db.UserSetPhoneAndVerifiedParams{ID: userID, PhoneNumber: &phone, PhoneVerified: phoneVerified}); err != nil {
		return "", mapUserUniqueViolation(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return "", err
	}
	return userID, nil
}
