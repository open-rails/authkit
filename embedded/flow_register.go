package embedded

// Unified registration as ONE engine decision (ak#318): identifier
// classification, password/username validation, the verification policy,
// conflict checks, the pending-registration write (which sends the code) and
// the session issue when no verification is pending.

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"time"

	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/password"
)

// RegisterInput is a native-user registration attempt: Identifier is an email
// or an E.164 phone; the account is password-backed.
type RegisterInput struct {
	Identifier         string
	Username           string
	Password           string
	PreferredLanguage  string
	AccountInviteToken string
	UserAgent          string
	IP                 string
}

// RegisterOutcomeKind is the closed set of ways a registration ends.
type RegisterOutcomeKind string

const (
	RegisterLoginRequired RegisterOutcomeKind = "login_required"
	// RegisterSessionIssued: the account exists and is signed in (no
	// verification pending).
	RegisterSessionIssued RegisterOutcomeKind = "session_issued"
	// RegisterVerifyEmail / RegisterVerifyPhone: the registration is pending
	// until the code just sent to the identifier is confirmed.
	RegisterVerifyEmail RegisterOutcomeKind = "verify_email"
	RegisterVerifyPhone RegisterOutcomeKind = "verify_phone"
)

// RegisterOutcome reports who was registered and what happens next.
type RegisterOutcome struct {
	Login    *LoginOutcome
	Kind     RegisterOutcomeKind
	Username string
	Email    *string
	Phone    *string
	Session  *IssuedSession
}

// Register runs the registration decision tree. Input problems come back as
// the validation errors (ValidationErrorCode) and the sentinels
// ErrInvalidIdentifier / ErrEmailInUse / ErrPhoneInUse / ErrUsernameInUse /
// ErrRegistrationDisabled / ErrEmailRegistrationUnavailable /
// ErrPhoneRegistrationUnavailable; engine failures carry a stage prefix
// and, for sends, the delivery sentinel.
func (s *engine) Register(ctx context.Context, in RegisterInput) (RegisterOutcome, error) {
	if s.cfg.Registration.NativeUserMode == RegistrationModeClosed {
		return RegisterOutcome{}, ErrRegistrationDisabled
	}
	language, err := NormalizePreferredLanguage(in.PreferredLanguage)
	if err != nil {
		return RegisterOutcome{}, err
	}
	in.PreferredLanguage = language
	identifier := strings.TrimSpace(in.Identifier)
	username := strings.TrimSpace(in.Username)
	if identifier == "" || username == "" {
		return RegisterOutcome{}, authkit.ErrInvalidIdentifier
	}
	if err := s.ValidatePassword(in.Password); err != nil {
		return RegisterOutcome{}, err
	}
	if _, err := s.ValidateUsernameForRegistration(ctx, username); err != nil {
		if ValidationErrorCode(err) != "" {
			return RegisterOutcome{}, err
		}
		return RegisterOutcome{}, stageErr("validate_username", err)
	}
	isPhone := ValidatePhone(identifier) == nil
	isEmail := ValidateEmail(identifier) == nil
	if isPhone == isEmail {
		return RegisterOutcome{}, authkit.ErrInvalidIdentifier
	}
	phc, err := password.HashArgon2id(in.Password)
	if err != nil {
		return RegisterOutcome{}, stageErr("hash_password", err)
	}
	requiresVerification := s.RegistrationVerificationRequired()

	ctx = contextWithAccountRegistrationInviteToken(ctx, in.AccountInviteToken)
	if isPhone {
		phone := NormalizePhone(identifier)
		if requiresVerification && !s.SMSAvailable() {
			return RegisterOutcome{}, authkit.ErrPhoneRegistrationUnavailable
		}
		phoneTaken, usernameTaken, err := s.CheckPhoneRegistrationConflict(ctx, phone, username)
		if err != nil {
			return RegisterOutcome{}, stageErr("check_phone_conflict", err)
		}
		if phoneTaken {
			return RegisterOutcome{}, ErrPhoneInUse
		}
		if usernameTaken {
			return RegisterOutcome{}, ErrUsernameInUse
		}
		out := RegisterOutcome{Username: username, Phone: &phone}
		if requiresVerification {
			if _, err := s.issuePendingPhoneRegistration(ctx, phone, username, phc, in.PreferredLanguage); err != nil {
				return RegisterOutcome{}, registrationErr("send_phone_verification", err)
			}
			out.Kind = RegisterVerifyPhone
			return out, nil
		}
		verified := s.RegistrationVerificationPolicy() == RegistrationVerificationNone || !s.SMSAvailable()
		account, err := s.registerAccount(ctx, accountRegistration{User: ImportUserInput{PhoneNumber: phone, Username: username, PasswordHash: phc, HashAlgo: "argon2id", PhoneVerified: verified}, Language: in.PreferredLanguage, InviteToken: in.AccountInviteToken})
		if err != nil {
			return RegisterOutcome{}, err
		}
		if !verified {
			if err := s.SendPhoneVerificationToUser(ctx, phone, account.ID, 0); err != nil {
				slog.Warn("optional registration verification unavailable", "user_id", account.ID, "error", err)
			}
		}
		return s.registeredSession(ctx, in, out, account)
	}

	email := NormalizeEmail(identifier)
	if requiresVerification && !s.HasEmailSender() {
		return RegisterOutcome{}, authkit.ErrEmailRegistrationUnavailable
	}
	emailTaken, usernameTaken, err := s.CheckPendingRegistrationConflict(ctx, email, username)
	if err != nil {
		return RegisterOutcome{}, stageErr("check_email_conflict", err)
	}
	if emailTaken {
		return RegisterOutcome{}, ErrEmailInUse
	}
	if usernameTaken {
		return RegisterOutcome{}, ErrUsernameInUse
	}
	out := RegisterOutcome{Username: username, Email: &email}
	if requiresVerification {
		if _, err := s.issuePendingEmailRegistration(ctx, email, username, phc, 0, in.PreferredLanguage); err != nil {
			return RegisterOutcome{}, registrationErr("send_email_verification", err)
		}
		out.Kind = RegisterVerifyEmail
		return out, nil
	}
	verified := s.RegistrationVerificationPolicy() == RegistrationVerificationNone || !s.HasEmailSender()
	account, err := s.registerAccount(ctx, accountRegistration{User: ImportUserInput{Email: email, Username: username, PasswordHash: phc, HashAlgo: "argon2id", EmailVerified: verified}, Language: in.PreferredLanguage, InviteToken: in.AccountInviteToken})
	if err != nil {
		return RegisterOutcome{}, err
	}
	if !verified {
		if err := s.RequestEmailVerification(ctx, email, 0); err != nil {
			slog.Warn("optional registration verification unavailable", "user_id", account.ID, "error", err)
		}
	}
	return s.registeredSession(ctx, in, out, account)
}

// registrationErr keeps the typed conflicts, validation codes, delivery
// sentinels and ErrRegistrationDisabled visible through the stage tag.
func registrationErr(stage string, err error) error {
	switch {
	case errors.Is(err, ErrEmailInUse), errors.Is(err, ErrPhoneInUse), errors.Is(err, ErrUsernameInUse),
		errors.Is(err, ErrRegistrationDisabled), ValidationErrorCode(err) != "":
		return err
	default:
		return stageErr(stage, err)
	}
}

func (s *engine) registeredSession(ctx context.Context, in RegisterInput, out RegisterOutcome, account registeredAccount) (RegisterOutcome, error) {
	login, err := s.finishFirstFactor(ctx, loginProof{Version: account.Version, AuthenticatedAt: time.Now().UTC(), Input: LoginSessionInput{UserID: account.ID, AuthMethods: []string{"pwd"}, Event: "registration", UserAgent: in.UserAgent, IP: in.IP}})
	if err != nil {
		return RegisterOutcome{}, err
	}
	if login.Kind == LoginSessionIssued {
		out.Kind = RegisterSessionIssued
		out.Session = login.Session
	} else {
		out.Kind = RegisterLoginRequired
		out.Login = &login
	}
	return out, nil
}
