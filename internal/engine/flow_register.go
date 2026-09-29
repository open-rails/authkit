package engine

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

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/contact"
	"github.com/open-rails/authkit/internal/password"
)

// Register runs the registration decision tree. Input problems come back as
// the validation errors (ValidationErrorCode) and the sentinels
// ErrInvalidIdentifier / ErrEmailInUse / ErrPhoneInUse / ErrUsernameInUse /
// ErrRegistrationDisabled / ErrEmailRegistrationUnavailable /
// ErrPhoneRegistrationUnavailable; engine failures carry a stage prefix
// and, for sends, the delivery sentinel.
func (s *Engine) Register(ctx context.Context, in authflow.RegisterInput) (authflow.RegisterOutcome, error) {
	if s.cfg.Registration.NativeUserMode == iam.RegistrationModeClosed {
		return authflow.RegisterOutcome{}, iam.ErrRegistrationDisabled
	}
	language, err := authflow.NormalizePreferredLanguage(in.PreferredLanguage)
	if err != nil {
		return authflow.RegisterOutcome{}, err
	}
	in.PreferredLanguage = language
	identifier := strings.TrimSpace(in.Identifier)
	username := strings.TrimSpace(in.Username)
	if identifier == "" || username == "" {
		return authflow.RegisterOutcome{}, iam.ErrInvalidIdentifier
	}
	if err := s.ValidatePassword(in.Password, username, identifier); err != nil {
		return authflow.RegisterOutcome{}, err
	}
	if _, err := s.ValidateUsernameForRegistration(ctx, username); err != nil {
		if authflow.ValidationErrorCode(err) != "" {
			return authflow.RegisterOutcome{}, err
		}
		return authflow.RegisterOutcome{}, stageErr("validate_username", err)
	}
	isPhone := contact.ValidatePhone(identifier) == nil
	isEmail := contact.ValidateEmail(identifier) == nil
	if isPhone == isEmail {
		return authflow.RegisterOutcome{}, iam.ErrInvalidIdentifier
	}
	phc, err := password.HashArgon2id(in.Password)
	if err != nil {
		return authflow.RegisterOutcome{}, stageErr("hash_password", err)
	}
	requiresVerification := s.RegistrationVerificationRequired()

	ctx = contextWithAccountRegistrationInviteToken(ctx, in.AccountInviteToken)
	if isPhone {
		phone := contact.NormalizePhone(identifier)
		if requiresVerification && !s.SMSAvailable() {
			return authflow.RegisterOutcome{}, iam.ErrPhoneRegistrationUnavailable
		}
		phoneTaken, usernameTaken, err := s.CheckPhoneRegistrationConflict(ctx, phone, username)
		if err != nil {
			return authflow.RegisterOutcome{}, stageErr("check_phone_conflict", err)
		}
		if phoneTaken {
			return authflow.RegisterOutcome{}, iam.ErrPhoneInUse
		}
		if usernameTaken {
			return authflow.RegisterOutcome{}, iam.ErrUsernameInUse
		}
		out := authflow.RegisterOutcome{Username: username, Phone: &phone}
		if requiresVerification {
			if _, err := s.issuePendingPhoneRegistration(ctx, phone, username, phc, in.PreferredLanguage); err != nil {
				return authflow.RegisterOutcome{}, registrationErr("send_phone_verification", err)
			}
			out.Kind = authflow.RegisterVerifyPhone
			return out, nil
		}
		// Never verified without proof (ak#393): "none" only means proof is not
		// required to use the account.
		account, err := s.registerAccount(ctx, accountRegistration{User: iam.ImportUserInput{PhoneNumber: phone, Username: username, PasswordHash: phc, HashAlgo: "argon2id"}, Language: in.PreferredLanguage, InviteToken: in.AccountInviteToken})
		if err != nil {
			return authflow.RegisterOutcome{}, err
		}
		if s.RegistrationVerificationPolicy() == iam.RegistrationVerificationOptional && s.SMSAvailable() {
			if err := s.SendPhoneVerificationToUser(ctx, phone, account.ID, 0); err != nil {
				slog.Warn("optional registration verification unavailable", "user_id", account.ID, "error", err)
			}
		}
		return s.registeredSession(ctx, in, out, account)
	}

	email := contact.NormalizeEmail(identifier)
	if requiresVerification && !s.HasEmailSender() {
		return authflow.RegisterOutcome{}, iam.ErrEmailRegistrationUnavailable
	}
	emailTaken, usernameTaken, err := s.CheckPendingRegistrationConflict(ctx, email, username)
	if err != nil {
		return authflow.RegisterOutcome{}, stageErr("check_email_conflict", err)
	}
	if emailTaken {
		return authflow.RegisterOutcome{}, iam.ErrEmailInUse
	}
	if usernameTaken {
		return authflow.RegisterOutcome{}, iam.ErrUsernameInUse
	}
	out := authflow.RegisterOutcome{Username: username, Email: &email}
	if requiresVerification {
		if _, err := s.issuePendingEmailRegistration(ctx, email, username, phc, 0, in.PreferredLanguage); err != nil {
			return authflow.RegisterOutcome{}, registrationErr("send_email_verification", err)
		}
		out.Kind = authflow.RegisterVerifyEmail
		return out, nil
	}
	account, err := s.registerAccount(ctx, accountRegistration{User: iam.ImportUserInput{Email: email, Username: username, PasswordHash: phc, HashAlgo: "argon2id"}, Language: in.PreferredLanguage, InviteToken: in.AccountInviteToken})
	if err != nil {
		return authflow.RegisterOutcome{}, err
	}
	if s.RegistrationVerificationPolicy() == iam.RegistrationVerificationOptional && s.HasEmailSender() {
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
	case errors.Is(err, iam.ErrEmailInUse), errors.Is(err, iam.ErrPhoneInUse), errors.Is(err, iam.ErrUsernameInUse),
		errors.Is(err, iam.ErrRegistrationDisabled), authflow.ValidationErrorCode(err) != "":
		return err
	default:
		return stageErr(stage, err)
	}
}

func (s *Engine) registeredSession(ctx context.Context, in authflow.RegisterInput, out authflow.RegisterOutcome, account registeredAccount) (authflow.RegisterOutcome, error) {
	login, err := s.finishFirstFactor(ctx, loginProof{Version: account.Version, AuthenticatedAt: time.Now().UTC(), Input: loginSessionInput{UserID: account.ID, AuthMethods: []string{"pwd"}, Event: "registration", UserAgent: in.UserAgent, IP: in.IP}})
	if err != nil {
		return authflow.RegisterOutcome{}, err
	}
	if login.Kind == authflow.LoginSessionIssued {
		out.Kind = authflow.RegisterSessionIssued
		out.Session = login.Session
	} else {
		out.Kind = authflow.RegisterLoginRequired
		out.Login = &login
	}
	return out, nil
}
