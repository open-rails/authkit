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
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/internal/naming"
	"github.com/open-rails/authkit/internal/password"
	"github.com/open-rails/authkit/internal/secret"
)

// Register runs the registration decision tree. Input problems come back as
// the validation errors (ValidationErrorCode) and the sentinels
// ErrInvalidIdentifier / ErrEmailInUse / ErrPhoneInUse / ErrUsernameInUse /
// ErrRegistrationDisabled / ErrEmailUnavailable /
// ErrSMSUnavailable; engine failures carry a stage prefix
// and, for sends, the delivery sentinel. When verification is required, an
// email or phone that an account holds answers like a free one and its owner
// is notified (registerTakenContact); ErrEmailInUse and ErrPhoneInUse then
// only mean a pending sign-up holds it.
func (s *Engine) Register(ctx context.Context, in authflow.RegisterInput) (authflow.RegisterOutcome, error) {
	if token := strings.TrimSpace(in.AccountInviteToken); token != "" {
		var err error
		ctx, err = s.proofContext(ctx, "registration-invite", secret.Hash(token))
		if err != nil {
			return authflow.RegisterOutcome{}, err
		}
	}
	if s.cfg.Registration.NativeUserMode == iam.RegistrationModeClosed {
		return authflow.RegisterOutcome{}, errmodel.ErrRegistrationDisabled
	}
	language, err := authflow.NormalizePreferredLanguage(in.PreferredLanguage)
	if err != nil {
		return authflow.RegisterOutcome{}, err
	}
	in.PreferredLanguage = language
	identifier := strings.TrimSpace(in.Identifier)
	username := naming.Canonical(in.Username)
	if identifier == "" || username == "" {
		return authflow.RegisterOutcome{}, errmodel.ErrInvalidIdentifier
	}
	agreements, err := s.acceptable(in.Agreements)
	if err != nil {
		return authflow.RegisterOutcome{}, err
	}
	if err := s.requireRegistrationAgreements(agreements); err != nil {
		return authflow.RegisterOutcome{}, err
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
		return authflow.RegisterOutcome{}, errmodel.ErrInvalidIdentifier
	}
	phc, err := password.HashArgon2id(ctx, in.Password)
	if err != nil {
		return authflow.RegisterOutcome{}, stageErr("hash_password", err)
	}
	requiresVerification := s.registrationVerificationRequired()

	ctx = contextWithAccountRegistrationInviteToken(ctx, in.AccountInviteToken)
	ctx = contextWithRegistrationAgreements(ctx, agreements)
	if isPhone {
		phone := contact.NormalizePhone(identifier)
		if requiresVerification && !s.SMSAvailable() {
			return authflow.RegisterOutcome{}, errmodel.ErrSMSUnavailable
		}
		phoneTaken, usernameTaken, err := s.CheckPhoneRegistrationConflict(ctx, phone, username)
		if err != nil {
			return authflow.RegisterOutcome{}, stageErr("check_phone_conflict", err)
		}
		if usernameTaken {
			return authflow.RegisterOutcome{}, iam.ErrUsernameInUse
		}
		out := authflow.RegisterOutcome{Username: username, Phone: &phone}
		if requiresVerification {
			switch {
			case !phoneTaken:
				_, err = s.issuePendingPhoneRegistration(ctx, phone, username, phc, in.PreferredLanguage)
			case s.pendingChangeTargetTaken(ctx, kindRegisterPhone, phone):
				return authflow.RegisterOutcome{}, iam.ErrPhoneInUse
			default:
				err = s.registerTakenContact(ctx, kindRegisterPhone, phone, username, phc, in.PreferredLanguage)
			}
			if err != nil {
				return authflow.RegisterOutcome{}, registrationErr("send_phone_verification", err)
			}
			out.Kind = authflow.RegisterVerifyPhone
			return out, nil
		}
		if phoneTaken {
			return authflow.RegisterOutcome{}, iam.ErrPhoneInUse
		}
		// Never verified without proof (ak#393): "none" only means proof is not
		// required to use the account.
		account, err := s.registerAccount(ctx, accountRegistration{User: newAccount{PhoneNumber: phone, Username: username, PasswordHash: phc, HashAlgo: "argon2id"}, Language: in.PreferredLanguage, InviteToken: in.AccountInviteToken, Agreements: agreements, IP: in.IP, UserAgent: in.UserAgent})
		if err != nil {
			return authflow.RegisterOutcome{}, err
		}
		if s.cfg.Registration.Verification == iam.RegistrationVerificationOptional && s.SMSAvailable() {
			if err := s.sendPhoneVerificationToUser(ctx, phone, account.ID, 0); err != nil {
				slog.Warn("optional registration verification unavailable", "user_id", account.ID, "error", err)
			}
		}
		return s.registeredSession(ctx, in, out, account)
	}

	email := contact.NormalizeEmail(identifier)
	if requiresVerification && !s.EmailAvailable() {
		return authflow.RegisterOutcome{}, errmodel.ErrEmailUnavailable
	}
	emailTaken, usernameTaken, err := s.CheckPendingRegistrationConflict(ctx, email, username)
	if err != nil {
		return authflow.RegisterOutcome{}, stageErr("check_email_conflict", err)
	}
	if usernameTaken {
		return authflow.RegisterOutcome{}, iam.ErrUsernameInUse
	}
	out := authflow.RegisterOutcome{Username: username, Email: &email}
	if requiresVerification {
		switch {
		case !emailTaken:
			_, err = s.issuePendingEmailRegistration(ctx, email, username, phc, 0, in.PreferredLanguage)
		case s.pendingChangeTargetTaken(ctx, kindRegisterEmail, email):
			// Every attempt leaves a pending sign-up, taken address or not, so
			// this says nothing about an account.
			return authflow.RegisterOutcome{}, iam.ErrEmailInUse
		default:
			err = s.registerTakenContact(ctx, kindRegisterEmail, email, username, phc, in.PreferredLanguage)
		}
		if err != nil {
			return authflow.RegisterOutcome{}, registrationErr("send_email_verification", err)
		}
		out.Kind = authflow.RegisterVerifyEmail
		return out, nil
	}
	// Without required proof a fresh sign-up signs in, which a taken address
	// cannot imitate.
	if emailTaken {
		return authflow.RegisterOutcome{}, iam.ErrEmailInUse
	}
	account, err := s.registerAccount(ctx, accountRegistration{User: newAccount{Email: email, Username: username, PasswordHash: phc, HashAlgo: "argon2id"}, Language: in.PreferredLanguage, InviteToken: in.AccountInviteToken, Agreements: agreements, IP: in.IP, UserAgent: in.UserAgent})
	if err != nil {
		return authflow.RegisterOutcome{}, err
	}
	if s.cfg.Registration.Verification == iam.RegistrationVerificationOptional && s.EmailAvailable() {
		if err := s.RequestEmailVerification(ctx, email, 0); err != nil {
			slog.Warn("optional registration verification unavailable", "user_id", account.ID, "error", err)
		}
	}
	return s.registeredSession(ctx, in, out, account)
}

// registerTakenContact is a fresh sign-up's pending step for an address an
// account holds. It runs the same admission check and leaves the same pending
// record, so the attempt holds its username, can be abandoned, and recovers by
// its password at sign-in (passwordRejected) like a fresh one. Its code is
// never sent and cannot match; the account's owner is notified instead.
func (s *Engine) registerTakenContact(ctx context.Context, kind pendingChangeKind, target, username, passwordHash, preferredLanguage string) error {
	allowed, err := s.registrationAllowedForEmail(ctx, target)
	if err != nil {
		return err
	}
	if !allowed {
		return errmodel.ErrRegistrationDisabled
	}
	language, err := authflow.NormalizePreferredLanguage(preferredLanguage)
	if err != nil {
		return err
	}
	if err := s.storePendingChange(ctx, pendingChange{
		Kind:              kind,
		Target:            target,
		Username:          username,
		PasswordHash:      passwordHash,
		PreferredLanguage: language,
		CodeHash:          secret.Hash(secret.Token(32)),
		LinkHash:          secret.Hash(secret.Token(32)),
	}, kind.defaultTTL()); err != nil {
		return err
	}
	return s.notifyAccountExists(ctx, notifyChannel(kind), target)
}

// renewTakenRegistration gives a placeholder a fresh lifetime wherever a
// re-send renews a real pending sign-up, so its expiry matches one. It does
// nothing when no pending record holds the target.
func (s *Engine) renewTakenRegistration(ctx context.Context, kind pendingChangeKind, target string) error {
	rec, ok, err := s.pendingChangeByTarget(ctx, kind, target)
	if err != nil || !ok {
		return err
	}
	return s.storePendingChange(ctx, pendingChange{
		Kind:               kind,
		Target:             rec.Target,
		Username:           rec.Username,
		PasswordHash:       rec.PasswordHash,
		PreferredLanguage:  rec.PreferredLanguage,
		AccountInviteToken: rec.AccountInviteToken,
		Agreements:         rec.Agreements,
		CodeHash:           secret.Hash(secret.Token(32)),
		LinkHash:           secret.Hash(secret.Token(32)),
	}, kind.defaultTTL())
}

func notifyChannel(kind pendingChangeKind) string {
	if kind.isEmail() {
		return "email"
	}
	return "sms"
}

// registrationErr keeps the typed conflicts, validation codes, delivery
// sentinels and ErrRegistrationDisabled visible through the stage tag.
func registrationErr(stage string, err error) error {
	switch {
	case errors.Is(err, iam.ErrEmailInUse), errors.Is(err, iam.ErrPhoneInUse), errors.Is(err, iam.ErrUsernameInUse),
		errors.Is(err, errmodel.ErrRegistrationDisabled), authflow.ValidationErrorCode(err) != "":
		return err
	default:
		return stageErr(stage, err)
	}
}

func (s *Engine) registeredSession(ctx context.Context, in authflow.RegisterInput, out authflow.RegisterOutcome, account registeredAccount) (authflow.RegisterOutcome, error) {
	login, err := s.finishFirstFactor(ctx, loginProof{Version: account.Version, AuthenticatedAt: time.Now().UTC(), Created: true, Input: loginSessionInput{UserID: account.ID, AuthMethods: []string{"pwd"}, Event: "registration", UserAgent: in.UserAgent, IP: in.IP}})
	if err != nil {
		return authflow.RegisterOutcome{}, err
	}
	out.Kind, out.Login = authflow.RegisterSignedIn, &login
	return out, nil
}
