package authhttp

import (
	"errors"
	"net/http"
	"strings"

	authkit "github.com/open-rails/authkit"

	"github.com/open-rails/authkit/embedded"
	"github.com/open-rails/authkit/internal/authcore"
	authlang "github.com/open-rails/authkit/lang"
	pwhash "github.com/open-rails/authkit/password"
)

type registrationNextAction string

const (
	registrationNextActionNone        registrationNextAction = "none"
	registrationNextActionVerifyEmail registrationNextAction = "verify_email"
	registrationNextActionVerifyPhone registrationNextAction = "verify_phone"
)

// registrationResponse: what happens next, who was registered, and — when no
// verification is pending — the session (#313).
type registrationResponse struct {
	NextAction registrationNextAction `json:"next_action"`
	User       registrationUser       `json:"user"`
	TokenSet   *authkit.TokenSet      `json:"token_set,omitempty"`
}

type registrationUser struct {
	Username    string  `json:"username"`
	Email       *string `json:"email"`
	PhoneNumber *string `json:"phone_number"`
}

func newRegistrationResponse(username string, email, phone *string, nextAction registrationNextAction, tokens *authkit.TokenSet) registrationResponse {
	return registrationResponse{
		NextAction: nextAction,
		User:       registrationUser{Username: username, Email: email, PhoneNumber: phone},
		TokenSet:   tokens,
	}
}

func preferredLanguageFromRequest(r *http.Request) string {
	if r == nil {
		return ""
	}
	language, ok := authlang.LanguageFromContext(r.Context())
	if !ok {
		return ""
	}
	return language
}

func (s *Service) handleRegisterUnifiedPOST(w http.ResponseWriter, r *http.Request) {
	if s.svc.Config().Registration.NativeUserMode == embedded.RegistrationModeClosed {
		registrationDisabled(w)
		return
	}
	var req struct {
		Identifier         string `json:"identifier"`
		Username           string `json:"username"`
		Password           string `json:"password"`
		AccountInviteToken string `json:"account_invite_token,omitempty"`
	}
	if err := decodeJSON(r, &req); err != nil {
		badRequest(w, ErrInvalidRequest)
		return
	}

	identifier := strings.TrimSpace(req.Identifier)
	username := strings.TrimSpace(req.Username)
	pass := req.Password

	if identifier == "" || username == "" {
		badRequest(w, ErrInvalidRequest)
		return
	}

	// Per-identifier check: prevents spamming verification emails to the same
	// address from many IPs, each spending their own per-IP budget.
	if s.rateLimitedByIdentifier(w, r, RLAuthRegister, identifier) {
		return
	}
	if err := embedded.ValidatePassword(pass); err != nil {
		badRequest(w, ErrorCode(embedded.ValidationErrorCode(err)))
		return
	}
	if _, err := s.svc.ValidateUsernameForRegistration(r.Context(), username); err != nil {
		if code := ErrorCode(embedded.ValidationErrorCode(err)); code != "" {
			badRequest(w, code)
			return
		}
		s.logInternalError(r, "register", "validate_username", "database_error", err)
		serverErr(w, ErrDatabaseError)
		return
	}
	username = strings.TrimSpace(username)

	isPhone := embedded.ValidatePhone(identifier) == nil
	isEmail := embedded.ValidateEmail(identifier) == nil
	if !isPhone && !isEmail {
		badRequest(w, ErrInvalidIdentifier)
		return
	}
	if isPhone && isEmail {
		badRequest(w, ErrInvalidIdentifier)
		return
	}

	phc, err := pwhash.HashArgon2id(pass)
	if err != nil {
		serverErr(w, ErrHashFailed)
		return
	}

	policy := s.svc.RegistrationVerificationPolicy()
	requiresVerification := policy == embedded.RegistrationVerificationRequired
	preferredLanguage := preferredLanguageFromRequest(r)

	if isPhone {
		identifier = embedded.NormalizePhone(identifier)
		if requiresVerification && !s.svc.SMSAvailable() {
			serverErr(w, ErrPhoneRegistrationUnavailable)
			return
		}
		phoneTaken, usernameTaken, err := s.svc.CheckPhoneRegistrationConflict(r.Context(), identifier, username)
		if err != nil {
			s.logInternalError(r, "register", "check_phone_conflict", "database_error", err)
			serverErr(w, ErrDatabaseError)
			return
		}
		if phoneTaken {
			badRequest(w, ErrPhoneInUse)
			return
		}
		if usernameTaken {
			badRequest(w, ErrUsernameInUse)
			return
		}
		_, err = s.svc.CreatePendingPhoneRegistrationWithLanguage(r.Context(), identifier, username, phc, preferredLanguage)
		if err != nil {
			if s.handleDeliveryError(w, r, "register", "send_phone_verification", err) {
				return
			}
			if errors.Is(err, authkit.ErrPhoneInUse) {
				badRequest(w, ErrPhoneInUse)
				return
			}
			if errors.Is(err, authkit.ErrUsernameInUse) {
				badRequest(w, ErrUsernameInUse)
				return
			}
			if code := ErrorCode(embedded.ValidationErrorCode(err)); code != "" {
				badRequest(w, code)
				return
			}
			if errors.Is(err, authkit.ErrRegistrationDisabled) {
				registrationDisabled(w)
				return
			}
			serverErr(w, ErrRegistrationFailed)
			return
		}

		nextAction := registrationNextActionNone
		var tokens *authkit.TokenSet
		if requiresVerification {
			nextAction = registrationNextActionVerifyPhone
		} else {
			u, err := s.svc.GetUserByPhone(r.Context(), identifier)
			if err != nil || u == nil {
				serverErr(w, ErrRegistrationFailed)
				return
			}
			tokenSet, err := s.createTokensForUser(r, u.ID, "registration")
			if err != nil {
				if errors.Is(err, authkit.ErrUserBanned) {
					unauthorized(w, ErrUserBanned)
					return
				}
				serverErr(w, ErrTokenIssueFailed)
				return
			}
			delivered := s.deliverRefreshToken(w, r, tokenSet)
			tokens = &delivered
		}

		writeJSON(w, http.StatusAccepted, newRegistrationResponse(username, nil, &identifier, nextAction, tokens))
		return
	}

	identifier = embedded.NormalizeEmail(identifier)
	if requiresVerification && !s.svc.HasEmailSender() {
		serverErr(w, ErrEmailRegistrationUnavailable)
		return
	}
	emailTaken, usernameTaken, err := s.svc.CheckPendingRegistrationConflict(r.Context(), identifier, username)
	if err != nil {
		s.logInternalError(r, "register", "check_email_conflict", "database_error", err)
		serverErr(w, ErrDatabaseError)
		return
	}
	if emailTaken {
		badRequest(w, ErrEmailInUse)
		return
	}
	if usernameTaken {
		badRequest(w, ErrUsernameInUse)
		return
	}
	ctx := authcore.WithAccountRegistrationInviteToken(r.Context(), req.AccountInviteToken)
	_, err = s.svc.CreatePendingRegistrationWithLanguage(ctx, identifier, username, phc, 0, preferredLanguage)
	if err != nil {
		if s.handleDeliveryError(w, r, "register", "send_email_verification", err) {
			return
		}
		// #326: the race loser of check-then-insert gets the typed conflict.
		if errors.Is(err, authkit.ErrEmailInUse) {
			badRequest(w, ErrEmailInUse)
			return
		}
		if errors.Is(err, authkit.ErrUsernameInUse) {
			badRequest(w, ErrUsernameInUse)
			return
		}
		if code := ErrorCode(embedded.ValidationErrorCode(err)); code != "" {
			badRequest(w, code)
			return
		}
		if errors.Is(err, authkit.ErrRegistrationDisabled) {
			registrationDisabled(w)
			return
		}
		serverErr(w, ErrRegistrationFailed)
		return
	}

	nextAction := registrationNextActionNone
	var tokens *authkit.TokenSet
	if requiresVerification {
		nextAction = registrationNextActionVerifyEmail
	} else {
		u, err := s.svc.GetUserByEmail(r.Context(), identifier)
		if err != nil || u == nil {
			serverErr(w, ErrRegistrationFailed)
			return
		}
		tokenSet, err := s.createTokensForUser(r, u.ID, "registration")
		if err != nil {
			if errors.Is(err, authkit.ErrUserBanned) {
				unauthorized(w, ErrUserBanned)
				return
			}
			serverErr(w, ErrTokenIssueFailed)
			return
		}
		delivered := s.deliverRefreshToken(w, r, tokenSet)
		tokens = &delivered
	}

	writeJSON(w, http.StatusAccepted, newRegistrationResponse(username, &identifier, nil, nextAction, tokens))
}

// handlePendingRegistrationAbandonPOST lets a user cancel/abandon a pending
// (unverified) registration they created — e.g. after mistyping their email or
// phone. Ownership is proven by the password set during registration (the only
// secret the user still has when they never received the verification code).
// Responds 200 {ok:true} whether or not a matching pending registration existed,
// so the endpoint never reveals whether a given identifier is mid-signup.
func (s *Service) handlePendingRegistrationAbandonPOST(w http.ResponseWriter, r *http.Request) {
	if s.publicRegistrationDisabled() {
		registrationDisabled(w)
		return
	}
	var req struct {
		Identifier string `json:"identifier"`
		Password   string `json:"password"`
	}
	if err := decodeJSON(r, &req); err != nil {
		badRequest(w, ErrInvalidRequest)
		return
	}
	identifier := strings.TrimSpace(req.Identifier)
	if identifier == "" || req.Password == "" {
		badRequest(w, ErrInvalidRequest)
		return
	}
	if s.rateLimitedByIdentifier(w, r, RLAuthRegisterAbandon, identifier) {
		return
	}

	if strings.HasPrefix(identifier, "+") {
		phone := embedded.NormalizePhone(identifier)
		// Only delete when the password matches; otherwise respond ok without
		// revealing whether a pending registration exists (anti-enumeration).
		if s.svc.VerifyPendingPhonePassword(r.Context(), phone, req.Password) {
			if err := s.svc.DeletePendingPhoneRegistrationByPhone(r.Context(), phone); err != nil {
				s.logInternalError(r, "register_abandon", "delete_pending_phone_registration", "abandon_failed", err)
				serverErr(w, ErrAbandonFailed)
				return
			}
		}
		noContent(w)
		return
	}

	email := strings.TrimSpace(identifier)
	if s.svc.VerifyPendingPassword(r.Context(), email, req.Password) {
		if err := s.svc.DeletePendingRegistrationByEmail(r.Context(), email); err != nil {
			s.logInternalError(r, "register_abandon", "delete_pending_registration", "abandon_failed", err)
			serverErr(w, ErrAbandonFailed)
			return
		}
	}
	noContent(w)
}
