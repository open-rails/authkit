package authhttp

import (
	"errors"
	"net/http"
	"strings"

	core "github.com/open-rails/authkit/core"
	pwhash "github.com/open-rails/authkit/password"
)

type registrationNextAction string

const (
	registrationNextActionNone        registrationNextAction = "none"
	registrationNextActionVerifyEmail registrationNextAction = "verify_email"
	registrationNextActionVerifyPhone registrationNextAction = "verify_phone"
)

type registrationResponse struct {
	OK              bool                   `json:"ok"`
	Username        string                 `json:"username"`
	Email           *string                `json:"email"`
	PhoneNumber     *string                `json:"phone_number"`
	DiscordUsername *string                `json:"discord_username"`
	NextAction      registrationNextAction `json:"next_action"`
	AccessToken     string                 `json:"access_token,omitempty"`
	TokenType       string                 `json:"token_type,omitempty"`
	ExpiresIn       int64                  `json:"expires_in,omitempty"`
	RefreshToken    string                 `json:"refresh_token,omitempty"`
}

func newRegistrationResponse(username string, email, phone *string, nextAction registrationNextAction, tokens *authTokensResponse) registrationResponse {
	resp := registrationResponse{
		OK:              true,
		Username:        username,
		Email:           email,
		PhoneNumber:     phone,
		DiscordUsername: nil,
		NextAction:      nextAction,
	}
	if tokens != nil {
		resp.AccessToken = tokens.AccessToken
		resp.TokenType = tokens.TokenType
		resp.ExpiresIn = tokens.ExpiresIn
		resp.RefreshToken = tokens.RefreshToken
	}
	return resp
}

func (s *Service) handleRegisterUnifiedPOST(w http.ResponseWriter, r *http.Request) {
	if s.rateLimited(w, r, RLAuthRegister) {
		return
	}

	var req struct {
		Identifier string `json:"identifier"`
		Username   string `json:"username"`
		Password   string `json:"password"`
	}
	if err := decodeJSON(r, &req); err != nil {
		badRequest(w, "invalid_request")
		return
	}

	identifier := strings.TrimSpace(req.Identifier)
	username := strings.TrimSpace(req.Username)
	pass := req.Password

	if identifier == "" || username == "" {
		badRequest(w, "invalid_request")
		return
	}
	if err := core.ValidatePassword(pass); err != nil {
		badRequest(w, core.ValidationErrorCode(err))
		return
	}
	if _, err := s.svc.ValidateUsernameForRegistration(r.Context(), username); err != nil {
		if code := core.ValidationErrorCode(err); code != "" {
			badRequest(w, code)
			return
		}
		s.logInternalError(r, "register", "validate_username", "database_error", err)
		serverErr(w, "database_error")
		return
	}
	username = strings.TrimSpace(username)

	isPhone := core.ValidatePhone(identifier) == nil
	isEmail := core.ValidateEmail(identifier) == nil
	if !isPhone && !isEmail {
		badRequest(w, "invalid_identifier")
		return
	}
	if isPhone && isEmail {
		badRequest(w, "invalid_identifier")
		return
	}

	phc, err := pwhash.HashArgon2id(pass)
	if err != nil {
		serverErr(w, "hash_failed")
		return
	}

	policy := s.svc.Options().RegistrationVerificationPolicy()
	requiresVerification := policy == core.RegistrationVerificationRequired

	if isPhone {
		identifier = core.NormalizePhone(identifier)
		if requiresVerification && !s.svc.HasSMSSender() {
			serverErr(w, "phone_registration_unavailable")
			return
		}
		phoneTaken, usernameTaken, err := s.svc.CheckPhoneRegistrationConflict(r.Context(), identifier, username)
		if err != nil {
			s.logInternalError(r, "register", "check_phone_conflict", "database_error", err)
			serverErr(w, "database_error")
			return
		}
		if phoneTaken {
			badRequest(w, "phone_in_use")
			return
		}
		if usernameTaken {
			badRequest(w, "username_in_use")
			return
		}
		_, err = s.svc.CreatePendingPhoneRegistration(r.Context(), identifier, username, phc)
		if err != nil {
			if s.handleDeliveryError(w, r, "register", "send_phone_verification", err) {
				return
			}
			if code := core.ValidationErrorCode(err); code != "" {
				badRequest(w, code)
				return
			}
			serverErr(w, "registration_failed")
			return
		}

		nextAction := registrationNextActionNone
		var tokens *authTokensResponse
		if requiresVerification {
			nextAction = registrationNextActionVerifyPhone
		} else {
			u, err := s.svc.GetUserByPhone(r.Context(), identifier)
			if err != nil || u == nil {
				serverErr(w, "registration_failed")
				return
			}
			tokenSet, err := s.createTokensForUser(r, u.ID, "registration")
			if err != nil {
				if errors.Is(err, core.ErrUserBanned) {
					unauthorized(w, "user_banned")
					return
				}
				serverErr(w, "token_issue_failed")
				return
			}
			tokens = &tokenSet
		}

		writeJSON(w, http.StatusAccepted, newRegistrationResponse(username, nil, &identifier, nextAction, tokens))
		return
	}

	identifier = core.NormalizeEmail(identifier)
	if requiresVerification && !s.svc.HasEmailSender() {
		serverErr(w, "email_registration_unavailable")
		return
	}
	emailTaken, usernameTaken, err := s.svc.CheckPendingRegistrationConflict(r.Context(), identifier, username)
	if err != nil {
		s.logInternalError(r, "register", "check_email_conflict", "database_error", err)
		serverErr(w, "database_error")
		return
	}
	if emailTaken {
		badRequest(w, "email_in_use")
		return
	}
	if usernameTaken {
		badRequest(w, "username_in_use")
		return
	}
	_, err = s.svc.CreatePendingRegistration(r.Context(), identifier, username, phc, 0)
	if err != nil {
		if s.handleDeliveryError(w, r, "register", "send_email_verification", err) {
			return
		}
		if code := core.ValidationErrorCode(err); code != "" {
			badRequest(w, code)
			return
		}
		serverErr(w, "registration_failed")
		return
	}

	nextAction := registrationNextActionNone
	var tokens *authTokensResponse
	if requiresVerification {
		nextAction = registrationNextActionVerifyEmail
	} else {
		u, err := s.svc.GetUserByEmail(r.Context(), identifier)
		if err != nil || u == nil {
			serverErr(w, "registration_failed")
			return
		}
		tokenSet, err := s.createTokensForUser(r, u.ID, "registration")
		if err != nil {
			if errors.Is(err, core.ErrUserBanned) {
				unauthorized(w, "user_banned")
				return
			}
			serverErr(w, "token_issue_failed")
			return
		}
		tokens = &tokenSet
	}

	writeJSON(w, http.StatusAccepted, newRegistrationResponse(username, &identifier, nil, nextAction, tokens))
}

func (s *Service) handlePendingRegistrationResendPOST(w http.ResponseWriter, r *http.Request) {
	if !s.svc.Options().RegistrationVerificationEnabled() {
		writeJSON(w, http.StatusAccepted, map[string]any{"ok": true})
		return
	}
	if s.rateLimited(w, r, RLAuthRegisterResendEmail) {
		return
	}

	var req struct {
		Email string `json:"email"`
	}
	if err := decodeJSON(r, &req); err != nil {
		badRequest(w, "invalid_request")
		return
	}
	if err := core.ValidateEmail(req.Email); err != nil {
		badRequest(w, core.ValidationErrorCode(err))
		return
	}
	if !s.svc.HasEmailSender() {
		serverErr(w, "email_unavailable")
		return
	}
	email := strings.TrimSpace(req.Email)

	pendingUser, err := s.svc.GetPendingRegistrationByEmail(r.Context(), email)
	if err != nil || pendingUser == nil {
		notFound(w, "pending_registration_not_found")
		return
	}
	if _, err := s.svc.CreatePendingRegistration(r.Context(), email, pendingUser.Username, pendingUser.PasswordHash, 0); err != nil {
		if s.handleDeliveryError(w, r, "register_resend_email", "send_email_verification", err) {
			return
		}
		s.logInternalError(r, "register_resend_email", "create_pending_registration", "resend_failed", err)
		serverErr(w, "resend_failed")
		return
	}

	writeJSON(w, http.StatusAccepted, map[string]any{"ok": true})
}

func (s *Service) handlePhoneRegisterResendPOST(w http.ResponseWriter, r *http.Request) {
	if !s.svc.Options().RegistrationVerificationEnabled() {
		writeJSON(w, http.StatusAccepted, map[string]any{"ok": true})
		return
	}
	if s.rateLimited(w, r, RLAuthRegisterResendPhone) {
		return
	}

	var req struct {
		PhoneNumber string `json:"phone_number"`
	}
	if err := decodeJSON(r, &req); err != nil {
		badRequest(w, "invalid_request")
		return
	}
	phone := strings.TrimSpace(req.PhoneNumber)
	if err := core.ValidatePhone(phone); err != nil {
		badRequest(w, core.ValidationErrorCode(err))
		return
	}
	phone = core.NormalizePhone(phone)

	if !s.svc.HasSMSSender() {
		serverErr(w, "phone_unavailable")
		return
	}
	pending, err := s.svc.GetPendingPhoneRegistrationByPhone(r.Context(), phone)
	if err != nil || pending == nil {
		notFound(w, "pending_registration_not_found")
		return
	}
	if _, err := s.svc.CreatePendingPhoneRegistration(r.Context(), phone, pending.Username, pending.PasswordHash); err != nil {
		if s.handleDeliveryError(w, r, "register_resend_phone", "send_phone_verification", err) {
			return
		}
		s.logInternalError(r, "register_resend_phone", "create_pending_phone_registration", "resend_failed", err)
		serverErr(w, "resend_failed")
		return
	}

	writeJSON(w, http.StatusAccepted, map[string]any{"ok": true})
}
