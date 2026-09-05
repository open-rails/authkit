package authhttp

import (
	"errors"
	"net/http"
	"strings"

	authkit "github.com/open-rails/authkit"

	"github.com/open-rails/authkit/embedded"
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
	language, ok := authkit.LanguageFromContext(r.Context())
	if !ok {
		return ""
	}
	return language
}

// handleRegisterUnifiedPOST: decode, rate-limit, one engine call, one switch.
// The registration policy (identifier classification, validation, verification
// mode, conflicts, the pending write + code send, the session) is
// embedded.Register (ak#318).
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
		badRequest(w, authkit.CodeInvalidRequest)
		return
	}
	identifier := strings.TrimSpace(req.Identifier)
	if identifier == "" || strings.TrimSpace(req.Username) == "" {
		badRequest(w, authkit.CodeInvalidRequest)
		return
	}
	// Per-identifier check: prevents spamming verification emails to the same
	// address from many IPs, each spending their own per-IP budget.
	if s.rateLimitedByIdentifier(w, r, RLAuthRegister, identifier) {
		return
	}

	out, err := s.svc.Register(r.Context(), embedded.RegisterInput{
		Identifier: identifier, Username: req.Username, Password: req.Password,
		PreferredLanguage: preferredLanguageFromRequest(r), AccountInviteToken: req.AccountInviteToken,
		UserAgent: r.UserAgent(), IP: remoteIP(r),
	})
	if err != nil {
		s.writeRegisterError(w, err)
		return
	}
	var tokens *authkit.TokenSet
	nextAction := registrationNextActionNone
	switch out.Kind {
	case embedded.RegisterVerifyEmail:
		nextAction = registrationNextActionVerifyEmail
	case embedded.RegisterVerifyPhone:
		nextAction = registrationNextActionVerifyPhone
	default:
		delivered := s.deliverRefreshToken(w, r, out.Session.TokenSet())
		tokens = &delivered
	}
	writeJSON(w, http.StatusAccepted, newRegistrationResponse(out.Username, out.Email, out.Phone, nextAction, tokens))
}

func (s *Service) writeRegisterError(w http.ResponseWriter, err error) {
	if errors.Is(err, authkit.ErrTwoFAEnrollmentRequired) {
		s.send2FAEnrollmentRequiredError(w)
		return
	}
	writeError(w, err)
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
		badRequest(w, authkit.CodeInvalidRequest)
		return
	}
	identifier := strings.TrimSpace(req.Identifier)
	if identifier == "" || req.Password == "" {
		badRequest(w, authkit.CodeInvalidRequest)
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
				serverErr(w, authkit.CodeAbandonFailed)
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
			serverErr(w, authkit.CodeAbandonFailed)
			return
		}
	}
	noContent(w)
}
