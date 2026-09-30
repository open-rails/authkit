package httpapi

import (
	"errors"
	"net/http"
	"strings"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/contact"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/internal/lang"
)

func preferredLanguageFromRequest(r *http.Request) string { return lang.Request(r.Context()) }

// handleRegisterUnifiedPOST: decode, rate-limit, one engine call, one switch.
// The registration policy (identifier classification, validation, verification
// mode, conflicts, the pending write + code send, the session) is
// authkit.Register (ak#318).
func (s *Service) handleRegisterUnifiedPOST(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Registration.NativeUserMode == iam.RegistrationModeClosed {
		registrationDisabled(w)
		return
	}
	var req RegisterRequest
	if err := decodeJSON(r, &req); err != nil {
		fail(w, errmodel.CodeInvalidRequest)
		return
	}
	identifier := strings.TrimSpace(req.Identifier)
	if identifier == "" || strings.TrimSpace(req.Username) == "" {
		fail(w, errmodel.CodeInvalidRequest)
		return
	}
	// Per-identifier check: prevents spamming verification emails to the same
	// address from many IPs, each spending their own per-IP budget.
	if s.rateLimitedByIdentifier(w, r, RLAuthRegister, identifier) {
		return
	}

	out, err := s.svc.Register(r.Context(), authflow.RegisterInput{
		Identifier: identifier, Username: req.Username, Password: req.Password,
		PreferredLanguage: preferredLanguageFromRequest(r), AccountInviteToken: req.InviteCode,
		UserAgent: r.UserAgent(), IP: s.requestIP(r),
	})
	if err != nil {
		s.writeRegisterError(w, err)
		return
	}
	switch out.Kind {
	case authflow.RegisterLoginRequired:
		s.writeLoginContinuation(w, r, *out.Login, nil)
	case authflow.RegisterVerifyEmail, authflow.RegisterVerifyPhone:
		// The code is sent to the identifier; confirming it signs in.
		accepted(w)
	default:
		writeJSON(w, http.StatusOK, RegistrationResult{
			User:     RegistrationUser{Username: out.Username, Email: out.Email, PhoneNumber: out.Phone},
			TokenSet: s.deliverRefreshToken(w, r, out.Session.TokenSet()),
		})
	}
}

func (s *Service) writeRegisterError(w http.ResponseWriter, err error) {
	if errors.Is(err, iam.ErrTwoFAEnrollmentRequired) {
		s.send2FAEnrollmentRequiredError(w)
		return
	}
	writeError(w, err)
}

// handlePendingRegistrationAbandonPOST lets a user cancel/abandon a pending
// (unverified) registration they created — e.g. after mistyping their email or
// phone. Ownership is proven by the password set during registration (the only
// secret the user still has when they never received the verification code).
// Answers 204 whether or not a matching pending registration existed,
// so the endpoint never reveals whether a given identifier is mid-signup.
func (s *Service) handlePendingRegistrationAbandonPOST(w http.ResponseWriter, r *http.Request) {
	if s.publicRegistrationDisabled() {
		registrationDisabled(w)
		return
	}
	var req IdentifierPasswordRequest
	if err := decodeJSON(r, &req); err != nil {
		fail(w, errmodel.CodeInvalidRequest)
		return
	}
	identifier := strings.TrimSpace(req.Identifier)
	if identifier == "" || req.Password == "" {
		fail(w, errmodel.CodeInvalidRequest)
		return
	}
	if s.rateLimitedByIdentifier(w, r, RLAuthRegisterAbandon, identifier) {
		return
	}

	if strings.HasPrefix(identifier, "+") {
		phone := contact.NormalizePhone(identifier)
		// Only delete when the password matches; otherwise respond ok without
		// revealing whether a pending registration exists (anti-enumeration).
		if s.svc.VerifyPendingPhonePassword(r.Context(), phone, req.Password) {
			if err := s.svc.DeletePendingPhoneRegistrationByPhone(r.Context(), phone); err != nil {
				s.logInternalError(r, "register_abandon", "delete_pending_phone_registration", "abandon_failed", err)
				serverErr(w, "abandon_failed", nil)
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
			serverErr(w, "abandon_failed", nil)
			return
		}
	}
	noContent(w)
}
