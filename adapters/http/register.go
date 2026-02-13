package authhttp

import (
	"net/http"
	"strings"

	pwhash "github.com/open-rails/authkit/password"
)

func (s *Service) handleRegisterUnifiedPOST(w http.ResponseWriter, r *http.Request) {
	if !s.allow(r, RLAuthRegister) {
		tooMany(w)
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

	if identifier == "" || username == "" || pwhash.Validate(pass) != nil {
		badRequest(w, "invalid_request")
		return
	}
	if err := validateUsername(username); err != nil {
		badRequest(w, err.Error())
		return
	}

	isPhone := reE164.MatchString(identifier)
	isEmail := strings.Contains(identifier, "@")
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

	if isPhone {
		if s.svc.Options().VerificationRequired && !s.svc.HasSMSSender() {
			serverErr(w, "phone_registration_unavailable")
			return
		}
		phoneTaken, usernameTaken, err := s.svc.CheckPhoneRegistrationConflict(r.Context(), identifier, username)
		if err != nil {
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
			serverErr(w, "registration_failed")
			return
		}
		msg := "Registration pending. Please check your phone for a verification code."
		if !s.svc.Options().VerificationRequired {
			msg = "Registration successful. You can log in immediately."
		}
		writeJSON(w, http.StatusAccepted, map[string]any{
			"ok":      true,
			"message": msg,
			"phone":   identifier,
		})
		return
	}

	if s.svc.Options().VerificationRequired && !s.svc.HasEmailSender() {
		serverErr(w, "email_registration_unavailable")
		return
	}
	emailTaken, usernameTaken, err := s.svc.CheckPendingRegistrationConflict(r.Context(), identifier, username)
	if err != nil {
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
		serverErr(w, "registration_failed")
		return
	}

	msg := "Registration pending. Please check your email to verify your account."
	if !s.svc.Options().VerificationRequired {
		msg = "Registration successful. You can log in immediately."
	}
	writeJSON(w, http.StatusAccepted, map[string]any{
		"ok":      true,
		"message": msg,
		"email":   identifier,
	})
}

func (s *Service) handlePendingRegistrationResendPOST(w http.ResponseWriter, r *http.Request) {
	if s.svc.Options().VerificationRequired && !s.svc.HasEmailSender() {
		serverErr(w, "email_unavailable")
		return
	}
	if !s.allow(r, RLAuthRegisterResendEmail) {
		tooMany(w)
		return
	}

	var req struct {
		Email string `json:"email"`
	}
	if err := decodeJSON(r, &req); err != nil || strings.TrimSpace(req.Email) == "" {
		writeJSON(w, http.StatusAccepted, map[string]any{"ok": true})
		return
	}
	email := strings.TrimSpace(req.Email)

	pendingUser, err := s.svc.GetPendingRegistrationByEmail(r.Context(), email)
	if err == nil && pendingUser != nil {
		_, _ = s.svc.CreatePendingRegistration(r.Context(), email, pendingUser.Username, pendingUser.PasswordHash, 0)
	}

	writeJSON(w, http.StatusAccepted, map[string]any{"ok": true, "message": "If a pending registration exists, a new code has been sent."})
}

func (s *Service) handlePhoneRegisterResendPOST(w http.ResponseWriter, r *http.Request) {
	if s.svc.Options().VerificationRequired && !s.svc.HasSMSSender() {
		serverErr(w, "phone_unavailable")
		return
	}
	if !s.allow(r, RLAuthRegisterResendPhone) {
		tooMany(w)
		return
	}

	var req struct {
		PhoneNumber string `json:"phone_number"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeJSON(w, http.StatusAccepted, map[string]any{"ok": true})
		return
	}
	phone := strings.TrimSpace(req.PhoneNumber)
	if phone == "" || !reE164.MatchString(phone) {
		writeJSON(w, http.StatusAccepted, map[string]any{"ok": true})
		return
	}

	pending, err := s.svc.GetPendingPhoneRegistrationByPhone(r.Context(), phone)
	if err == nil && pending != nil {
		_, _ = s.svc.CreatePendingPhoneRegistration(r.Context(), phone, pending.Username, pending.PasswordHash)
	}

	writeJSON(w, http.StatusAccepted, map[string]any{"ok": true, "message": "If a pending registration exists, a new code has been sent."})
}
