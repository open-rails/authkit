package authhttp

import (
	"net/http"
	"strings"

	core "github.com/open-rails/authkit/core"
)

func (s *Service) handleUserUsernamePATCH(w http.ResponseWriter, r *http.Request) {
	if !s.allow(r, RLUserUpdateUsername) {
		tooMany(w)
		return
	}
	claims, ok := ClaimsFromContext(r.Context())
	if !ok || claims.UserID == "" {
		unauthorized(w, "unauthorized")
		return
	}
	var body struct {
		Username string `json:"username"`
	}
	if err := decodeJSON(r, &body); err != nil || strings.TrimSpace(body.Username) == "" {
		badRequest(w, "invalid_request")
		return
	}

	if err := validateUsername(body.Username); err != nil {
		badRequest(w, err.Error())
		return
	}

	if err := s.svc.UpdateUsername(r.Context(), claims.UserID, body.Username); err != nil {
		if err == core.ErrOwnerSlugTaken {
			badRequest(w, "owner_slug_taken")
			return
		}
		badRequest(w, "failed_to_update_username")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Service) handleUserEmailChangeRequestPOST(w http.ResponseWriter, r *http.Request) {
	if !s.svc.HasEmailSender() {
		serverErr(w, "email_verification_unavailable")
		return
	}
	if !s.allow(r, RLUserEmailChangeRequest) {
		tooMany(w)
		return
	}

	claims, ok := ClaimsFromContext(r.Context())
	if !ok || claims.UserID == "" {
		unauthorized(w, "not_authenticated")
		return
	}

	var body struct {
		NewEmail string `json:"new_email"`
		Password string `json:"password"`
	}
	if err := decodeJSON(r, &body); err != nil || strings.TrimSpace(body.NewEmail) == "" || body.Password == "" {
		badRequest(w, "invalid_request")
		return
	}

	_, _, err := s.svc.PasswordLoginByUserID(r.Context(), claims.UserID, body.Password, nil)
	if err != nil {
		unauthorized(w, "invalid_password")
		return
	}

	if err := s.svc.RequestEmailChange(r.Context(), claims.UserID, body.NewEmail); err != nil {
		msg := err.Error()
		switch {
		case strings.Contains(msg, "same as current"):
			badRequest(w, "email_unchanged")
		case strings.Contains(msg, "already in use"):
			badRequest(w, "email_in_use")
		default:
			badRequest(w, "failed_to_request_email_change")
		}
		return
	}

	writeJSON(w, http.StatusAccepted, map[string]any{
		"ok":      true,
		"message": "Verification code sent to new email address",
	})
}

func (s *Service) handleUserEmailChangeConfirmPOST(w http.ResponseWriter, r *http.Request) {
	if !s.allow(r, RLUserEmailChangeConfirm) {
		tooMany(w)
		return
	}

	claims, ok := ClaimsFromContext(r.Context())
	if !ok || claims.UserID == "" {
		unauthorized(w, "not_authenticated")
		return
	}

	var body struct {
		Code string `json:"code"`
	}
	if err := decodeJSON(r, &body); err != nil || strings.TrimSpace(body.Code) == "" {
		badRequest(w, "invalid_request")
		return
	}

	code := strings.ToUpper(strings.TrimSpace(body.Code))
	if err := s.svc.ConfirmEmailChange(r.Context(), claims.UserID, code); err != nil {
		badRequest(w, "invalid_or_expired_code")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"message": "Email changed successfully",
	})
}

func (s *Service) handleUserEmailChangeResendPOST(w http.ResponseWriter, r *http.Request) {
	if !s.svc.HasEmailSender() {
		serverErr(w, "email_verification_unavailable")
		return
	}
	if !s.allow(r, RLUserEmailChangeResend) {
		tooMany(w)
		return
	}

	claims, ok := ClaimsFromContext(r.Context())
	if !ok || claims.UserID == "" {
		unauthorized(w, "not_authenticated")
		return
	}

	if err := s.svc.ResendEmailChangeCode(r.Context(), claims.UserID); err != nil {
		badRequest(w, "no_pending_email_change")
		return
	}

	writeJSON(w, http.StatusAccepted, map[string]any{
		"ok":      true,
		"message": "Verification code resent",
	})
}

func (s *Service) handleUserPhoneChangeRequestPOST(w http.ResponseWriter, r *http.Request) {
	if !s.allow(r, RLUserPhoneChangeRequest) {
		tooMany(w)
		return
	}

	claims, ok := ClaimsFromContext(r.Context())
	if !ok || claims.UserID == "" {
		unauthorized(w, "not_authenticated")
		return
	}

	var body struct {
		NewPhone string `json:"phone_number"`
		Password string `json:"password"`
	}
	if err := decodeJSON(r, &body); err != nil || strings.TrimSpace(body.NewPhone) == "" || body.Password == "" {
		badRequest(w, "invalid_request")
		return
	}

	_, _, err := s.svc.PasswordLoginByUserID(r.Context(), claims.UserID, body.Password, nil)
	if err != nil {
		unauthorized(w, "invalid_password")
		return
	}

	if err := s.svc.RequestPhoneChange(r.Context(), claims.UserID, body.NewPhone); err != nil {
		msg := err.Error()
		switch {
		case strings.Contains(msg, "same as current"):
			badRequest(w, "phone_unchanged")
		case strings.Contains(msg, "already in use"):
			badRequest(w, "phone_in_use")
		default:
			badRequest(w, "failed_to_request_phone_change")
		}
		return
	}

	writeJSON(w, http.StatusAccepted, map[string]any{
		"ok":      true,
		"message": "Verification code sent to new phone",
	})
}

func (s *Service) handleUserPhoneChangeConfirmPOST(w http.ResponseWriter, r *http.Request) {
	if !s.allow(r, RLUserPhoneChangeConfirm) {
		tooMany(w)
		return
	}

	claims, ok := ClaimsFromContext(r.Context())
	if !ok || claims.UserID == "" {
		unauthorized(w, "not_authenticated")
		return
	}

	var body struct {
		Phone string `json:"phone_number"`
		Code  string `json:"code"`
	}
	if err := decodeJSON(r, &body); err != nil || strings.TrimSpace(body.Code) == "" || strings.TrimSpace(body.Phone) == "" {
		badRequest(w, "invalid_request")
		return
	}

	code := strings.TrimSpace(body.Code)
	phone := strings.TrimSpace(body.Phone)
	if err := s.svc.ConfirmPhoneChange(r.Context(), claims.UserID, phone, code); err != nil {
		badRequest(w, "invalid_or_expired_code")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"message": "Phone number changed successfully",
	})
}

func (s *Service) handleUserPhoneChangeResendPOST(w http.ResponseWriter, r *http.Request) {
	if !s.allow(r, RLUserPhoneChangeResend) {
		tooMany(w)
		return
	}

	claims, ok := ClaimsFromContext(r.Context())
	if !ok || claims.UserID == "" {
		unauthorized(w, "not_authenticated")
		return
	}

	var body struct {
		Phone string `json:"phone_number"`
	}
	if err := decodeJSON(r, &body); err != nil || strings.TrimSpace(body.Phone) == "" {
		badRequest(w, "invalid_request")
		return
	}
	phone := strings.TrimSpace(body.Phone)

	if err := s.svc.ResendPhoneChangeCode(r.Context(), claims.UserID, phone); err != nil {
		badRequest(w, "no_pending_phone_change")
		return
	}

	writeJSON(w, http.StatusAccepted, map[string]any{
		"ok":      true,
		"message": "Verification code resent",
	})
}

func (s *Service) handleUserBiographyPATCH(w http.ResponseWriter, r *http.Request) {
	claims, ok := ClaimsFromContext(r.Context())
	if !ok || claims.UserID == "" {
		unauthorized(w, "unauthorized")
		return
	}

	var body struct {
		Biography *string `json:"biography"`
	}
	if err := decodeJSON(r, &body); err != nil {
		badRequest(w, "invalid_request")
		return
	}
	if body.Biography != nil {
		s := strings.TrimSpace(*body.Biography)
		if len(s) > 2000 {
			s = s[:2000]
		}
		body.Biography = &s
	}
	if err := s.svc.UpdateBiography(r.Context(), claims.UserID, body.Biography); err != nil {
		badRequest(w, "failed_to_update_biography")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Service) handleUserDeleteDELETE(w http.ResponseWriter, r *http.Request) {
	if !s.allow(r, RLUserDelete) {
		tooMany(w)
		return
	}
	claims, ok := ClaimsFromContext(r.Context())
	if !ok || claims.UserID == "" {
		unauthorized(w, "unauthorized")
		return
	}
	_ = s.svc.SoftDeleteUser(r.Context(), claims.UserID)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Service) handleUserUnlinkProviderDELETE(w http.ResponseWriter, r *http.Request) {
	if !s.allow(r, RLUserUnlinkProvider) {
		tooMany(w)
		return
	}
	claims, ok := ClaimsFromContext(r.Context())
	if !ok || claims.UserID == "" {
		unauthorized(w, "unauthorized")
		return
	}
	provider := strings.ToLower(strings.TrimSpace(r.PathValue("provider")))
	if provider == "" {
		badRequest(w, "invalid_provider")
		return
	}
	hasPwd, links := s.svc.HasPassword(r.Context(), claims.UserID), s.svc.CountProviderLinks(r.Context(), claims.UserID)
	if !hasPwd && links <= 1 {
		badRequest(w, "cannot_unlink_last_login_method")
		return
	}
	if err := s.svc.UnlinkProvider(r.Context(), claims.UserID, provider); err != nil {
		serverErr(w, "failed_to_unlink")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}
