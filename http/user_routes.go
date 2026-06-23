package authhttp

import (
	"net/http"
	"strings"
	"time"

	core "github.com/open-rails/authkit/core"
)

func (s *Service) handleUserUsernamePATCH(w http.ResponseWriter, r *http.Request) {
	if s.rateLimited(w, r, RLUserUpdateUsername) {
		return
	}
	claims, ok := ClaimsFromContext(r.Context())
	if !ok || claims.UserID == "" {
		unauthorized(w, ErrUnauthorized)
		return
	}
	var body struct {
		Username string `json:"username"`
	}
	if err := decodeJSON(r, &body); err != nil || strings.TrimSpace(body.Username) == "" {
		badRequest(w, ErrInvalidRequest)
		return
	}

	if err := s.svc.UpdateUsername(r.Context(), claims.UserID, body.Username); err != nil {
		if err == core.ErrOwnerSlugTaken {
			badRequest(w, ErrOwnerSlugTaken)
			return
		}
		if err == core.ErrRenameRateLimited {
			seconds, _ := s.svc.TimeUntilUsernameRenameAvailable(r.Context(), claims.UserID, time.Now())
			availability := cooldownAvailability(ActionUpdateUsername, seconds, 72*time.Hour, time.Now())
			data := availability.toMap()
			data["time_until_rename_available"] = seconds
			sendErrData(w, http.StatusTooManyRequests, ErrRenameRateLimited, data)
			return
		}
		if code := ErrorCode(core.ValidationErrorCode(err)); code != "" {
			badRequest(w, code)
			return
		}
		badRequest(w, ErrFailedToUpdateUsername)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "time_until_rename_available": int64(0)})
}

func (s *Service) handleUserPreferredLocalePATCH(w http.ResponseWriter, r *http.Request) {
	if s.rateLimited(w, r, RLUserPreferredLocale) {
		return
	}
	claims, ok := ClaimsFromContext(r.Context())
	if !ok || claims.UserID == "" {
		unauthorized(w, ErrUnauthorized)
		return
	}
	var body struct {
		PreferredLocale string `json:"preferred_locale"`
		Locale          string `json:"locale"`
	}
	if err := decodeJSON(r, &body); err != nil {
		badRequest(w, ErrInvalidRequest)
		return
	}
	locale := strings.TrimSpace(body.PreferredLocale)
	if locale == "" {
		locale = strings.TrimSpace(body.Locale)
	}
	if locale == "" {
		badRequest(w, ErrInvalidRequest)
		return
	}
	if err := s.svc.SetPreferredLocale(r.Context(), claims.UserID, locale, "explicit"); err != nil {
		if strings.Contains(err.Error(), "invalid_preferred_locale") {
			badRequest(w, ErrInvalidPreferredLocale)
			return
		}
		badRequest(w, ErrFailedToUpdatePreferredLocale)
		return
	}
	preferred, err := s.svc.GetPreferredLocale(r.Context(), claims.UserID)
	if err != nil {
		serverErr(w, ErrPreferredLocaleLookupFailed)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":                          true,
		"preferred_locale":            preferred.Locale,
		"preferred_locale_source":     preferred.Source,
		"preferred_locale_updated_at": formatOptionalTime(preferred.UpdatedAt),
	})
}

func formatOptionalTime(t *time.Time) *string {
	if t == nil || t.IsZero() {
		return nil
	}
	formatted := t.UTC().Format(time.RFC3339)
	return &formatted
}

func (s *Service) handleUserEmailChangeRequestPOST(w http.ResponseWriter, r *http.Request) {
	if !s.svc.HasEmailSender() {
		serverErr(w, ErrEmailVerificationUnavailable)
		return
	}
	if s.rateLimited(w, r, RLUserEmailChangeRequest) {
		return
	}

	claims, ok := ClaimsFromContext(r.Context())
	if !ok || claims.UserID == "" {
		unauthorized(w, ErrNotAuthenticated)
		return
	}

	var body struct {
		NewEmail string `json:"new_email"`
		Password string `json:"password"`
	}
	if err := decodeJSON(r, &body); err != nil || strings.TrimSpace(body.NewEmail) == "" {
		badRequest(w, ErrInvalidRequest)
		return
	}

	if !s.requireFreshAuthOrPassword(w, r, claims, body.Password) {
		return
	}

	if err := s.svc.RequestEmailChange(r.Context(), claims.UserID, body.NewEmail); err != nil {
		if s.handleDeliveryError(w, r, "user_email_change_request", "send_email_verification", err) {
			return
		}
		if code := ErrorCode(core.ValidationErrorCode(err)); code != "" {
			badRequest(w, code)
			return
		}
		msg := err.Error()
		switch {
		case strings.Contains(msg, "same as current"):
			badRequest(w, ErrEmailUnchanged)
		case strings.Contains(msg, "already in use"):
			badRequest(w, ErrEmailInUse)
		default:
			badRequest(w, ErrFailedToRequestEmailChange)
		}
		return
	}

	writeJSON(w, http.StatusAccepted, map[string]any{
		"ok":      true,
		"message": "Verification code sent to new email address",
	})
}

func (s *Service) handleUserEmailChangeConfirmPOST(w http.ResponseWriter, r *http.Request) {
	if s.rateLimited(w, r, RLUserEmailChangeConfirm) {
		return
	}

	claims, ok := ClaimsFromContext(r.Context())
	if !ok || claims.UserID == "" {
		unauthorized(w, ErrNotAuthenticated)
		return
	}

	var body struct {
		Code string `json:"code"`
	}
	if err := decodeJSON(r, &body); err != nil || strings.TrimSpace(body.Code) == "" {
		badRequest(w, ErrInvalidRequest)
		return
	}

	code := strings.ToUpper(strings.TrimSpace(body.Code))
	if err := s.svc.ConfirmEmailChange(r.Context(), claims.UserID, code); err != nil {
		if strings.Contains(err.Error(), "already in use") {
			badRequest(w, ErrEmailInUse)
			return
		}
		badRequest(w, ErrInvalidOrExpiredCode)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"message": "Email changed successfully",
	})
}

func (s *Service) handleUserEmailChangeResendPOST(w http.ResponseWriter, r *http.Request) {
	if !s.svc.HasEmailSender() {
		serverErr(w, ErrEmailVerificationUnavailable)
		return
	}
	if s.rateLimited(w, r, RLUserEmailChangeResend) {
		return
	}

	claims, ok := ClaimsFromContext(r.Context())
	if !ok || claims.UserID == "" {
		unauthorized(w, ErrNotAuthenticated)
		return
	}

	if err := s.svc.ResendEmailChangeCode(r.Context(), claims.UserID); err != nil {
		if s.handleDeliveryError(w, r, "user_email_change_resend", "send_email_verification", err) {
			return
		}
		badRequest(w, ErrNoPendingEmailChange)
		return
	}

	writeJSON(w, http.StatusAccepted, map[string]any{
		"ok":      true,
		"message": "Verification code resent",
	})
}

func (s *Service) handleUserPhoneChangeRequestPOST(w http.ResponseWriter, r *http.Request) {
	if s.rateLimited(w, r, RLUserPhoneChangeRequest) {
		return
	}

	claims, ok := ClaimsFromContext(r.Context())
	if !ok || claims.UserID == "" {
		unauthorized(w, ErrNotAuthenticated)
		return
	}

	var body struct {
		NewPhone string `json:"phone_number"`
		Password string `json:"password"`
	}
	if err := decodeJSON(r, &body); err != nil || strings.TrimSpace(body.NewPhone) == "" {
		badRequest(w, ErrInvalidRequest)
		return
	}

	if !s.requireFreshAuthOrPassword(w, r, claims, body.Password) {
		return
	}

	// Gate on real SMS deliverability up front (parity with signup / phone
	// verification), so an undeliverable sender fails fast instead of silently
	// stranding the user on the OTP screen.
	if !s.svc.SMSAvailable() {
		serverErr(w, ErrPhoneChangeUnavailable)
		return
	}

	if err := s.svc.RequestPhoneChange(r.Context(), claims.UserID, body.NewPhone); err != nil {
		if s.handleDeliveryError(w, r, "user_phone_change_request", "send_phone_verification", err) {
			return
		}
		if code := ErrorCode(core.ValidationErrorCode(err)); code != "" {
			badRequest(w, code)
			return
		}
		msg := err.Error()
		switch {
		case strings.Contains(msg, "same as current"):
			badRequest(w, ErrPhoneUnchanged)
		case strings.Contains(msg, "already in use"):
			badRequest(w, ErrPhoneInUse)
		default:
			badRequest(w, ErrFailedToRequestPhoneChange)
		}
		return
	}

	writeJSON(w, http.StatusAccepted, map[string]any{
		"ok":      true,
		"message": "Verification code sent to new phone",
	})
}

func (s *Service) handleUserPhoneChangeConfirmPOST(w http.ResponseWriter, r *http.Request) {
	if s.rateLimited(w, r, RLUserPhoneChangeConfirm) {
		return
	}

	claims, ok := ClaimsFromContext(r.Context())
	if !ok || claims.UserID == "" {
		unauthorized(w, ErrNotAuthenticated)
		return
	}

	var body struct {
		Phone string `json:"phone_number"`
		Code  string `json:"code"`
	}
	if err := decodeJSON(r, &body); err != nil || strings.TrimSpace(body.Code) == "" || strings.TrimSpace(body.Phone) == "" {
		badRequest(w, ErrInvalidRequest)
		return
	}

	code := strings.TrimSpace(body.Code)
	phone := strings.TrimSpace(body.Phone)
	if err := s.svc.ConfirmPhoneChange(r.Context(), claims.UserID, phone, code); err != nil {
		badRequest(w, ErrInvalidOrExpiredCode)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"message": "Phone number changed successfully",
	})
}

func (s *Service) handleUserPhoneChangeResendPOST(w http.ResponseWriter, r *http.Request) {
	if s.rateLimited(w, r, RLUserPhoneChangeResend) {
		return
	}

	claims, ok := ClaimsFromContext(r.Context())
	if !ok || claims.UserID == "" {
		unauthorized(w, ErrNotAuthenticated)
		return
	}

	var body struct {
		Phone string `json:"phone_number"`
	}
	if err := decodeJSON(r, &body); err != nil || strings.TrimSpace(body.Phone) == "" {
		badRequest(w, ErrInvalidRequest)
		return
	}
	phone := strings.TrimSpace(body.Phone)

	if err := s.svc.ResendPhoneChangeCode(r.Context(), claims.UserID, phone); err != nil {
		if s.handleDeliveryError(w, r, "user_phone_change_resend", "send_phone_verification", err) {
			return
		}
		badRequest(w, ErrNoPendingPhoneChange)
		return
	}

	writeJSON(w, http.StatusAccepted, map[string]any{
		"ok":      true,
		"message": "Verification code resent",
	})
}

// handleUserEmailChangeCancelPOST cancels a pending email change for the
// authenticated user, clearing the server-side pending verification token so no
// stale pending state lingers after the user dismisses the change. Idempotent:
// responds 200 {ok:true} whether or not a pending change existed.
func (s *Service) handleUserEmailChangeCancelPOST(w http.ResponseWriter, r *http.Request) {
	if s.rateLimited(w, r, RLUserEmailChangeCancel) {
		return
	}
	claims, ok := ClaimsFromContext(r.Context())
	if !ok || claims.UserID == "" {
		unauthorized(w, ErrNotAuthenticated)
		return
	}
	if err := s.svc.CancelEmailChange(r.Context(), claims.UserID); err != nil {
		s.logInternalError(r, "user_email_change_cancel", "cancel_email_change", "cancel_failed", err)
		serverErr(w, ErrCancelFailed)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// handleUserPhoneChangeCancelPOST cancels a pending phone change for the
// authenticated user, clearing the server-side pending verification record.
// Idempotent: responds 200 {ok:true} whether or not a pending change existed.
func (s *Service) handleUserPhoneChangeCancelPOST(w http.ResponseWriter, r *http.Request) {
	if s.rateLimited(w, r, RLUserPhoneChangeCancel) {
		return
	}
	claims, ok := ClaimsFromContext(r.Context())
	if !ok || claims.UserID == "" {
		unauthorized(w, ErrNotAuthenticated)
		return
	}
	var body struct {
		Phone string `json:"phone_number"`
	}
	if err := decodeJSON(r, &body); err != nil || strings.TrimSpace(body.Phone) == "" {
		badRequest(w, ErrInvalidRequest)
		return
	}
	if err := s.svc.CancelPhoneChange(r.Context(), claims.UserID, strings.TrimSpace(body.Phone)); err != nil {
		s.logInternalError(r, "user_phone_change_cancel", "cancel_phone_change", "cancel_failed", err)
		serverErr(w, ErrCancelFailed)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Service) handleUserBiographyPATCH(w http.ResponseWriter, r *http.Request) {
	claims, ok := ClaimsFromContext(r.Context())
	if !ok || claims.UserID == "" {
		unauthorized(w, ErrUnauthorized)
		return
	}

	var body struct {
		Biography *string `json:"biography"`
	}
	if err := decodeJSON(r, &body); err != nil {
		badRequest(w, ErrInvalidRequest)
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
		badRequest(w, ErrFailedToUpdateBiography)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Service) handleUserDeleteDELETE(w http.ResponseWriter, r *http.Request) {
	if s.rateLimited(w, r, RLUserDelete) {
		return
	}
	claims, ok := ClaimsFromContext(r.Context())
	if !ok || claims.UserID == "" {
		unauthorized(w, ErrUnauthorized)
		return
	}
	_ = s.svc.SoftDeleteUser(r.Context(), claims.UserID)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Service) handleUserUnlinkProviderDELETE(w http.ResponseWriter, r *http.Request) {
	if s.rateLimited(w, r, RLUserUnlinkProvider) {
		return
	}
	claims, ok := ClaimsFromContext(r.Context())
	if !ok || claims.UserID == "" {
		unauthorized(w, ErrUnauthorized)
		return
	}
	provider := strings.ToLower(strings.TrimSpace(r.PathValue("provider")))
	if provider == "" {
		badRequest(w, ErrInvalidProvider)
		return
	}
	hasPwd, links := s.svc.HasPassword(r.Context(), claims.UserID), s.svc.CountProviderLinks(r.Context(), claims.UserID)
	if !hasPwd && links <= 1 {
		badRequest(w, ErrCannotUnlinkLastLoginMethod)
		return
	}
	if err := s.svc.UnlinkProvider(r.Context(), claims.UserID, provider); err != nil {
		serverErr(w, ErrFailedToUnlink)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}
