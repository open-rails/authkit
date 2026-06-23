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

func (s *Service) handleUserPreferredLanguagePATCH(w http.ResponseWriter, r *http.Request) {
	if s.rateLimited(w, r, RLUserPreferredLanguage) {
		return
	}
	claims, ok := ClaimsFromContext(r.Context())
	if !ok || claims.UserID == "" {
		unauthorized(w, ErrUnauthorized)
		return
	}
	var body struct {
		PreferredLanguage string `json:"preferred_language"`
		Language          string `json:"language"`
	}
	if err := decodeJSON(r, &body); err != nil {
		badRequest(w, ErrInvalidRequest)
		return
	}
	language := strings.TrimSpace(body.PreferredLanguage)
	if language == "" {
		language = strings.TrimSpace(body.Language)
	}
	if language == "" {
		badRequest(w, ErrInvalidRequest)
		return
	}
	normalized, err := core.NormalizePreferredLanguage(language)
	if err != nil || !s.supportsLanguage(normalized) {
		badRequest(w, ErrInvalidPreferredLanguage)
		return
	}
	if err := s.svc.SetPreferredLanguage(r.Context(), claims.UserID, normalized); err != nil {
		if strings.Contains(err.Error(), "invalid_preferred_language") {
			badRequest(w, ErrInvalidPreferredLanguage)
			return
		}
		badRequest(w, ErrFailedToUpdatePreferredLanguage)
		return
	}
	preferred, err := s.svc.GetPreferredLanguage(r.Context(), claims.UserID)
	if err != nil {
		serverErr(w, ErrPreferredLanguageLookupFailed)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":                 true,
		"preferred_language": preferred.Language,
	})
}

func (s *Service) supportsLanguage(language string) bool {
	cfg := s.langCfg.defaulted()
	supported := supportedSet(cfg.Supported)
	if supported == nil {
		return language == normalizeLangCode(cfg.Default)
	}
	_, ok := supported[language]
	return ok
}

func formatOptionalTime(t *time.Time) *string {
	if t == nil || t.IsZero() {
		return nil
	}
	formatted := t.UTC().Format(time.RFC3339)
	return &formatted
}

func (s *Service) handleUserEmailChangePOST(w http.ResponseWriter, r *http.Request) {
	claims, ok := ClaimsFromContext(r.Context())
	if !ok || claims.UserID == "" {
		unauthorized(w, ErrNotAuthenticated)
		return
	}

	var body struct {
		NewEmail string `json:"new_email"`
		Password string `json:"password"`
		Code     string `json:"code"`
	}
	if err := decodeJSON(r, &body); err != nil {
		badRequest(w, ErrInvalidRequest)
		return
	}

	newEmail := strings.TrimSpace(body.NewEmail)
	code := strings.TrimSpace(body.Code)
	if (newEmail == "") == (code == "") {
		badRequest(w, ErrInvalidRequest)
		return
	}

	if code != "" {
		if s.rateLimited(w, r, RLUserEmailChangeConfirm) {
			return
		}
		if err := s.svc.ConfirmEmailChange(r.Context(), claims.UserID, strings.ToUpper(code)); err != nil {
			if strings.Contains(err.Error(), "already in use") {
				badRequest(w, ErrEmailInUse)
				return
			}
			badRequest(w, ErrInvalidOrExpiredCode)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": "Email changed successfully"})
		return
	}

	if !s.svc.HasEmailSender() {
		serverErr(w, ErrEmailVerificationUnavailable)
		return
	}
	ok, authMeta := s.requireFreshAuthOrPassword(w, r, claims, body.Password)
	if s.rateLimited(w, r, RLUserEmailChangeRequest) || !ok {
		return
	}
	if err := s.svc.RequestEmailChange(r.Context(), claims.UserID, newEmail); err != nil {
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
	resp := map[string]any{"ok": true, "message": "Verification code sent to new email address"}
	for k, v := range authMeta {
		resp[k] = v
	}
	writeJSON(w, http.StatusAccepted, resp)
}

func (s *Service) handleUserPhoneChangePOST(w http.ResponseWriter, r *http.Request) {
	claims, ok := ClaimsFromContext(r.Context())
	if !ok || claims.UserID == "" {
		unauthorized(w, ErrNotAuthenticated)
		return
	}

	var body struct {
		Phone    string `json:"phone_number"`
		Password string `json:"password"`
		Code     string `json:"code"`
	}
	if err := decodeJSON(r, &body); err != nil {
		badRequest(w, ErrInvalidRequest)
		return
	}

	phone := strings.TrimSpace(body.Phone)
	code := strings.TrimSpace(body.Code)
	if phone == "" || (code != "" && strings.TrimSpace(body.Password) != "") {
		badRequest(w, ErrInvalidRequest)
		return
	}

	if code != "" {
		if s.rateLimited(w, r, RLUserPhoneChangeConfirm) {
			return
		}
		if err := s.svc.ConfirmPhoneChange(r.Context(), claims.UserID, phone, code); err != nil {
			badRequest(w, ErrInvalidOrExpiredCode)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": "Phone number changed successfully"})
		return
	}

	ok, authMeta := s.requireFreshAuthOrPassword(w, r, claims, body.Password)
	if s.rateLimited(w, r, RLUserPhoneChangeRequest) || !ok {
		return
	}
	if !s.svc.SMSAvailable() {
		serverErr(w, ErrPhoneChangeUnavailable)
		return
	}
	if err := s.svc.RequestPhoneChange(r.Context(), claims.UserID, phone); err != nil {
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
	resp := map[string]any{"ok": true, "message": "Verification code sent to new phone"}
	for k, v := range authMeta {
		resp[k] = v
	}
	writeJSON(w, http.StatusAccepted, resp)
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
	var body struct {
		Password string `json:"password"`
	}
	if err := decodeOptionalJSON(r, &body); err != nil {
		badRequest(w, ErrInvalidRequest)
		return
	}
	if ok, _ := s.requireFreshAuthOrPassword(w, r, claims, body.Password); !ok {
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
	var body struct {
		Password string `json:"password"`
	}
	if err := decodeOptionalJSON(r, &body); err != nil {
		badRequest(w, ErrInvalidRequest)
		return
	}
	if ok, _ := s.requireFreshAuthOrPassword(w, r, claims, body.Password); !ok {
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
