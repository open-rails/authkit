package authhttp

import (
	authkit "github.com/open-rails/authkit"
	"net/http"
	"strings"
	"time"

	"github.com/open-rails/authkit/embedded"
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
		if err == authkit.ErrOwnerSlugTaken {
			badRequest(w, ErrOwnerSlugTaken)
			return
		}
		if err == authkit.ErrRenameRateLimited {
			seconds, _ := s.svc.TimeUntilUsernameRenameAvailable(r.Context(), claims.UserID, time.Now())
			availability := cooldownAvailability(ActionUpdateUsername, seconds, 72*time.Hour, time.Now())
			data := availability.toMap()
			data["time_until_rename_available"] = seconds
			sendErrData(w, http.StatusTooManyRequests, ErrRenameRateLimited, data)
			return
		}
		if code := ErrorCode(embedded.ValidationErrorCode(err)); code != "" {
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
	normalized, err := embedded.NormalizePreferredLanguage(language)
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
	if err := s.svc.SoftDeleteUser(r.Context(), claims.UserID); err != nil {
		serverErr(w, ErrFailedToDelete)
		return
	}
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
	removed, err := s.svc.UnlinkProviderUnlessLast(r.Context(), claims.UserID, provider)
	if err != nil {
		serverErr(w, ErrFailedToUnlink)
		return
	}
	if !removed {
		badRequest(w, ErrCannotUnlinkLastLoginMethod)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}
