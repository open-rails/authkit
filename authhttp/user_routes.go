package authhttp

import (
	"errors"

	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/verify"
	"net/http"
	"strings"
	"time"

	"github.com/open-rails/authkit/embedded"
)

func (s *Service) handleUserUsernamePATCH(w http.ResponseWriter, r *http.Request) {
	if s.rateLimited(w, r, RLUserUpdateUsername) {
		return
	}
	claims, ok := verify.ClaimsFromContext(r.Context())
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
		if errors.Is(err, authkit.ErrOwnerSlugTaken) {
			badRequest(w, ErrOwnerSlugTaken)
			return
		}
		if errors.Is(err, authkit.ErrRenamesDisabled) || errors.Is(err, authkit.ErrNameAdmissionRefused) {
			sendErr(w, http.StatusForbidden, ErrorCode(authkit.CodeForError(err)))
			return
		}
		if errors.Is(err, authkit.ErrRenameRateLimited) {
			state, stateErr := s.svc.UserNamingState(r.Context(), claims.UserID)
			if stateErr != nil {
				serverErr(w, ErrDatabaseError)
				return
			}
			sendErrData(w, http.StatusTooManyRequests, ErrRenameRateLimited, map[string]any{"time_until_rename_available": state.RetryAfterSeconds, "naming": state, "next_allowed_at": state.NextRenameAt, "retry_after_seconds": state.RetryAfterSeconds, "cooldown_seconds": int64(state.Policy.RenameInterval / time.Second), "allowed": state.Allowed, "reason": "cooldown", "action": ActionUpdateUsername})
			return
		}
		if code := ErrorCode(embedded.ValidationErrorCode(err)); code != "" {
			badRequest(w, code)
			return
		}
		badRequest(w, ErrFailedToUpdateUsername)
		return
	}
	state, err := s.svc.UserNamingState(r.Context(), claims.UserID)
	if err != nil {
		serverErr(w, ErrDatabaseError)
		return
	}
	users, err := s.svc.PublicUsersByIDs(r.Context(), []string{claims.UserID})
	if err != nil {
		serverErr(w, ErrDatabaseError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "user_id": claims.UserID, "username": users[claims.UserID].Username, "time_until_rename_available": state.RetryAfterSeconds, "naming": state})
}

func (s *Service) handleUserPreferredLanguagePATCH(w http.ResponseWriter, r *http.Request) {
	if s.rateLimited(w, r, RLUserPreferredLanguage) {
		return
	}
	claims, ok := verify.ClaimsFromContext(r.Context())
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

func (s *Service) handleUserDeleteDELETE(w http.ResponseWriter, r *http.Request) {
	if s.rateLimited(w, r, RLUserDelete) {
		return
	}
	claims, ok := verify.ClaimsFromContext(r.Context())
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
	claims, ok := verify.ClaimsFromContext(r.Context())
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
