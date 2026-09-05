package authhttp

import (
	"errors"

	"net/http"
	"strings"
	"time"

	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/verify"

	"github.com/open-rails/authkit/embedded"
)

func (s *Service) handleUserUsernamePATCH(w http.ResponseWriter, r *http.Request) {
	claims, ok := verify.ClaimsFromContext(r.Context())
	if !ok || claims.UserID == "" {
		unauthorized(w, authkit.CodeUnauthorized)
		return
	}
	var body struct {
		Username string `json:"username"`
	}
	if err := decodeJSON(r, &body); err != nil || strings.TrimSpace(body.Username) == "" {
		badRequest(w, authkit.CodeInvalidRequest)
		return
	}

	if err := s.svc.UpdateUsername(r.Context(), claims.UserID, body.Username); err != nil {
		if errors.Is(err, authkit.ErrRenameRateLimited) {
			state, stateErr := s.svc.UserNamingState(r.Context(), claims.UserID)
			if stateErr != nil {
				serverErr(w, authkit.CodeDatabaseError)
				return
			}
			sendErrData(w, http.StatusTooManyRequests, authkit.CodeRenameRateLimited, map[string]any{"time_until_rename_available": state.RetryAfterSeconds, "naming": state, "next_allowed_at": state.NextRenameAt, "retry_after_seconds": state.RetryAfterSeconds, "cooldown_seconds": int64(state.Policy.RenameInterval / time.Second), "allowed": state.Allowed, "reason": "cooldown", "action": ActionUpdateUsername})
			return
		}
		writeError(w, err)
		return
	}
	state, err := s.svc.UserNamingState(r.Context(), claims.UserID)
	if err != nil {
		serverErr(w, authkit.CodeDatabaseError)
		return
	}
	users, err := s.svc.PublicUsersByIDs(r.Context(), []string{claims.UserID})
	if err != nil {
		serverErr(w, authkit.CodeDatabaseError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"username": users[claims.UserID].Username, "naming": state})
}

func (s *Service) handleUserPreferredLanguagePATCH(w http.ResponseWriter, r *http.Request) {
	claims, ok := verify.ClaimsFromContext(r.Context())
	if !ok || claims.UserID == "" {
		unauthorized(w, authkit.CodeUnauthorized)
		return
	}
	var body struct {
		PreferredLanguage string `json:"preferred_language"`
		Language          string `json:"language"`
	}
	if err := decodeJSON(r, &body); err != nil {
		badRequest(w, authkit.CodeInvalidRequest)
		return
	}
	language := strings.TrimSpace(body.PreferredLanguage)
	if language == "" {
		language = strings.TrimSpace(body.Language)
	}
	if language == "" {
		badRequest(w, authkit.CodeInvalidRequest)
		return
	}
	normalized, err := embedded.NormalizePreferredLanguage(language)
	if err != nil || !s.supportsLanguage(normalized) {
		badRequest(w, authkit.CodeInvalidPreferredLanguage)
		return
	}
	if err := s.svc.SetPreferredLanguage(r.Context(), claims.UserID, normalized); err != nil {
		if strings.Contains(err.Error(), "invalid_preferred_language") {
			badRequest(w, authkit.CodeInvalidPreferredLanguage)
			return
		}
		badRequest(w, authkit.CodeFailedToUpdatePreferredLanguage)
		return
	}
	preferred, err := s.svc.GetPreferredLanguage(r.Context(), claims.UserID)
	if err != nil {
		serverErr(w, authkit.CodePreferredLanguageLookupFailed)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"preferred_language": preferred.Language})
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
	claims, ok := verify.ClaimsFromContext(r.Context())
	if !ok || claims.UserID == "" {
		unauthorized(w, authkit.CodeUnauthorized)
		return
	}
	var body struct {
		Password string `json:"password"`
	}
	if err := decodeOptionalJSON(r, &body); err != nil {
		badRequest(w, authkit.CodeInvalidRequest)
		return
	}
	if ok, _ := s.requireFreshAuthOrPassword(w, r, claims, body.Password); !ok {
		return
	}
	if err := s.svc.SoftDeleteUser(r.Context(), claims.UserID); err != nil {
		serverErr(w, authkit.CodeFailedToDelete)
		return
	}
	noContent(w)
}

func (s *Service) handleUserUnlinkProviderDELETE(w http.ResponseWriter, r *http.Request) {
	claims, ok := verify.ClaimsFromContext(r.Context())
	if !ok || claims.UserID == "" {
		unauthorized(w, authkit.CodeUnauthorized)
		return
	}
	var body struct {
		Password string `json:"password"`
	}
	if err := decodeOptionalJSON(r, &body); err != nil {
		badRequest(w, authkit.CodeInvalidRequest)
		return
	}
	if ok, _ := s.requireFreshAuthOrPassword(w, r, claims, body.Password); !ok {
		return
	}
	provider := strings.ToLower(strings.TrimSpace(r.PathValue("provider")))
	if provider == "" {
		badRequest(w, authkit.CodeInvalidProvider)
		return
	}
	removed, err := s.svc.UnlinkProviderUnlessLast(r.Context(), claims.UserID, provider)
	if err != nil {
		serverErr(w, authkit.CodeFailedToUnlink)
		return
	}
	if !removed {
		badRequest(w, authkit.CodeCannotUnlinkLastLoginMethod)
		return
	}
	noContent(w)
}
