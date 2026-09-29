package httpapi

import (
	"errors"

	"net/http"
	"strings"
	"time"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/verify"
)

func (s *Service) handleUserUsernamePATCH(w http.ResponseWriter, r *http.Request) {
	claims, ok := verify.ClaimsFromContext(r.Context())
	if !ok || claims.UserID == "" {
		fail(w, errmodel.CodeUnauthorized)
		return
	}
	var body struct {
		Username string `json:"username"`
	}
	if err := decodeJSON(r, &body); err != nil || strings.TrimSpace(body.Username) == "" {
		fail(w, errmodel.CodeInvalidRequest)
		return
	}

	if err := s.svc.UpdateUsername(r.Context(), claims.UserID, body.Username); err != nil {
		if errors.Is(err, iam.ErrRenameRateLimited) {
			state, stateErr := s.svc.UserNamingState(r.Context(), claims.UserID)
			if stateErr != nil {
				serverErr(w, "database_error", stateErr)
				return
			}
			fail(w, errmodel.CodeRenameRateLimited, errmodel.WithMetadata(map[string]any{"time_until_rename_available": state.RetryAfterSeconds, "naming": state, "next_allowed_at": state.NextRenameAt, "retry_after_seconds": state.RetryAfterSeconds, "cooldown_seconds": int64(s.svc.NamingPolicy().RenameInterval / time.Second), "allowed": state.Allowed, "reason": "cooldown", "action": authflow.ActionUpdateUsername}))
			return
		}
		writeError(w, err)
		return
	}
	state, err := s.svc.UserNamingState(r.Context(), claims.UserID)
	if err != nil {
		serverErr(w, "database_error", err)
		return
	}
	users, err := s.svc.PublicUsersByIDs(r.Context(), []string{claims.UserID})
	if err != nil {
		serverErr(w, "database_error", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"username": users[claims.UserID].Username, "naming": state})
}

func (s *Service) handleUserPreferredLanguagePATCH(w http.ResponseWriter, r *http.Request) {
	claims, ok := verify.ClaimsFromContext(r.Context())
	if !ok || claims.UserID == "" {
		fail(w, errmodel.CodeUnauthorized)
		return
	}
	var body struct {
		PreferredLanguage string `json:"preferred_language"`
		Language          string `json:"language"`
	}
	if err := decodeJSON(r, &body); err != nil {
		fail(w, errmodel.CodeInvalidRequest)
		return
	}
	language := strings.TrimSpace(body.PreferredLanguage)
	if language == "" {
		language = strings.TrimSpace(body.Language)
	}
	if language == "" {
		fail(w, errmodel.CodeInvalidRequest)
		return
	}
	normalized, err := authflow.NormalizePreferredLanguage(language)
	if err != nil || !s.supportsLanguage(normalized) {
		fail(w, errmodel.CodeInvalidPreferredLanguage)
		return
	}
	if err := s.svc.SetPreferredLanguage(r.Context(), claims.UserID, normalized); err != nil {
		if strings.Contains(err.Error(), "invalid_preferred_language") {
			fail(w, errmodel.CodeInvalidPreferredLanguage)
			return
		}
		fail(w, errmodel.CodeFailedToUpdatePreferredLanguage)
		return
	}
	preferred, err := s.svc.GetPreferredLanguage(r.Context(), claims.UserID)
	if err != nil {
		serverErr(w, "preferred_language_lookup_failed", err)
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
		fail(w, errmodel.CodeUnauthorized)
		return
	}
	var body struct {
		Password string `json:"password"`
	}
	if err := decodeOptionalJSON(r, &body); err != nil {
		fail(w, errmodel.CodeInvalidRequest)
		return
	}
	if ok, _ := s.requireFreshAuthOrPassword(w, r, claims, body.Password); !ok {
		return
	}
	if err := s.svc.SoftDeleteUser(r.Context(), claims.UserID); err != nil {
		serverErr(w, "failed_to_delete", err)
		return
	}
	noContent(w)
}

func (s *Service) handleUserUnlinkProviderDELETE(w http.ResponseWriter, r *http.Request) {
	claims, ok := verify.ClaimsFromContext(r.Context())
	if !ok || claims.UserID == "" {
		fail(w, errmodel.CodeUnauthorized)
		return
	}
	var body struct {
		Password string `json:"password"`
	}
	if err := decodeOptionalJSON(r, &body); err != nil {
		fail(w, errmodel.CodeInvalidRequest)
		return
	}
	if ok, _ := s.requireFreshAuthOrPassword(w, r, claims, body.Password); !ok {
		return
	}
	provider := strings.ToLower(strings.TrimSpace(r.PathValue("provider")))
	if provider == "" {
		fail(w, errmodel.CodeInvalidProvider)
		return
	}
	removed, err := s.svc.UnlinkProviderUnlessLast(r.Context(), claims.UserID, provider)
	if err != nil {
		serverErr(w, "failed_to_unlink", err)
		return
	}
	if !removed {
		fail(w, errmodel.CodeCannotUnlinkLastLoginMethod)
		return
	}
	noContent(w)
}
