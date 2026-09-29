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

	actor, ok := verify.ActorFromContext(r.Context())
	if !ok {
		fail(w, errmodel.CodeUnauthorized)
		return
	}
	name := strings.TrimSpace(body.Username)
	updated, err := s.svc.UpdateUser(r.Context(), actor, claims.UserID, iam.UserUpdate{Username: &name})
	if err != nil {
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
	writeJSON(w, http.StatusOK, map[string]any{"username": updated.Username, "naming": state})
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
	actor, ok := verify.ActorFromContext(r.Context())
	if !ok {
		fail(w, errmodel.CodeUnauthorized)
		return
	}
	updated, err := s.svc.UpdateUser(r.Context(), actor, claims.UserID, iam.UserUpdate{PreferredLanguage: &normalized})
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"preferred_language": updated.PreferredLanguage})
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
	actor, ok := verify.ActorFromContext(r.Context())
	if !ok {
		fail(w, errmodel.CodeUnauthorized)
		return
	}
	res, err := s.svc.DeleteUsers(r.Context(), actor, []string{claims.UserID})
	if err := opErr(res, err); err != nil {
		if errmodel.As(err) == nil {
			serverErr(w, "failed_to_delete", err)
			return
		}
		writeError(w, err)
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
