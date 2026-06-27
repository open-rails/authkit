package authhttp

import (
	"encoding/json"
	"errors"
	authkit "github.com/open-rails/authkit"
	"io"
	"net/http"
	"time"
)

func (s *Service) handlePasskeyRegisterBeginPOST(w http.ResponseWriter, r *http.Request) {
	if s.rateLimited(w, r, RLPasskeyRegister) {
		return
	}
	claims, ok := ClaimsFromContext(r.Context())
	if !ok || claims.UserID == "" {
		unauthorized(w, ErrUnauthorized)
		return
	}
	if ok, _ := s.requireFreshAuthOrPassword(w, r, claims, ""); !ok {
		return
	}
	creation, err := s.svc.BeginPasskeyRegistration(r.Context(), claims.UserID)
	if err != nil {
		serverErr(w, ErrPasskeyFailed)
		return
	}
	writeJSON(w, http.StatusOK, creation)
}

func (s *Service) handlePasskeyRegisterFinishPOST(w http.ResponseWriter, r *http.Request) {
	if s.rateLimited(w, r, RLPasskeyRegister) {
		return
	}
	claims, ok := ClaimsFromContext(r.Context())
	if !ok || claims.UserID == "" {
		unauthorized(w, ErrUnauthorized)
		return
	}
	if ok, _ := s.requireFreshAuthOrPassword(w, r, claims, ""); !ok {
		return
	}
	body, err := readSmallBody(r)
	if err != nil {
		badRequest(w, ErrInvalidRequest)
		return
	}
	passkey, err := s.svc.FinishPasskeyRegistration(r.Context(), claims.UserID, body)
	if err != nil {
		badRequest(w, ErrInvalidRequest)
		return
	}
	writeJSON(w, http.StatusOK, passkey)
}

func (s *Service) handlePasskeyLoginBeginPOST(w http.ResponseWriter, r *http.Request) {
	if s.rateLimited(w, r, RLPasskeyLogin) {
		return
	}
	var req struct {
		Login string `json:"login"`
		Email string `json:"email"`
	}
	if r.Body != nil && r.Body != http.NoBody && r.ContentLength != 0 {
		_ = decodeJSON(r, &req)
	}
	identifier := firstTrimmedNonEmpty(req.Login, req.Email)
	if identifier != "" && s.rateLimitedByIdentifier(w, r, RLPasskeyLogin, identifier) {
		return
	}
	assertion, err := s.svc.BeginPasskeyLogin(r.Context(), identifier)
	if err != nil {
		serverErr(w, ErrPasskeyFailed)
		return
	}
	writeJSON(w, http.StatusOK, assertion)
}

func (s *Service) handlePasskeyLoginFinishPOST(w http.ResponseWriter, r *http.Request) {
	if s.rateLimited(w, r, RLPasskeyLogin) {
		return
	}
	body, err := readSmallBody(r)
	if err != nil {
		badRequest(w, ErrInvalidRequest)
		return
	}
	result, err := s.svc.FinishPasskeyLogin(r.Context(), body, r.UserAgent(), nil)
	if err != nil {
		if errors.Is(err, authkit.ErrTwoFAEnrollmentRequired) && result.UserID != "" {
			s.write2FAEnrollmentRequired(w, r, result.UserID)
			return
		}
		unauthorized(w, ErrInvalidCredentials)
		return
	}
	ua := r.UserAgent()
	ip := remoteIP(r)
	s.svc.LogSessionCreated(r.Context(), result.UserID, "passkey_login", result.SessionID, &ip, &ua)
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token":  result.AccessToken,
		"token_type":    "Bearer",
		"expires_in":    int64(time.Until(result.ExpiresAt).Seconds()),
		"refresh_token": result.RefreshToken,
	})
}

func (s *Service) handlePasskeysGET(w http.ResponseWriter, r *http.Request) {
	claims, ok := ClaimsFromContext(r.Context())
	if !ok || claims.UserID == "" {
		unauthorized(w, ErrUnauthorized)
		return
	}
	passkeys, err := s.svc.ListPasskeys(r.Context(), claims.UserID)
	if err != nil {
		serverErr(w, ErrPasskeyFailed)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"passkeys": passkeys})
}

func (s *Service) handlePasskeyPATCH(w http.ResponseWriter, r *http.Request) {
	claims, ok := ClaimsFromContext(r.Context())
	if !ok || claims.UserID == "" {
		unauthorized(w, ErrUnauthorized)
		return
	}
	if ok, _ := s.requireFreshAuthOrPassword(w, r, claims, ""); !ok {
		return
	}
	var req struct {
		Label string `json:"label"`
	}
	if err := decodeJSON(r, &req); err != nil {
		badRequest(w, ErrInvalidRequest)
		return
	}
	if err := s.svc.RenamePasskey(r.Context(), claims.UserID, r.PathValue("id"), req.Label); err != nil {
		if errors.Is(err, authkit.ErrPasskeyNotFound) {
			notFound(w, ErrNotFound)
			return
		}
		serverErr(w, ErrPasskeyFailed)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Service) handlePasskeyDELETE(w http.ResponseWriter, r *http.Request) {
	claims, ok := ClaimsFromContext(r.Context())
	if !ok || claims.UserID == "" {
		unauthorized(w, ErrUnauthorized)
		return
	}
	if ok, _ := s.requireFreshAuthOrPassword(w, r, claims, ""); !ok {
		return
	}
	if err := s.svc.DeletePasskey(r.Context(), claims.UserID, r.PathValue("id")); err != nil {
		if errors.Is(err, authkit.ErrPasskeyNotFound) {
			notFound(w, ErrNotFound)
			return
		}
		serverErr(w, ErrPasskeyFailed)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func readSmallBody(r *http.Request) ([]byte, error) {
	if r == nil || r.Body == nil {
		return nil, io.ErrUnexpectedEOF
	}
	body, err := io.ReadAll(http.MaxBytesReader(nil, r.Body, maxRequestBodyBytes))
	if err != nil {
		return nil, err
	}
	if !json.Valid(body) {
		return nil, io.ErrUnexpectedEOF
	}
	return body, nil
}
