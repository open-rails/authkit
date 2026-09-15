package authhttp

import (
	"encoding/json"
	"io"
	"net/http"

	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/verify"
)

func (s *Service) handlePasskeyRegisterBeginPOST(w http.ResponseWriter, r *http.Request) {
	claims, ok := verify.ClaimsFromContext(r.Context())
	if !ok || claims.UserID == "" {
		unauthorized(w, authkit.CodeUnauthorized)
		return
	}
	if ok, _ := s.requireFreshAuthOrPassword(w, r, claims, ""); !ok {
		return
	}
	creation, err := s.svc.BeginPasskeyRegistration(r.Context(), claims.UserID)
	if err != nil {
		serverErr(w, authkit.CodePasskeyFailed)
		return
	}
	writeJSON(w, http.StatusOK, creation)
}

func (s *Service) handlePasskeyRegisterFinishPOST(w http.ResponseWriter, r *http.Request) {
	claims, ok := verify.ClaimsFromContext(r.Context())
	if !ok || claims.UserID == "" {
		unauthorized(w, authkit.CodeUnauthorized)
		return
	}
	if ok, _ := s.requireFreshAuthOrPassword(w, r, claims, ""); !ok {
		return
	}
	body, err := readSmallBody(r)
	if err != nil {
		badRequest(w, authkit.CodeInvalidRequest)
		return
	}
	passkey, err := s.svc.FinishPasskeyRegistration(r.Context(), claims.UserID, body)
	if err != nil {
		badRequest(w, authkit.CodeInvalidRequest)
		return
	}
	writeJSON(w, http.StatusOK, passkey)
}

func (s *Service) handlePasskeyLoginBeginPOST(w http.ResponseWriter, r *http.Request) {
	if r.Body != nil && r.Body != http.NoBody && r.ContentLength != 0 {
		var req map[string]json.RawMessage
		if err := decodeJSON(r, &req); err != nil || req == nil || len(req) != 0 {
			badRequest(w, authkit.CodeInvalidRequest)
			return
		}
	}
	assertion, err := s.svc.BeginPasskeyLogin(r.Context())
	if err != nil {
		serverErr(w, authkit.CodePasskeyFailed)
		return
	}
	writeJSON(w, http.StatusOK, assertion)
}

func (s *Service) handlePasskeyLoginFinishPOST(w http.ResponseWriter, r *http.Request) {
	body, err := readSmallBody(r)
	if err != nil {
		badRequest(w, authkit.CodeInvalidRequest)
		return
	}
	result, err := s.svc.FinishPasskeyLogin(r.Context(), body, r.UserAgent(), parseIP(s.requestIP(r)))
	if err != nil {
		unauthorized(w, authkit.CodeInvalidCredentials)
		return
	}

	s.writeTokenSet(w, r, http.StatusOK, authkit.NewTokenSet(result.AccessToken, result.RefreshToken, result.ExpiresAt))
}

func (s *Service) handlePasskeysGET(w http.ResponseWriter, r *http.Request) {
	claims, ok := verify.ClaimsFromContext(r.Context())
	if !ok || claims.UserID == "" {
		unauthorized(w, authkit.CodeUnauthorized)
		return
	}
	passkeys, err := s.svc.ListPasskeys(r.Context(), claims.UserID)
	if err != nil {
		serverErr(w, authkit.CodePasskeyFailed)
		return
	}
	writeList(w, passkeys, "")
}

func (s *Service) handlePasskeyPATCH(w http.ResponseWriter, r *http.Request) {
	claims, ok := verify.ClaimsFromContext(r.Context())
	if !ok || claims.UserID == "" {
		unauthorized(w, authkit.CodeUnauthorized)
		return
	}
	if ok, _ := s.requireFreshAuthOrPassword(w, r, claims, ""); !ok {
		return
	}
	var req struct {
		Label string `json:"label"`
	}
	if err := decodeJSON(r, &req); err != nil {
		badRequest(w, authkit.CodeInvalidRequest)
		return
	}
	if err := s.svc.RenamePasskey(r.Context(), claims.UserID, r.PathValue("id"), req.Label); err != nil {
		writeError(w, remap(err, notFoundCodes))
		return
	}
	noContent(w)
}

func (s *Service) handlePasskeyDELETE(w http.ResponseWriter, r *http.Request) {
	claims, ok := verify.ClaimsFromContext(r.Context())
	if !ok || claims.UserID == "" {
		unauthorized(w, authkit.CodeUnauthorized)
		return
	}
	if ok, _ := s.requireFreshAuthOrPassword(w, r, claims, ""); !ok {
		return
	}
	if err := s.svc.DeletePasskey(r.Context(), claims.UserID, r.PathValue("id")); err != nil {
		writeError(w, remap(err, notFoundCodes))
		return
	}
	noContent(w)
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
