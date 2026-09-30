package httpapi

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/open-rails/authkit/internal/errmodel"
)

func (s *Service) handlePasskeyLoginBeginPOST(w http.ResponseWriter, r *http.Request) {
	if r.Body != nil && r.Body != http.NoBody && r.ContentLength != 0 {
		var req map[string]json.RawMessage
		if err := decodeJSON(r, &req); err != nil || req == nil || len(req) != 0 {
			fail(w, errmodel.CodeInvalidRequest)
			return
		}
	}
	assertion, err := s.svc.BeginPasskeyLogin(r.Context())
	if err != nil {
		serverErr(w, "passkey_failed", err)
		return
	}
	writeJSON(w, http.StatusOK, assertion)
}

func (s *Service) handlePasskeyLoginFinishPOST(w http.ResponseWriter, r *http.Request) {
	body, err := readSmallBody(r)
	if err != nil {
		fail(w, errmodel.CodeInvalidRequest)
		return
	}
	result, err := s.svc.FinishPasskeyLogin(r.Context(), body, r.UserAgent(), parseIP(s.requestIP(r)))
	if err != nil {
		fail(w, errmodel.CodeInvalidCredentials)
		return
	}

	s.writeAuthResult(w, r, result, authExtras{})
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
