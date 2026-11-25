package httpapi

import (
	"net/http"
	"strings"

	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/verify"
)

// Changing the caller's email or phone: PUT sends a code to the new address
// and answers its challenge, which the caller confirms signed in at POST
// /verify/confirm; nothing changes until then. The routes require a recent
// sign-in.

func (s *Service) handleMeEmailPUT(w http.ResponseWriter, r *http.Request) {
	var req EmailChangeRequest
	if err := decodeJSON(r, &req); err != nil {
		s.fail(w, errmodel.CodeInvalidRequest)
		return
	}
	s.requestContactChange(w, r, s.emailChannel(), req.Email, "email")
}

func (s *Service) handleMePhonePUT(w http.ResponseWriter, r *http.Request) {
	var req PhoneChangeRequest
	if err := decodeJSON(r, &req); err != nil {
		s.fail(w, errmodel.CodeInvalidRequest)
		return
	}
	s.requestContactChange(w, r, s.phoneChannel(), req.PhoneNumber, "phone_number")
}

// handleMePhoneDELETE removes the caller's phone number, while a proven email
// remains.
func (s *Service) handleMePhoneDELETE(w http.ResponseWriter, r *http.Request) {
	claims, ok := verify.ClaimsFromContext(r.Context())
	who, hasIdentity := verify.IdentityFromContext(r.Context())
	if !ok || !hasIdentity || claims.UserID == "" {
		s.fail(w, errmodel.CodeUnauthenticated)
		return
	}
	if err := s.svc.RemovePhone(r.Context(), who, claims.UserID); err != nil {
		s.writeError(w, err)
		return
	}
	noContent(w)
}

func (s *Service) requestContactChange(w http.ResponseWriter, r *http.Request, ch contactChannel, value, param string) {
	claims, ok := verify.ClaimsFromContext(r.Context())
	if !ok || claims.UserID == "" {
		s.fail(w, errmodel.CodeUnauthenticated)
		return
	}
	value = strings.TrimSpace(value)
	if value == "" {
		s.fail(w, errmodel.CodeInvalidRequest, errmodel.WithParam(param))
		return
	}
	if err := ch.validate(value); err != nil {
		s.writeError(w, err)
		return
	}
	id := ch.normalize(value)
	if !ch.senderAvailable() {
		s.writeError(w, errmodel.E(ch.errUnavailable))
		return
	}
	challenge, err := ch.requestChange(r.Context(), claims.UserID, id)
	if err != nil {
		s.writeError(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, CodeChallenge{Challenge: challenge})
}
