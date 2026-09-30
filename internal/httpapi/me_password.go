package httpapi

import (
	"net/http"

	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/verify"
)

// handleMePasswordPUT sets or changes the caller's password; the route
// requires a recent sign-in, and the caller's other sessions end.
func (s *Service) handleMePasswordPUT(w http.ResponseWriter, r *http.Request) {
	claims, ok := verify.ClaimsFromContext(r.Context())
	if !ok || claims.UserID == "" {
		fail(w, errmodel.CodeUnauthenticated)
		return
	}
	var body PasswordChangeRequest
	if err := decodeJSON(r, &body); err != nil {
		fail(w, errmodel.CodeInvalidRequest)
		return
	}
	// Policy failures and hashing overload (503 server_busy) answer as
	// themselves.
	if err := s.svc.SetPasswordAfterFreshAuth(r.Context(), claims.UserID, body.NewPassword, keepCredential(claims)); err != nil {
		writeError(w, err)
		return
	}
	noContent(w)
}
