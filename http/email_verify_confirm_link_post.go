package authhttp

import "net/http"

// confirmEmailVerificationToken runs the shared verify-confirm-by-link flow for the
// email channel (see verify_confirm_link.go).
func (s *Service) confirmEmailVerificationToken(w http.ResponseWriter, r *http.Request, token, identifier, email string) {
	s.confirmVerificationToken(w, r, s.emailVerifyChannel(), token, identifier, email)
}
