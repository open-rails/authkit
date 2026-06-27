package authhttp

import "net/http"

// confirmPhoneVerificationToken runs the shared verify-confirm-by-link flow for the
// phone channel (see verify_confirm_link.go).
func (s *Service) confirmPhoneVerificationToken(w http.ResponseWriter, r *http.Request, token, identifier, phoneNumber string) {
	s.confirmVerificationToken(w, r, s.phoneVerifyChannel(), token, identifier, phoneNumber)
}
